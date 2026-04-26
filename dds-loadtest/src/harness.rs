//! Soak harness: owns N DdsNodes + per-node LocalServices, drives a
//! mixed workload, samples gauges, and writes summaries on exit.
//!
//! All work happens inside one tokio task that owns the swarms (libp2p
//! swarms are `!Sync` and we want to avoid Mutex churn). The main loop
//! is a `select!` between:
//!
//!   * the joined swarm event stream (via `select_all`)
//!   * a 100 ms workload tick
//!   * a 30 s gauge tick
//!   * a 60 s log tick
//!   * a 15 min snapshot tick
//!   * the shutdown notify (ctrl-c or duration elapsed)

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dds_core::crdt::causal_dag::Operation;
use dds_core::crdt::lww_register::LwwRegister;
use dds_core::identity::Identity;
use dds_core::policy::{Effect, PolicyRule};
use dds_core::token::{Token, TokenKind, TokenPayload};
use dds_core::trust::TrustGraph;
use dds_domain::{DomainDocument, SessionDocument};
use dds_net::gossip::GossipMessage;
use dds_node::config::{NetworkConfig, NodeConfig};
use dds_node::node::DdsNode;
use dds_node::service::LocalService;
use dds_store::MemoryBackend;
use ed25519_dalek::{Signature, Verifier};
use futures::StreamExt;
use libp2p::Multiaddr;
use libp2p::swarm::SwarmEvent;
use rand::Rng;
use rand::SeedableRng;
use rand::rngs::StdRng;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
use tempfile::TempDir;
use tokio::sync::watch;
use tokio::time::{Interval, MissedTickBehavior, interval, timeout};
use tracing::{info, warn};

use crate::Cli;
use crate::metrics::{GaugeSample, Metrics};
use crate::report::{ChaosSummary, Summary, compute_kpis, write_snapshot, write_summary};
use crate::workload::Synth;

/// In-flight gossip propagation probe — sent on a chosen anchor, awaited on the rest.
struct Probe {
    op_id: String,
    publish_at: Instant,
    awaiting: BTreeSet<usize>, // node indices that haven't yet seen it
    is_revocation: bool,
}

/// In-flight rejoin convergence probe — set when a paused node returns.
/// Convergence = node's trust_graph token_count reaching the target captured
/// at the moment of rejoin (median across the still-online peers).
struct RejoinProbe {
    node_idx: usize,
    rejoined_at: Instant,
    target_tokens: usize,
}

/// Chaos layer state — owns the random walk that pauses/resumes nodes.
struct ChaosState {
    enabled: bool,
    /// Per-node online flag.
    online: Vec<bool>,
    /// When each currently-offline node should rejoin.
    offline_until: Vec<Option<Instant>>,
    /// Saved listen addrs from mesh formation, used for redial on rejoin.
    addrs: Vec<Multiaddr>,
    /// Saved peer ids for redial / explicit-peer add on rejoin.
    pids: Vec<libp2p::PeerId>,
    interval: Duration,
    offline_dur: Duration,
    max_fraction: f64,
    rng: StdRng,
    pending_rejoins: Vec<RejoinProbe>,
    /// Counters for the summary footer.
    pause_events: u64,
    rejoin_events: u64,
}

impl ChaosState {
    #[allow(clippy::too_many_arguments)] // chaos config — collapsing into a struct would just hide the same fields
    fn new(
        enabled: bool,
        n: usize,
        addrs: Vec<Multiaddr>,
        pids: Vec<libp2p::PeerId>,
        interval: Duration,
        offline_dur: Duration,
        max_fraction: f64,
        seed: u64,
    ) -> Self {
        Self {
            enabled,
            online: vec![true; n],
            offline_until: vec![None; n],
            addrs,
            pids,
            interval,
            offline_dur,
            max_fraction,
            rng: StdRng::seed_from_u64(seed.wrapping_add(0xC4A05)),
            pending_rejoins: Vec::new(),
            pause_events: 0,
            rejoin_events: 0,
        }
    }

    fn online_indices(&self) -> Vec<usize> {
        self.online
            .iter()
            .enumerate()
            .filter_map(|(i, on)| if *on { Some(i) } else { None })
            .collect()
    }

    fn offline_count(&self) -> usize {
        self.online.iter().filter(|o| !**o).count()
    }

    fn pick_anchor(&self) -> Option<usize> {
        // Pick the lowest-index online node as the publish anchor for probes.
        self.online.iter().position(|on| *on)
    }
}

pub async fn run(
    cli: Cli,
    mut stop: watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error>> {
    let nodes_count = cli.effective_nodes();
    let duration = cli.effective_duration();
    info!(
        nodes = nodes_count,
        duration_secs = duration.as_secs(),
        smoke = cli.smoke,
        "starting load test"
    );

    let metrics = Arc::new(Metrics::new());

    // ---- spin up nodes ----
    let mut nodes: Vec<DdsNode> = Vec::with_capacity(nodes_count);
    let mut _dirs: Vec<TempDir> = Vec::with_capacity(nodes_count);
    let org = format!("loadtest-{}", cli.seed);
    for _ in 0..nodes_count {
        let (n, d) = spawn_node(&org).await?;
        nodes.push(n);
        _dirs.push(d);
    }

    // Wait for listen addrs.
    let mut addrs: Vec<Multiaddr> = Vec::with_capacity(nodes_count);
    for n in nodes.iter_mut() {
        addrs.push(wait_for_listen(n).await?);
    }
    // Full mesh dial.
    let pids: Vec<libp2p::PeerId> = nodes.iter().map(|n| n.peer_id).collect();
    #[allow(clippy::needless_range_loop)]
    for i in 0..nodes_count {
        for j in 0..nodes_count {
            if i == j {
                continue;
            }
            let addr = addrs[j].clone();
            let pid = pids[j];
            let n = &mut nodes[i];
            n.swarm.behaviour_mut().gossipsub.add_explicit_peer(&pid);
            n.swarm
                .behaviour_mut()
                .kademlia
                .add_address(&pid, addr.clone());
            let _ = n.swarm.dial(addr);
        }
    }
    // Pump a few seconds for mesh formation.
    pump_many(
        &mut nodes,
        Duration::from_secs(8),
        &metrics,
        &mut Vec::new(),
    )
    .await;
    info!("mesh formed");

    // ---- chaos layer state (idle if --chaos not set) ----
    let mut chaos = ChaosState::new(
        cli.chaos_enabled(),
        nodes_count,
        addrs.clone(),
        pids.clone(),
        cli.chaos_interval_dur(),
        cli.chaos_offline_dur(),
        cli.chaos_max_fraction.clamp(0.0, 0.9),
        cli.seed,
    );
    if chaos.enabled {
        info!(
            interval_secs = chaos.interval.as_secs(),
            offline_secs = chaos.offline_dur.as_secs(),
            max_fraction = chaos.max_fraction,
            "chaos layer enabled"
        );
    }

    // ---- per-node LocalServices (MemoryBackend, isolated from the swarm
    //      RedbBackend so we can measure local-op KPIs without disk I/O).
    // Each service has its own trusted root identity, retained so the
    // harness can sign vouch tokens that grant purposes to enrolled users
    // (otherwise issue_session fails because purposes_for() is empty).
    let mut services: Vec<LocalService<MemoryBackend>> = Vec::with_capacity(nodes_count);
    let mut roots_per_node: Vec<Identity> = Vec::with_capacity(nodes_count);
    for i in 0..nodes_count {
        let ident = Identity::generate(&format!("node-{i}"), &mut rand::rngs::OsRng);
        let root = Identity::generate(&format!("root-{i}"), &mut rand::rngs::OsRng);
        let mut roots = BTreeSet::new();
        roots.insert(root.id.to_urn());
        let graph = std::sync::Arc::new(std::sync::RwLock::new(TrustGraph::new()));
        let mut svc = LocalService::new(ident, graph, roots, MemoryBackend::new());
        // FIDO2 verify is on (we want to measure it). The synthetic builder
        // produces valid `none` attestations.
        svc.add_policy_rule(PolicyRule {
            effect: Effect::Allow,
            required_purpose: "repo:proj".into(),
            resource: "repo:proj".into(),
            actions: vec!["read".into(), "write".into()],
        });
        services.push(svc);
        roots_per_node.push(root);
    }

    // ---- workload state ----
    let mut synth = Synth::new(cli.seed);
    let _rng = StdRng::seed_from_u64(cli.seed.wrapping_add(1));
    let mut user_urns_per_node: Vec<Vec<String>> = vec![Vec::new(); nodes_count];

    // Workload pacing — convert per-hour/per-second knobs into per-tick
    // counts at the 100 ms tick rate.
    let tick = Duration::from_millis(100);
    let users_per_tick = (cli.users_per_hour as f64 / 36000.0).max(0.0);
    let devices_per_tick = (cli.devices_per_hour as f64 / 36000.0).max(0.0);
    let sessions_per_tick = (cli.sessions_per_second as f64 / 10.0).max(0.0);
    let evals_per_tick = (cli.policy_evals_per_second as f64 / 10.0).max(0.0);
    let revokes_per_tick = (cli.revocations_per_hour as f64 / 36000.0).max(0.0);

    // Gossip propagation probe interval.
    let mut probe_iv = make_interval(Duration::from_secs(2));
    // Revocation propagation probe interval.
    let mut revoke_probe_iv = make_interval(Duration::from_secs(10));
    // Periodic ticks.
    let mut work_iv = make_interval(tick);
    let mut gauge_iv = make_interval(Duration::from_secs(30));
    let mut log_iv = make_interval(Duration::from_secs(60));
    let mut snap_iv = make_interval(Duration::from_secs(15 * 60));
    // Expiry sweep — short cadence so the trust graph stays bounded.
    let mut expiry_iv = make_interval(Duration::from_secs(30));
    // Chaos: pick a node to flip every chaos_interval (jittered).
    let mut chaos_iv = make_interval(chaos.interval.max(Duration::from_secs(1)));
    // Rejoin check: poll convergence + scheduled rejoins every 500 ms.
    let mut rejoin_iv = make_interval(Duration::from_millis(500));

    // Carry-overs for fractional ops.
    let mut acc_user = 0.0f64;
    let mut acc_dev = 0.0f64;
    let mut acc_sess = 0.0f64;
    let mut acc_eval = 0.0f64;
    let mut acc_rev = 0.0f64;

    let mut probes: Vec<Probe> = Vec::new();
    let mut snap_idx: usize = 0;
    let started = Instant::now();
    let deadline = started + duration;
    let mut sys = System::new();
    let pid = Pid::from_u32(std::process::id());
    let mut last_rss: u64 = 0;

    let dur_sleep = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
    tokio::pin!(dur_sleep);

    info!("entering main loop");
    // Pre-check the initial stop value (in case shutdown raced ahead).
    if *stop.borrow() {
        info!("shutdown requested before main loop entry");
        return Ok(());
    }
    loop {
        tokio::select! {
            biased;
            res = stop.changed() => {
                // `changed()` resolves on a state change OR sender drop.
                // In both cases the right move is to wind down.
                if res.is_err() || *stop.borrow() {
                    info!("shutdown requested");
                    break;
                }
            }
            _ = &mut dur_sleep => {
                info!("duration elapsed");
                break;
            }
            _ = work_iv.tick() => {
                acc_user += users_per_tick;
                acc_dev += devices_per_tick;
                acc_sess += sessions_per_tick;
                acc_eval += evals_per_tick;
                acc_rev += revokes_per_tick;
                // Drain to integer counts.
                let n_user = acc_user as u64; acc_user -= n_user as f64;
                let n_dev = acc_dev as u64; acc_dev -= n_dev as f64;
                let n_sess = acc_sess as u64; acc_sess -= n_sess as f64;
                let n_eval = acc_eval as u64; acc_eval -= n_eval as f64;
                let n_rev = acc_rev as u64; acc_rev -= n_rev as f64;

                let online = if chaos.enabled {
                    chaos.online_indices()
                } else {
                    (0..nodes_count).collect()
                };
                if !online.is_empty() {
                    for _ in 0..n_user {
                        let idx = pick_online(&online, &mut synth_seq(&mut synth));
                        do_enroll_user(
                            &mut services[idx],
                            &roots_per_node[idx],
                            &mut synth,
                            &metrics,
                            &mut user_urns_per_node[idx],
                        );
                    }
                    for _ in 0..n_dev {
                        let idx = pick_online(&online, &mut synth_seq(&mut synth));
                        do_enroll_device(&mut services[idx], &mut synth, &metrics);
                    }
                    for _ in 0..n_sess {
                        let idx = pick_online(&online, &mut synth_seq(&mut synth));
                        do_issue_session(&mut services[idx], &mut synth, &metrics, &user_urns_per_node[idx]);
                    }
                    for _ in 0..n_eval {
                        let idx = pick_online(&online, &mut synth_seq(&mut synth));
                        do_eval_policy(&services[idx], &metrics, &user_urns_per_node[idx]);
                    }
                    for _ in 0..n_rev {
                        let idx = pick_online(&online, &mut synth_seq(&mut synth));
                        do_revoke_local(&mut services[idx], &metrics, &mut user_urns_per_node[idx]);
                    }
                }

                // Sample CRDT merge + ed25519 verify on every tick (cheap).
                sample_crdt_merge(&metrics);
                sample_ed25519(&metrics);
            }
            _ = probe_iv.tick() => {
                publish_probe(&mut nodes, &metrics, &mut probes, false, &chaos);
            }
            _ = revoke_probe_iv.tick() => {
                publish_probe(&mut nodes, &metrics, &mut probes, true, &chaos);
            }
            _ = chaos_iv.tick() => {
                if chaos.enabled {
                    chaos_step(&mut nodes, &mut chaos);
                }
            }
            _ = rejoin_iv.tick() => {
                if chaos.enabled {
                    chaos_check_rejoins(&mut nodes, &mut chaos, &metrics);
                }
            }
            _ = gauge_iv.tick() => {
                let elapsed = started.elapsed().as_secs();
                sys.refresh_processes_specifics(
                    ProcessesToUpdate::Some(&[pid]),
                    true,
                    ProcessRefreshKind::new().with_memory(),
                );
                let rss = sys.process(pid).map(|p| p.memory()).unwrap_or(0);
                let delta_rss = rss.saturating_sub(last_rss);
                last_rss = rss;
                let trust: Vec<usize> = nodes
                    .iter()
                    .map(|n| n.trust_graph.read().unwrap().token_count())
                    .collect();
                // LocalService doesn't expose a store accessor we can
                // count cheaply; use the dds-node store as a proxy.
                use dds_store::traits::TokenStore;
                let store: Vec<usize> = nodes
                    .iter()
                    .map(|n| n.store.count_tokens(None).unwrap_or(0))
                    .collect();
                let conn: Vec<usize> = nodes.iter().map(|n| n.connected_peers()).collect();
                // gossip-bandwidth proxy: change in RSS / 30s. Real net byte
                // counters aren't exposed by libp2p; documented limitation.
                let bw = delta_rss as f64 / 30.0;
                metrics.record_gauge(GaugeSample {
                    elapsed_secs: elapsed,
                    rss_bytes: rss,
                    trust_graph_tokens: trust,
                    store_tokens: store,
                    gossip_tx_bytes_per_sec: bw,
                    connected_peers: conn,
                    online: chaos.online.clone(),
                });
            }
            _ = log_iv.tick() => {
                let snap = metrics.snapshot();
                let elapsed = started.elapsed().as_secs().max(1);
                let mut total = 0u64;
                let mut total_err = 0u64;
                for op in snap.ops.values() {
                    total += op.count;
                    total_err += op.err;
                }
                let issue = snap.ops.get("issue_session");
                let eval = snap.ops.get("evaluate_policy");
                info!(
                    elapsed,
                    ops = total,
                    err = total_err,
                    op_per_s = total / elapsed,
                    sess_p99_us = issue.map(|o| o.p99_ns / 1000).unwrap_or(0),
                    eval_p99_us = eval.map(|o| o.p99_ns / 1000).unwrap_or(0),
                    rss_mb = last_rss as f64 / (1024.0 * 1024.0),
                    "rolling stats"
                );
            }
            _ = snap_iv.tick() => {
                snap_idx += 1;
                let snap = metrics.snapshot();
                if let Err(e) = write_snapshot(&cli.output_dir, &snap, snap_idx) {
                    warn!("snapshot write failed: {e}");
                }
            }
            _ = expiry_iv.tick() => {
                // Sweep expired sessions/tokens off each LocalService's
                // trust graph. The LocalService doesn't expose its graph
                // directly, so we sweep through the dds-node graph instead
                // (it sees the gossiped tokens).
                for n in nodes.iter_mut() {
                    let _ = n.sweep_expired();
                }
            }
            ev = next_swarm_event(&mut nodes) => {
                if let Some((idx, event)) = ev {
                    handle_swarm_event(&mut nodes, idx, event, &metrics, &mut probes);
                }
            }
        }
    }

    info!("draining and writing summary");
    let snap = metrics.snapshot();
    let kpis = compute_kpis(&snap);
    let summary = Summary {
        duration_secs: started.elapsed().as_secs(),
        nodes: nodes_count,
        kpis: kpis.clone(),
        metrics: snap,
        chaos: ChaosSummary {
            enabled: chaos.enabled,
            pause_events: chaos.pause_events,
            rejoin_events: chaos.rejoin_events,
            interval_secs: chaos.interval.as_secs(),
            offline_secs: chaos.offline_dur.as_secs(),
            max_fraction: chaos.max_fraction,
        },
    };
    write_summary(&cli.output_dir, &summary)?;
    info!("wrote summary to {}", cli.output_dir.display());

    // Smoke gating.
    if cli.smoke {
        let mut any_fail = false;
        for k in &summary.kpis {
            if matches!(k.status, crate::report::KpiStatus::Fail) {
                tracing::error!(name = %k.name, measured = %k.measured, "KPI FAIL");
                any_fail = true;
            }
        }
        // Op error-rate gate (1%).
        for (name, op) in &summary.metrics.ops {
            if op.count == 0 {
                continue;
            }
            let rate = op.err as f64 / op.count as f64;
            if rate > 0.01 {
                tracing::error!(op = %name, err = op.err, count = op.count, "error rate exceeds 1%");
                any_fail = true;
            }
        }
        if any_fail {
            std::process::exit(2);
        }
    }
    Ok(())
}

// ---------- workload op runners ----------

fn do_enroll_user(
    svc: &mut LocalService<MemoryBackend>,
    root: &Identity,
    synth: &mut Synth,
    metrics: &Metrics,
    user_urns: &mut Vec<String>,
) {
    let req = synth.user_request();
    let t0 = Instant::now();
    let res = svc.enroll_user(req);
    let dt = t0.elapsed();
    match res {
        Ok(r) => {
            metrics.record("enroll_user", dt, true);
            // Sign a vouch from the trusted root → user with purpose
            // `repo:proj`. Without this, purposes_for() returns empty and
            // every subsequent issue_session for this user fails.
            //
            // Token::create() requires Vouch tokens to carry both vch_iss
            // and vch_sum (payload hash of the user's attestation token),
            // so decode the just-issued attestation to compute the hash.
            let attest = match Token::from_cbor(&r.token_cbor) {
                Ok(t) => t,
                Err(_) => return,
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let vouch_payload = TokenPayload {
                iss: root.id.to_urn(),
                iss_key: root.public_key.clone(),
                jti: format!("vouch-{}", r.jti),
                sub: r.urn.clone(),
                kind: TokenKind::Vouch,
                purpose: Some("repo:proj".into()),
                vch_iss: Some(r.urn.clone()),
                vch_sum: Some(attest.payload_hash()),
                revokes: None,
                iat: now,
                // 1 hour expiry — so the per-node `expiry_loop` reclaims
                // these as fast as new ones land, the trust graph reaches
                // steady state, and the soak measures realistic behavior.
                // The earlier 365-day expiry caused the 2026-04-09 soak's
                // graph to grow monotonically and contaminated the §10
                // KPI verdict (B5 was real, but B5 + monotonic growth
                // were entangled in the same number).
                exp: Some(now + 3600),
                body_type: None,
                body_cbor: None,
            };
            match Token::sign(vouch_payload, &root.signing_key) {
                Ok(vouch) => {
                    // Persist to the store (so a restart can rehydrate)
                    // and mirror to the shared in-memory graph (so the
                    // very next issue_session sees it). The trust graph
                    // is the source of truth for hot paths now (B5b);
                    // the store no longer drives per-query rebuilds.
                    use dds_store::traits::TokenStore;
                    let _ = svc.store_mut().put_token(&vouch);
                    let _ = svc.trust_graph_handle().write().unwrap().add_token(vouch);
                }
                Err(e) => warn!("vouch sign failed: {e}"),
            }
            // Cap the user pool well below one hour's worth of enrollments
            // (default 500/h ⇒ ~8/min, so 300 ≈ 36 min). Combined with the
            // 1-hour vouch expiry, this means we never try to issue
            // sessions against users whose vouch has been expired by the
            // sweeper, so the soak stays at steady state instead of
            // accumulating ghost users.
            if user_urns.len() < 300 {
                user_urns.push(r.urn);
            } else {
                let i = (r.jti.len()) % user_urns.len();
                user_urns[i] = r.urn;
            }
        }
        Err(e) => {
            metrics.record("enroll_user", dt, false);
            warn!("enroll_user failed: {e}");
        }
    }
}

fn do_enroll_device(svc: &mut LocalService<MemoryBackend>, synth: &mut Synth, metrics: &Metrics) {
    let req = synth.device_request();
    let t0 = Instant::now();
    let res = svc.enroll_device(req);
    let dt = t0.elapsed();
    metrics.record("enroll_device", dt, res.is_ok());
    if let Err(e) = res {
        warn!("enroll_device failed: {e}");
    }
}

fn do_issue_session(
    svc: &mut LocalService<MemoryBackend>,
    synth: &mut Synth,
    metrics: &Metrics,
    user_urns: &[String],
) {
    // No users enrolled on this node yet — skip rather than record a
    // guaranteed failure. The session pacer ramps up as enrollments land.
    let subj = match user_urns.last() {
        Some(u) => u.clone(),
        None => return,
    };
    let req = synth.session_request(subj);
    let t0 = Instant::now();
    let res = svc.issue_session(req);
    let dt = t0.elapsed();
    let ok = res.is_ok();
    metrics.record("issue_session", dt, ok);
    // Validate the issued session token (session_validate KPI).
    if let Ok(r) = res {
        let t1 = Instant::now();
        let validate_ok = match Token::from_cbor(&r.token_cbor) {
            Ok(tok) => {
                tok.validate().is_ok()
                    && SessionDocument::extract(&tok.payload)
                        .ok()
                        .flatten()
                        .is_some()
            }
            Err(_) => false,
        };
        metrics.record("session_validate", t1.elapsed(), validate_ok);
    }
}

fn do_eval_policy(svc: &LocalService<MemoryBackend>, metrics: &Metrics, user_urns: &[String]) {
    // Skip when the node has no users yet — same reasoning as do_issue_session.
    let subj = match user_urns.last() {
        Some(u) => u.clone(),
        None => return,
    };
    let t0 = Instant::now();
    let _ = svc.evaluate_policy(&subj, "repo:proj", "read");
    metrics.record("evaluate_policy", t0.elapsed(), true);
}

fn do_revoke_local(
    svc: &mut LocalService<MemoryBackend>,
    metrics: &Metrics,
    user_urns: &mut Vec<String>,
) {
    if user_urns.is_empty() {
        return;
    }
    let urn = user_urns.remove(0);
    use dds_store::traits::RevocationStore;
    let t0 = Instant::now();
    let r = svc.store_mut().revoke(&urn);
    metrics.record("revoke", t0.elapsed(), r.is_ok());
}

fn sample_crdt_merge(metrics: &Metrics) {
    // Single LWW merge — minimal isolated benchmark.
    let mut a = LwwRegister::new(1u64, 1);
    let b = LwwRegister::new(2u64, 2);
    let t0 = Instant::now();
    a.merge(&b);
    metrics.record("crdt_merge", t0.elapsed(), true);
}

fn sample_ed25519(metrics: &Metrics) {
    use ed25519_dalek::{Signer, SigningKey};
    // Cache a key + signature in a thread_local for stable measurement.
    thread_local! {
        static FIXTURE: std::cell::OnceCell<(ed25519_dalek::VerifyingKey, [u8;64], Vec<u8>)> = const { std::cell::OnceCell::new() };
    }
    FIXTURE.with(|cell| {
        let (vk, sig_bytes, msg) = cell.get_or_init(|| {
            let sk = SigningKey::generate(&mut rand::rngs::OsRng);
            let vk = sk.verifying_key();
            let msg = b"dds-loadtest fixture message".to_vec();
            let sig: Signature = sk.sign(&msg);
            (vk, sig.to_bytes(), msg)
        });
        let sig = Signature::from_bytes(sig_bytes);
        // Batch verifies inside one timed window so per-op cost is not
        // dominated by Instant::now() / hist-record overhead.
        const BATCH: u32 = 4096;
        let t0 = Instant::now();
        let mut ok_all = true;
        for _ in 0..BATCH {
            if vk.verify(msg, &sig).is_err() {
                ok_all = false;
            }
        }
        let per_op = t0.elapsed() / BATCH;
        metrics.record("ed25519_verify", per_op, ok_all);
    });
}

// ---------- gossip propagation probes ----------

fn publish_probe(
    nodes: &mut [DdsNode],
    metrics: &Metrics,
    probes: &mut Vec<Probe>,
    revocation: bool,
    chaos: &ChaosState,
) {
    if nodes.len() < 2 {
        return;
    }
    // Pick the first online node as the publish anchor; if everything is
    // offline (shouldn't happen — chaos enforces a min) bail.
    let anchor_idx = if chaos.enabled {
        match chaos.pick_anchor() {
            Some(i) => i,
            None => return,
        }
    } else {
        0
    };
    // Awaiting set is *online* peers that are not the anchor.
    let awaiting: BTreeSet<usize> = if chaos.enabled {
        chaos
            .online_indices()
            .into_iter()
            .filter(|i| *i != anchor_idx)
            .collect()
    } else {
        (0..nodes.len()).filter(|i| *i != anchor_idx).collect()
    };
    if awaiting.is_empty() {
        return;
    }
    // Build a synthetic attestation token signed by a fresh identity.
    let ident = Identity::generate("probe", &mut rand::rngs::OsRng);
    let jti = format!(
        "probe-{}-{}",
        if revocation { "rev" } else { "att" },
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    );
    let payload = TokenPayload {
        iss: ident.id.to_urn(),
        iss_key: ident.public_key.clone(),
        jti: jti.clone(),
        sub: ident.id.to_urn(),
        kind: if revocation {
            TokenKind::Revoke
        } else {
            TokenKind::Attest
        },
        purpose: Some("dds:directory-entry".into()),
        vch_iss: None,
        vch_sum: None,
        revokes: if revocation { Some(jti.clone()) } else { None },
        iat: 0,
        exp: Some(u64::MAX / 2),
        body_type: None,
        body_cbor: None,
    };
    let token = match Token::sign(payload, &ident.signing_key) {
        Ok(t) => t,
        Err(_) => return,
    };
    let token_bytes = match token.to_cbor() {
        Ok(b) => b,
        Err(_) => return,
    };

    let publish_at = Instant::now();
    let n0 = &mut nodes[anchor_idx];
    if revocation {
        let msg = GossipMessage::Revocation { token_bytes };
        if let Ok(cbor) = msg.to_cbor() {
            let topic = n0.topics.revocations.to_ident_topic();
            let _ = n0.swarm.behaviour_mut().gossipsub.publish(topic, cbor);
        }
        // Mirror locally on publisher.
        let _ = n0.trust_graph.write().unwrap().add_token(token.clone());
        probes.push(Probe {
            op_id: jti,
            publish_at,
            awaiting: awaiting.clone(),
            is_revocation: true,
        });
        let _ = metrics; // recorded on receive
    } else {
        let op = Operation {
            id: format!("op-{}", token.payload.jti),
            author: token.payload.iss.clone(),
            deps: Vec::new(),
            data: vec![0],
            timestamp: 0,
        };
        let mut op_bytes = Vec::new();
        if ciborium::into_writer(&op, &mut op_bytes).is_err() {
            return;
        }
        let msg = GossipMessage::DirectoryOp {
            op_bytes,
            token_bytes,
        };
        if let Ok(cbor) = msg.to_cbor() {
            let topic = n0.topics.operations.to_ident_topic();
            let _ = n0.swarm.behaviour_mut().gossipsub.publish(topic, cbor);
        }
        let _ = n0.trust_graph.write().unwrap().add_token(token.clone());
        use dds_store::traits::TokenStore;
        let _ = n0.store.put_token(&token);
        let _ = n0.dag.insert(op.clone());
        probes.push(Probe {
            op_id: op.id,
            publish_at,
            awaiting,
            is_revocation: false,
        });
    }
    // Garbage-collect probes older than 30s (timed out / dropped).
    let cutoff = Instant::now() - Duration::from_secs(30);
    probes.retain(|p| p.publish_at > cutoff || !p.awaiting.is_empty());
}

// ---------- swarm pumping ----------

async fn next_swarm_event(
    nodes: &mut [DdsNode],
) -> Option<(usize, SwarmEvent<dds_net::transport::DdsBehaviourEvent>)> {
    if nodes.is_empty() {
        return None;
    }
    let futs: Vec<_> = nodes
        .iter_mut()
        .map(|n| Box::pin(n.swarm.select_next_some()))
        .collect();
    let (event, idx, _rest) = futures::future::select_all(futs).await;
    Some((idx, event))
}

fn handle_swarm_event(
    nodes: &mut [DdsNode],
    idx: usize,
    event: SwarmEvent<dds_net::transport::DdsBehaviourEvent>,
    metrics: &Metrics,
    probes: &mut [Probe],
) {
    use dds_net::transport::DdsBehaviourEvent;
    match event {
        SwarmEvent::Behaviour(DdsBehaviourEvent::Gossipsub(
            libp2p::gossipsub::Event::Message { message, .. },
        )) => {
            ingest_gossip(nodes, idx, &message.topic, &message.data, metrics, probes);
        }
        SwarmEvent::NewListenAddr { address, .. } => {
            nodes[idx].config.network.listen_addr = address.to_string();
        }
        _ => {}
    }
}

fn ingest_gossip(
    nodes: &mut [DdsNode],
    idx: usize,
    topic_hash: &libp2p::gossipsub::TopicHash,
    data: &[u8],
    metrics: &Metrics,
    probes: &mut [Probe],
) {
    use dds_net::gossip::DdsTopic;
    let topic = match nodes[idx].topics.identify_topic(topic_hash) {
        Some(t) => t.clone(),
        None => return,
    };
    let msg = match GossipMessage::from_cbor(data) {
        Ok(m) => m,
        Err(_) => return,
    };
    match (topic, msg) {
        (
            DdsTopic::Operations(..),
            GossipMessage::DirectoryOp {
                op_bytes,
                token_bytes,
            },
        ) => {
            let op: Operation = match ciborium::from_reader(op_bytes.as_slice()) {
                Ok(op) => op,
                Err(_) => return,
            };
            let token = match Token::from_cbor(&token_bytes) {
                Ok(t) => t,
                Err(_) => return,
            };
            if token.validate().is_ok() {
                let _ = nodes[idx]
                    .trust_graph
                    .write()
                    .unwrap()
                    .add_token(token.clone());
                use dds_store::traits::TokenStore;
                let _ = nodes[idx].store.put_token(&token);
                let _ = nodes[idx].dag.insert(op.clone());
            }
            // Probe match?
            for p in probes.iter_mut() {
                if !p.is_revocation && p.op_id == op.id && p.awaiting.remove(&idx) {
                    metrics.record("gossip_propagation", p.publish_at.elapsed(), true);
                }
            }
        }
        (DdsTopic::Revocations(..), GossipMessage::Revocation { token_bytes }) => {
            let token = match Token::from_cbor(&token_bytes) {
                Ok(t) => t,
                Err(_) => return,
            };
            if token.validate().is_ok() {
                let _ = nodes[idx]
                    .trust_graph
                    .write()
                    .unwrap()
                    .add_token(token.clone());
                if let Some(target) = token.payload.revokes.clone() {
                    use dds_store::traits::RevocationStore;
                    let _ = nodes[idx].store.revoke(&target);
                }
            }
            for p in probes.iter_mut() {
                if p.is_revocation && p.op_id == token.payload.jti && p.awaiting.remove(&idx) {
                    metrics.record("revocation_propagation", p.publish_at.elapsed(), true);
                }
            }
        }
        _ => {}
    }
}

async fn pump_many(nodes: &mut [DdsNode], dur: Duration, metrics: &Metrics, probes: &mut [Probe]) {
    let deadline = Instant::now() + dur;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let evt = timeout(remaining, next_swarm_event(nodes)).await;
        match evt {
            Ok(Some((idx, event))) => handle_swarm_event(nodes, idx, event, metrics, probes),
            _ => return,
        }
    }
}

// ---------- node spawn ----------

async fn spawn_node(org: &str) -> Result<(DdsNode, TempDir), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().to_path_buf();

    let dkey = dds_domain::DomainKey::from_secret_bytes("loadtest.local", [7u8; 32]);
    let domain = dkey.domain();

    let p2p_keypair = libp2p::identity::Keypair::generate_ed25519();
    let peer_id = libp2p::PeerId::from(p2p_keypair.public());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let cert = dkey.issue_admission(peer_id.to_string(), now, None);
    dds_node::domain_store::save_admission_cert(&data_dir.join("admission.cbor"), &cert)?;

    let cfg = NodeConfig {
        data_dir,
        network: NetworkConfig {
            listen_addr: "/ip4/127.0.0.1/tcp/0".to_string(),
            bootstrap_peers: Vec::new(),
            mdns_enabled: false,
            heartbeat_secs: 1,
            idle_timeout_secs: 60,
            api_addr: "127.0.0.1:0".to_string(),
            api_auth: Default::default(),
            allow_legacy_v1_tokens: false,
            metrics_addr: None,
        },
        org_hash: org.to_string(),
        domain: dds_node::config::DomainConfig {
            name: domain.name.clone(),
            id: domain.id.to_string(),
            pubkey: dds_domain::domain::to_hex(&domain.pubkey),
            admission_path: None,
            audit_log_enabled: false,
            max_delegation_depth: 5,
            audit_log_max_entries: 0,
            audit_log_retention_days: 0,
            enforce_device_scope_vouch: false,
            // A-1 step-1: loadtest harness uses synthetic enrollment
            // and does not exercise the attestation gate.
            allow_unattested_credentials: true,
            fido2_allowed_aaguids: Vec::new(),
            fido2_attestation_roots: Vec::new(),
        },
        trusted_roots: Vec::new(),
        bootstrap_admin_urn: None,
        identity_path: None,
        expiry_scan_interval_secs: 60,
    };
    let mut node = DdsNode::init(cfg, p2p_keypair)?;
    node.swarm.listen_on("/ip4/127.0.0.1/tcp/0".parse()?)?;
    node.topics
        .subscribe_all(&mut node.swarm.behaviour_mut().gossipsub, false)?;
    Ok((node, dir))
}

async fn wait_for_listen(node: &mut DdsNode) -> Result<Multiaddr, Box<dyn std::error::Error>> {
    let result = timeout(Duration::from_secs(5), async {
        loop {
            let event = node.swarm.select_next_some().await;
            if let SwarmEvent::NewListenAddr { address, .. } = event {
                return address;
            }
        }
    })
    .await?;
    Ok(result)
}

// ---------- helpers ----------

fn make_interval(d: Duration) -> Interval {
    let mut iv = interval(d);
    iv.set_missed_tick_behavior(MissedTickBehavior::Skip);
    iv
}

/// Round-robin selection over a precomputed list of online indices.
fn pick_online(online: &[usize], seq: &mut u64) -> usize {
    let v = online[(*seq as usize) % online.len()];
    *seq = seq.wrapping_add(1);
    v
}

fn synth_seq(s: &mut Synth) -> u64 {
    // Cheap monotonic per-call value piggybacking on synth's internal seq.
    // Use the address of `s` plus a counter; we just need *some* spread.
    // (A separate counter would be cleaner; this is fine for round-robin.)
    let _ = s;
    static CTR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    CTR.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

// ---------- chaos layer ----------

/// One step of the chaos walk: pick a node to pause if we are below the
/// max-offline cap, or do nothing this tick.
fn chaos_step(nodes: &mut [DdsNode], chaos: &mut ChaosState) {
    let n = nodes.len();
    if n < 3 {
        return; // pointless with fewer than 3 nodes (need quorum)
    }
    let max_offline = ((n as f64) * chaos.max_fraction).floor() as usize;
    let max_offline = max_offline.max(1).min(n.saturating_sub(2));
    if chaos.offline_count() >= max_offline {
        return;
    }
    // Pick a random online node.
    let online: Vec<usize> = chaos.online_indices();
    if online.len() <= 2 {
        return; // never pause when ≤ 2 nodes are reachable
    }
    let pick = online[chaos.rng.gen_range(0..online.len())];
    pause_node(nodes, chaos, pick);
}

/// Pause a node: disconnect from peers, mark offline, schedule rejoin.
fn pause_node(nodes: &mut [DdsNode], chaos: &mut ChaosState, idx: usize) {
    let connected: Vec<libp2p::PeerId> = nodes[idx].swarm.connected_peers().copied().collect();
    let mut closed = 0usize;
    for pid in connected {
        if nodes[idx].swarm.disconnect_peer_id(pid).is_ok() {
            closed += 1;
        }
    }
    chaos.online[idx] = false;
    // Jitter offline duration ±25% so we don't sync rejoins.
    let base = chaos.offline_dur.as_secs_f64();
    let jitter = chaos.rng.gen_range(0.75..1.25);
    let dur = Duration::from_secs_f64(base * jitter);
    chaos.offline_until[idx] = Some(Instant::now() + dur);
    chaos.pause_events += 1;
    info!(
        node = idx,
        closed_conns = closed,
        offline_secs = dur.as_secs(),
        offline_total = chaos.offline_count(),
        "chaos: paused node"
    );
}

/// Periodic rejoin check: bring back any node whose offline window elapsed
/// and tick the convergence probes for already-rejoined nodes.
fn chaos_check_rejoins(nodes: &mut [DdsNode], chaos: &mut ChaosState, metrics: &Metrics) {
    let now = Instant::now();
    // 1. Resume any node whose offline window has expired.
    let to_resume: Vec<usize> = (0..nodes.len())
        .filter(|i| {
            !chaos.online[*i]
                && chaos
                    .offline_until
                    .get(*i)
                    .and_then(|o| *o)
                    .is_some_and(|t| t <= now)
        })
        .collect();
    for idx in to_resume {
        resume_node(nodes, chaos, idx);
    }

    // 2. Tick convergence probes — any rejoin probe whose target tokens have
    //    been seen is closed and recorded.
    let mut converged: Vec<usize> = Vec::new();
    for (slot, p) in chaos.pending_rejoins.iter().enumerate() {
        let cur = nodes[p.node_idx].trust_graph.read().unwrap().token_count();
        if cur >= p.target_tokens {
            metrics.record("rejoin_convergence", p.rejoined_at.elapsed(), true);
            info!(
                node = p.node_idx,
                target = p.target_tokens,
                converged_in_secs = p.rejoined_at.elapsed().as_secs_f64(),
                "chaos: rejoin convergence reached"
            );
            converged.push(slot);
        } else if p.rejoined_at.elapsed() > Duration::from_secs(300) {
            // Time out probes after 5 min so memory stays bounded.
            metrics.record("rejoin_convergence", p.rejoined_at.elapsed(), false);
            warn!(
                node = p.node_idx,
                target = p.target_tokens,
                have = cur,
                "chaos: rejoin convergence TIMED OUT after 300s"
            );
            converged.push(slot);
        }
    }
    // Drain converged probes (reverse order so indices stay valid).
    for slot in converged.into_iter().rev() {
        chaos.pending_rejoins.swap_remove(slot);
    }
}

/// Resume a node: re-add explicit peers, redial, capture target token count.
fn resume_node(nodes: &mut [DdsNode], chaos: &mut ChaosState, idx: usize) {
    // Capture the median trust-graph token count across the still-online
    // peers — this is the convergence target for the rejoining node.
    let mut online_counts: Vec<usize> = chaos
        .online_indices()
        .into_iter()
        .map(|i| nodes[i].trust_graph.read().unwrap().token_count())
        .collect();
    online_counts.sort_unstable();
    let target = if online_counts.is_empty() {
        0
    } else {
        online_counts[online_counts.len() / 2]
    };

    // Re-add explicit peers and redial. Skip self.
    let n = nodes.len();
    for j in 0..n {
        if j == idx {
            continue;
        }
        let pid = chaos.pids[j];
        let addr = chaos.addrs[j].clone();
        let node = &mut nodes[idx];
        node.swarm.behaviour_mut().gossipsub.add_explicit_peer(&pid);
        node.swarm
            .behaviour_mut()
            .kademlia
            .add_address(&pid, addr.clone());
        let _ = node.swarm.dial(addr);
    }
    chaos.online[idx] = true;
    chaos.offline_until[idx] = None;
    chaos.rejoin_events += 1;
    chaos.pending_rejoins.push(RejoinProbe {
        node_idx: idx,
        rejoined_at: Instant::now(),
        target_tokens: target,
    });
    info!(
        node = idx,
        target_tokens = target,
        "chaos: resumed node, awaiting convergence"
    );
}

// Silence dead-code in this file (some helpers used only in select branches).
#[allow(dead_code)]
fn _used(_: &BTreeMap<String, ()>, _: &HashMap<String, ()>) {}
