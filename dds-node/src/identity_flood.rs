//! **R1 (single-node review 2026-10-13) — fresh-identity budget.**
//!
//! Any admitted peer can mint an unlimited number of identities and have
//! every node verify, store and keep their tokens forever. The ingest
//! gates cannot tell a throw-away identity from a brand-new user at the
//! moment its first token arrives: both are a self-signed attestation
//! from an issuer nobody has seen. What separates them is what happens
//! *next* — a real user is vouched by someone with a chain to a trusted
//! root within minutes, a throw-away identity never is.
//!
//! The [`IdentityLedger`] therefore charges each *source* (the gossip
//! publisher a token was signed by, or the sync responder that served it)
//! for the fresh identities it introduces, and lets an identity stop
//! counting as soon as it becomes anchored. A source whose identities
//! stay unanchored past a grace period in numbers beyond the budget is an
//! identity flood. Two outcomes are left to the node (`dds-node::node`):
//! a gossip publisher is quarantined — it signed the flood itself — while
//! a sync responder is only throttled, because an honest node may be
//! relaying material it accepted before the flood was caught.
//!
//! **Follow-up review (2026-10-13), finding 3.** Counting identities
//! alone did not bound *volume*: once an identity was known it could
//! publish without limit, and by issuing continuously it postponed its
//! own pruning. The ledger therefore also charges each source for every
//! token it delivers from an **unanchored** issuer — a per-window token
//! count and a byte total ([`Limits::token_budget`],
//! [`Limits::byte_budget`]). Anchored issuers are not charged: someone
//! with a chain to a root signs for them, so they are accountable through
//! revocation, and a legitimate catch-up batch is almost entirely
//! anchored material.
//!
//! Pure data structure: no clock access, no I/O. `now` is injected so the
//! unit tests can drive the window and grace boundaries exactly.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::{Duration, Instant};

/// Budget window: one calendar-ish day from a source's first fresh
/// identity in the window.
pub const WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

/// Why a fresh identity was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// More unanchored-past-grace identities from this source than the
    /// budget allows.
    BudgetExceeded,
    /// More fresh identities (anchored or not) from this source in the
    /// window than the hard cap allows.
    HardCapExceeded,
    /// More tokens from unanchored issuers delivered by this source in
    /// the window than the token budget allows.
    TokenBudgetExceeded,
    /// More bytes of tokens from unanchored issuers delivered by this
    /// source in the window than the byte budget allows.
    ByteBudgetExceeded,
}

/// Budget parameters. A zero disables the limit it belongs to; with all
/// four zero the ledger accepts everything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Unanchored fresh identities past grace per source per window.
    pub budget: u32,
    pub grace: Duration,
    /// Fresh identities, anchored or not, per source per window.
    pub hard_cap: u32,
    /// Tokens from unanchored issuers per source per window.
    pub token_budget: u32,
    /// Bytes of tokens from unanchored issuers per source per window.
    pub byte_budget: u64,
}

impl Limits {
    pub fn disabled(&self) -> bool {
        self.budget == 0 && self.hard_cap == 0 && self.token_budget == 0 && self.byte_budget == 0
    }
}

/// Per-source accounting.
#[derive(Debug)]
struct SourceLedger {
    window_start: Instant,
    /// Fresh identities introduced in the window, anchored or not.
    total: u32,
    /// Identities still inside the grace period, oldest first (insertion
    /// order is time order because `first_seen` is monotonic).
    young: VecDeque<(Instant, String)>,
    /// Identities past the grace period that are still unanchored.
    aged: BTreeSet<String>,
    /// Tokens from unanchored issuers delivered in the window.
    tokens: u32,
    /// Bytes of those tokens.
    bytes: u64,
}

impl SourceLedger {
    fn new(now: Instant) -> Self {
        Self {
            window_start: now,
            total: 0,
            young: VecDeque::new(),
            aged: BTreeSet::new(),
            tokens: 0,
            bytes: 0,
        }
    }
}

/// Fresh-identity ledger across all sources. `S` is the source key
/// (`PeerId` in production; `&str` / `u32` in tests).
#[derive(Debug)]
pub struct IdentityLedger<S: Ord + Clone> {
    limits: Limits,
    sources: BTreeMap<S, SourceLedger>,
    /// identity URN → the source charged for it, for the anchoring
    /// refund. An identity is charged to exactly one source: the first
    /// that introduced it.
    charged_to: BTreeMap<String, S>,
}

impl<S: Ord + Clone> IdentityLedger<S> {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            sources: BTreeMap::new(),
            charged_to: BTreeMap::new(),
        }
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Reset a source whose window has elapsed, dropping its charges.
    fn roll_window(&mut self, source: &S, now: Instant) {
        let expired = match self.sources.get(source) {
            Some(l) => now.duration_since(l.window_start) >= WINDOW,
            None => false,
        };
        if expired {
            if let Some(l) = self.sources.remove(source) {
                for (_, urn) in l.young {
                    self.charged_to.remove(&urn);
                }
                for urn in l.aged {
                    self.charged_to.remove(&urn);
                }
            }
        }
    }

    /// Promote identities whose grace period has elapsed and that are
    /// still unanchored into the aged set.
    fn age(&mut self, source: &S, now: Instant) {
        let grace = self.limits.grace;
        let Some(l) = self.sources.get_mut(source) else {
            return;
        };
        while let Some((first_seen, _)) = l.young.front() {
            if now.duration_since(*first_seen) < grace {
                break;
            }
            let (_, urn) = l.young.pop_front().expect("front checked");
            // Still charged ⇒ still unanchored.
            if self.charged_to.contains_key(&urn) {
                l.aged.insert(urn);
            }
        }
    }

    /// Number of unanchored identities past grace that `source` is
    /// currently charged for.
    pub fn aged_count(&mut self, source: &S, now: Instant) -> usize {
        self.roll_window(source, now);
        self.age(source, now);
        self.sources.get(source).map_or(0, |l| l.aged.len())
    }

    /// Whether `source` is over budget right now (without charging
    /// anything).
    pub fn over_budget(&mut self, source: &S, now: Instant) -> bool {
        if self.limits.budget == 0 {
            return false;
        }
        self.aged_count(source, now) > self.limits.budget as usize
    }

    /// Charge `source` for introducing the fresh identity `urn`.
    ///
    /// `already_anchored` says the identity holds an effective vouch at
    /// the moment it arrives (its vouch came first); it then counts only
    /// toward the hard cap. Returns `Err` when the identity must be
    /// refused — the caller decides what that means for the source.
    pub fn charge(
        &mut self,
        source: &S,
        urn: &str,
        already_anchored: bool,
        now: Instant,
    ) -> Result<(), Refusal> {
        if self.limits.disabled() {
            return Ok(());
        }
        self.roll_window(source, now);
        self.age(source, now);
        if self.charged_to.contains_key(urn) {
            // Introduced earlier in the window by some source; a
            // re-delivery is not a new identity.
            return Ok(());
        }
        let budget = self.limits.budget;
        let hard_cap = self.limits.hard_cap;
        let l = self
            .sources
            .entry(source.clone())
            .or_insert_with(|| SourceLedger::new(now));
        if hard_cap != 0 && l.total >= hard_cap {
            return Err(Refusal::HardCapExceeded);
        }
        if budget != 0 && l.aged.len() > budget as usize {
            return Err(Refusal::BudgetExceeded);
        }
        l.total += 1;
        if !already_anchored {
            l.young.push_back((now, urn.to_string()));
            self.charged_to.insert(urn.to_string(), source.clone());
        }
        Ok(())
    }

    /// Charge `source` for delivering one token of `len` bytes from an
    /// issuer that is not anchored. Independent of the identity budget:
    /// a token from a long-known but never-vouched identity is charged
    /// here and nowhere else. Over either quota the token is refused and
    /// nothing is recorded, so a source stays exactly at the quota until
    /// its window rolls over.
    pub fn charge_token(&mut self, source: &S, len: usize, now: Instant) -> Result<(), Refusal> {
        let token_budget = self.limits.token_budget;
        let byte_budget = self.limits.byte_budget;
        if token_budget == 0 && byte_budget == 0 {
            return Ok(());
        }
        self.roll_window(source, now);
        let l = self
            .sources
            .entry(source.clone())
            .or_insert_with(|| SourceLedger::new(now));
        if token_budget != 0 && l.tokens >= token_budget {
            return Err(Refusal::TokenBudgetExceeded);
        }
        let bytes = l.bytes.saturating_add(len as u64);
        if byte_budget != 0 && bytes > byte_budget {
            return Err(Refusal::ByteBudgetExceeded);
        }
        l.tokens += 1;
        l.bytes = bytes;
        Ok(())
    }

    /// Tokens from unanchored issuers `source` delivered in its current
    /// window, and their byte total.
    pub fn volume(&self, source: &S) -> (u32, u64) {
        self.sources
            .get(source)
            .map_or((0, 0), |l| (l.tokens, l.bytes))
    }

    /// The identity `urn` became anchored: stop counting it against
    /// whichever source introduced it. Returns that source.
    pub fn anchored(&mut self, urn: &str) -> Option<S> {
        let source = self.charged_to.remove(urn)?;
        if let Some(l) = self.sources.get_mut(&source) {
            l.aged.remove(urn);
            // `young` entries are skipped lazily at promotion time.
        }
        Some(source)
    }

    /// Fresh identities `source` introduced in its current window,
    /// anchored or not.
    pub fn total(&self, source: &S) -> u32 {
        self.sources.get(source).map_or(0, |l| l.total)
    }

    /// Number of sources with a live window (bounded by the number of
    /// admitted peers that introduced an identity in the last day).
    pub fn source_count(&self) -> usize {
        self.sources.len()
    }

    /// Drop sources whose window has elapsed. Called from a periodic tick
    /// so a source that went quiet does not keep its charges around.
    pub fn sweep(&mut self, now: Instant) {
        let stale: Vec<S> = self
            .sources
            .iter()
            .filter(|(_, l)| now.duration_since(l.window_start) >= WINDOW)
            .map(|(s, _)| s.clone())
            .collect();
        for s in stale {
            self.roll_window(&s, now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(budget: u32, grace_secs: u64, hard_cap: u32) -> Limits {
        Limits {
            budget,
            grace: Duration::from_secs(grace_secs),
            hard_cap,
            token_budget: 0,
            byte_budget: 0,
        }
    }

    fn volume_limits(token_budget: u32, byte_budget: u64) -> Limits {
        Limits {
            budget: 0,
            grace: Duration::from_secs(0),
            hard_cap: 0,
            token_budget,
            byte_budget,
        }
    }

    #[test]
    fn identities_inside_grace_never_count() {
        let t0 = Instant::now();
        let mut l = IdentityLedger::new(limits(2, 60, 0));
        for i in 0..10 {
            assert_eq!(l.charge(&"src", &format!("urn:{i}"), false, t0), Ok(()));
        }
        assert!(!l.over_budget(&"src", t0 + Duration::from_secs(59)));
        assert_eq!(l.total(&"src"), 10);
    }

    #[test]
    fn unanchored_past_grace_trip_the_budget_but_anchored_ones_do_not() {
        let t0 = Instant::now();
        let mut l = IdentityLedger::new(limits(2, 60, 0));
        for i in 0..5 {
            l.charge(&"src", &format!("urn:{i}"), false, t0).unwrap();
        }
        // Three of five get vouched inside the grace period.
        assert_eq!(l.anchored("urn:0"), Some("src"));
        assert_eq!(l.anchored("urn:1"), Some("src"));
        assert_eq!(l.anchored("urn:2"), Some("src"));
        assert_eq!(l.anchored("urn:2"), None, "second refund is a no-op");
        let later = t0 + Duration::from_secs(61);
        assert_eq!(l.aged_count(&"src", later), 2);
        assert!(
            !l.over_budget(&"src", later),
            "2 unanchored == budget 2: not over"
        );
        // One more unanchored past grace tips it.
        l.charge(&"src", "urn:5", false, t0).unwrap();
        assert!(l.over_budget(&"src", later));
        assert_eq!(
            l.charge(&"src", "urn:6", false, later),
            Err(Refusal::BudgetExceeded)
        );
        // Another source is unaffected.
        assert_eq!(l.charge(&"other", "urn:7", false, later), Ok(()));
    }

    #[test]
    fn already_anchored_identities_count_only_toward_hard_cap() {
        let t0 = Instant::now();
        let mut l = IdentityLedger::new(limits(1, 0, 3));
        for i in 0..3 {
            assert_eq!(l.charge(&"src", &format!("urn:{i}"), true, t0), Ok(()));
        }
        assert!(!l.over_budget(&"src", t0 + Duration::from_secs(1)));
        assert_eq!(
            l.charge(&"src", "urn:3", true, t0),
            Err(Refusal::HardCapExceeded)
        );
    }

    #[test]
    fn redelivery_of_a_charged_identity_is_free_and_window_rolls_over() {
        let t0 = Instant::now();
        let mut l = IdentityLedger::new(limits(1, 0, 2));
        l.charge(&"src", "urn:a", false, t0).unwrap();
        l.charge(&"src", "urn:a", false, t0).unwrap();
        l.charge(&"src", "urn:a", false, t0).unwrap();
        assert_eq!(l.total(&"src"), 1, "same identity charged once");
        l.charge(&"src", "urn:b", false, t0).unwrap();
        assert_eq!(
            l.charge(&"src", "urn:c", false, t0),
            Err(Refusal::HardCapExceeded)
        );
        let next_day = t0 + WINDOW;
        assert_eq!(l.charge(&"src", "urn:c", false, next_day), Ok(()));
        assert_eq!(l.total(&"src"), 1, "window reset");
        assert_eq!(
            l.anchored("urn:a"),
            None,
            "old charges were dropped with the window"
        );
    }

    #[test]
    fn sweep_drops_quiet_sources_and_disabled_limits_accept_everything() {
        let t0 = Instant::now();
        let mut l = IdentityLedger::new(limits(1, 0, 1));
        l.charge(&"src", "urn:a", false, t0).unwrap();
        assert_eq!(l.source_count(), 1);
        l.sweep(t0 + WINDOW);
        assert_eq!(l.source_count(), 0);

        let mut off = IdentityLedger::new(limits(0, 0, 0));
        for i in 0..100 {
            assert_eq!(off.charge(&"src", &format!("urn:{i}"), false, t0), Ok(()));
        }
        assert!(!off.over_budget(&"src", t0 + WINDOW));
        assert!(off.limits().disabled());
        assert!(!volume_limits(1, 0).disabled());
    }

    /// Follow-up review finding 3: a known identity's tokens are bounded
    /// by the per-source token count and byte quotas, which the identity
    /// budget never touched.
    #[test]
    fn token_and_byte_quotas_bound_volume_per_source_and_window() {
        let t0 = Instant::now();
        let mut l = IdentityLedger::new(volume_limits(3, 0));
        for _ in 0..3 {
            assert_eq!(l.charge_token(&"src", 100, t0), Ok(()));
        }
        assert_eq!(
            l.charge_token(&"src", 100, t0),
            Err(Refusal::TokenBudgetExceeded)
        );
        assert_eq!(
            l.volume(&"src"),
            (3, 300),
            "a refused token is not recorded"
        );
        assert_eq!(l.charge_token(&"other", 100, t0), Ok(()), "per source");
        assert_eq!(
            l.charge_token(&"src", 100, t0 + WINDOW),
            Ok(()),
            "window rolled over"
        );
        assert_eq!(l.volume(&"src"), (1, 100));

        let mut b = IdentityLedger::new(volume_limits(0, 250));
        assert_eq!(b.charge_token(&"src", 100, t0), Ok(()));
        assert_eq!(b.charge_token(&"src", 100, t0), Ok(()));
        assert_eq!(
            b.charge_token(&"src", 100, t0),
            Err(Refusal::ByteBudgetExceeded)
        );
        assert_eq!(
            b.charge_token(&"src", 50, t0),
            Ok(()),
            "a smaller token still fits"
        );
        assert_eq!(b.volume(&"src"), (3, 250));

        // The identity budget is untouched by volume charges and vice
        // versa.
        let mut both = IdentityLedger::new(Limits {
            budget: 1,
            grace: Duration::from_secs(0),
            hard_cap: 0,
            token_budget: 2,
            byte_budget: 0,
        });
        assert_eq!(both.charge(&"src", "urn:a", false, t0), Ok(()));
        assert_eq!(both.charge_token(&"src", 10, t0), Ok(()));
        assert_eq!(both.charge_token(&"src", 10, t0), Ok(()));
        assert_eq!(
            both.charge_token(&"src", 10, t0),
            Err(Refusal::TokenBudgetExceeded)
        );
        assert_eq!(both.total(&"src"), 1);
        assert_eq!(both.aged_count(&"src", t0 + Duration::from_secs(1)), 1);
    }
}
