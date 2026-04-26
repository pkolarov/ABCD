//! Criterion benchmark for SessionDocument issue + validate.
//!
//! Measures the round trip:
//!   1. `LocalService::issue_session` (sign + embed SessionDocument)
//!   2. `Token::from_cbor` + `Token::validate` (verify on the consuming side)
//!   3. `SessionDocument::extract` (decode body)
//!
//! Targets the §10 KPI of <= 1 ms local auth decision.

use std::collections::BTreeSet;
use std::sync::{Arc, RwLock};

use criterion::{Criterion, criterion_group, criterion_main};
use dds_core::identity::Identity;
use dds_core::token::{Token, TokenKind, TokenPayload};
use dds_core::trust::TrustGraph;
use dds_domain::{DomainDocument, SessionDocument};
use dds_node::service::{LocalService, SessionRequest};
use dds_store::MemoryBackend;
use rand::rngs::OsRng;

fn bench_session_issue_and_validate(c: &mut Criterion) {
    let node = Identity::generate("bench-node", &mut OsRng);
    let root = Identity::generate("bench-root", &mut OsRng);
    let user = Identity::generate("bench-user", &mut OsRng);
    let user_urn = user.id.to_urn();

    // Post-B5b, `LocalService::new` takes a shared `Arc<RwLock<TrustGraph>>`
    // so the swarm event loop and the service share one in-memory graph.
    // The bench has no swarm, so the Arc lives only as long as the service.
    //
    // `issue_session` requires the subject to have at least one granted
    // purpose; otherwise it returns `Domain("subject has no granted
    // purposes…")`. Seed the graph with: root self-attest, user attest,
    // and a vouch from root → user granting purpose "api".
    let mut graph = TrustGraph::new();
    let root_attest = Token::sign(
        TokenPayload {
            iss: root.id.to_urn(),
            iss_key: root.public_key.clone(),
            jti: "bench-attest-root".into(),
            sub: root.id.to_urn(),
            kind: TokenKind::Attest,
            purpose: None,
            vch_iss: None,
            vch_sum: None,
            revokes: None,
            iat: 1000,
            exp: Some(4102444800),
            body_type: None,
            body_cbor: None,
        },
        &root.signing_key,
    )
    .unwrap();
    let user_attest = Token::sign(
        TokenPayload {
            iss: user.id.to_urn(),
            iss_key: user.public_key.clone(),
            jti: "bench-attest-user".into(),
            sub: user.id.to_urn(),
            kind: TokenKind::Attest,
            purpose: None,
            vch_iss: None,
            vch_sum: None,
            revokes: None,
            iat: 1000,
            exp: Some(4102444800),
            body_type: None,
            body_cbor: None,
        },
        &user.signing_key,
    )
    .unwrap();
    let vouch = Token::sign(
        TokenPayload {
            iss: root.id.to_urn(),
            iss_key: root.public_key.clone(),
            jti: "bench-vouch-user-api".into(),
            sub: user_urn.clone(),
            kind: TokenKind::Vouch,
            purpose: Some("api".into()),
            vch_iss: Some(user_urn.clone()),
            vch_sum: Some(user_attest.payload_hash()),
            revokes: None,
            iat: 1000,
            exp: Some(4102444800),
            body_type: None,
            body_cbor: None,
        },
        &root.signing_key,
    )
    .unwrap();
    graph.add_token(root_attest).unwrap();
    graph.add_token(user_attest).unwrap();
    graph.add_token(vouch).unwrap();

    let trust = Arc::new(RwLock::new(graph));
    let mut roots: BTreeSet<String> = BTreeSet::new();
    roots.insert(root.id.to_urn());
    let store = MemoryBackend::new();
    let mut svc = LocalService::new(node, trust, roots, store);

    c.bench_function("session_issue", |b| {
        b.iter(|| {
            let req = SessionRequest {
                subject_urn: user_urn.clone(),
                device_urn: None,
                requested_resources: vec!["api".into()],
                duration_secs: 300,
                mfa_verified: true,
                tls_binding: None,
            };
            let result = svc.issue_session(req).unwrap();
            std::hint::black_box(result);
        });
    });

    // Pre-issue once for the validate bench.
    let issued = svc
        .issue_session(SessionRequest {
            subject_urn: user_urn.clone(),
            device_urn: None,
            requested_resources: vec!["api".into()],
            duration_secs: 300,
            mfa_verified: true,
            tls_binding: None,
        })
        .unwrap();
    let cbor = issued.token_cbor;

    c.bench_function("session_validate", |b| {
        b.iter(|| {
            let token = Token::from_cbor(std::hint::black_box(&cbor)).unwrap();
            token.validate().unwrap();
            let doc = SessionDocument::extract(&token.payload).unwrap().unwrap();
            std::hint::black_box(doc);
        });
    });
}

criterion_group!(benches, bench_session_issue_and_validate);
criterion_main!(benches);
