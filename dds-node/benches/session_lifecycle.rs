//! Criterion benchmark for SessionDocument issue + validate.
//!
//! Measures the round trip:
//!   1. `LocalService::issue_session` (sign + embed SessionDocument)
//!   2. `Token::from_cbor` + `Token::validate` (verify on the consuming side)
//!   3. `SessionDocument::extract` (decode body)
//!
//! Targets the §10 KPI of <= 1 ms local auth decision.

use std::collections::BTreeSet;

use criterion::{Criterion, criterion_group, criterion_main};
use dds_core::identity::Identity;
use dds_core::token::Token;
use dds_core::trust::TrustGraph;
use dds_domain::{DomainDocument, SessionDocument};
use dds_node::service::{LocalService, SessionRequest};
use dds_store::MemoryBackend;
use rand::rngs::OsRng;

fn bench_session_issue_and_validate(c: &mut Criterion) {
    let node = Identity::generate("bench-node", &mut OsRng);
    let user = Identity::generate("bench-user", &mut OsRng);
    let user_urn = user.id.to_urn();
    let trust = TrustGraph::new();
    let roots: BTreeSet<String> = BTreeSet::new();
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
