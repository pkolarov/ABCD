//! Criterion benchmark for end-to-end policy evaluation.
//!
//! Builds a trust graph with one root → one user vouch and a small
//! policy ruleset, then measures `PolicyEngine::evaluate`. Targets the
//! §10 KPI of <= 1 ms local auth decision.

use std::collections::BTreeSet;

use criterion::{Criterion, criterion_group, criterion_main};
use dds_core::identity::Identity;
use dds_core::policy::{Effect, PolicyEngine, PolicyRule};
use dds_core::token::{Token, TokenKind, TokenPayload};
use dds_core::trust::TrustGraph;
use rand::rngs::OsRng;

fn build_fixture() -> (PolicyEngine, TrustGraph, BTreeSet<String>, String) {
    let root = Identity::generate("root", &mut OsRng);
    let user = Identity::generate("user", &mut OsRng);

    let user_attest = Token::sign(
        TokenPayload {
            iss: user.id.to_urn(),
            iss_key: user.public_key.clone(),
            jti: "attest-user".into(),
            sub: user.id.to_urn(),
            kind: TokenKind::Attest,
            purpose: None,
            vch_iss: None,
            vch_sum: None,
            revokes: None,
            iat: 0,
            exp: Some(u64::MAX / 2),
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
            jti: "vouch-user".into(),
            sub: user.id.to_urn(),
            kind: TokenKind::Vouch,
            purpose: Some("dds:group:devs".into()),
            vch_iss: Some(user.id.to_urn()),
            vch_sum: Some(user_attest.payload_hash()),
            revokes: None,
            iat: 0,
            exp: Some(u64::MAX / 2),
            body_type: None,
            body_cbor: None,
        },
        &root.signing_key,
    )
    .unwrap();

    let mut graph = TrustGraph::new();
    graph.add_token(user_attest).unwrap();
    graph.add_token(vouch).unwrap();

    let mut roots = BTreeSet::new();
    roots.insert(root.id.to_urn());

    let mut engine = PolicyEngine::new();
    engine.add_rule(PolicyRule {
        effect: Effect::Allow,
        required_purpose: "dds:group:devs".into(),
        resource: "build-server".into(),
        actions: vec!["read".into(), "deploy".into()],
    });

    (engine, graph, roots, user.id.to_urn())
}

fn bench_policy_eval(c: &mut Criterion) {
    let (engine, graph, roots, subject) = build_fixture();
    c.bench_function("policy_evaluate_allow", |b| {
        b.iter(|| {
            std::hint::black_box(engine.evaluate(
                std::hint::black_box(&subject),
                "build-server",
                "deploy",
                &graph,
                &roots,
            ));
        });
    });
}

criterion_group!(benches, bench_policy_eval);
criterion_main!(benches);
