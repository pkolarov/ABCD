//! Criterion benchmarks for signature verification.
//!
//! Covers:
//! - Ed25519 verify (classical)
//! - Hybrid Ed25519 + ML-DSA-65 verify
//!
//! Targets the §10 KPI of >= 50K Ed25519 verifies/sec.

use criterion::{Criterion, criterion_group, criterion_main};
use dds_core::crypto::classical::{Ed25519Only, verify_ed25519};
use rand::rngs::OsRng;

#[cfg(feature = "pq")]
use dds_core::crypto::hybrid::{HybridEdMldsa, verify_hybrid};

fn bench_ed25519_verify(c: &mut Criterion) {
    let key = Ed25519Only::generate(&mut OsRng);
    let pk = key.public_key_bundle();
    let msg = b"the quick brown fox jumps over the lazy DDS node";
    let sig = key.sign(msg);

    c.bench_function("ed25519_verify", |b| {
        b.iter(|| {
            verify_ed25519(
                std::hint::black_box(&pk.bytes),
                std::hint::black_box(msg),
                std::hint::black_box(&sig.bytes),
            )
            .unwrap();
        });
    });
}

#[cfg(feature = "pq")]
fn bench_hybrid_verify(c: &mut Criterion) {
    let key = HybridEdMldsa::generate(&mut OsRng);
    let pk = key.public_key_bundle();
    let msg = b"the quick brown fox jumps over the lazy DDS node";
    let sig = key.sign(msg);

    c.bench_function("hybrid_ed25519_mldsa65_verify", |b| {
        b.iter(|| {
            verify_hybrid(
                std::hint::black_box(&pk.bytes),
                std::hint::black_box(msg),
                std::hint::black_box(&sig.bytes),
            )
            .unwrap();
        });
    });
}

#[cfg(feature = "pq")]
criterion_group!(benches, bench_ed25519_verify, bench_hybrid_verify);
#[cfg(not(feature = "pq"))]
criterion_group!(benches, bench_ed25519_verify);
criterion_main!(benches);
