//! Criterion benchmarks for delta-sync protocol operations.
//!
//! Covers:
//! - State negotiation: compute_missing_ops at 100 and 1K op scale
//! - DAG merge: CausalDag::merge at 100 and 1K op scale
//!
//! Targets the §10 bootstrap KPI: ≤ 30 s for 10K-entry directory over 10 Mbps.

use std::collections::BTreeSet;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use dds_core::crdt::causal_dag::{CausalDag, Operation};
use dds_net::sync::compute_missing_ops;

fn make_linear_dag(size: usize) -> CausalDag {
    let mut dag = CausalDag::new();
    dag.insert(Operation {
        id: "op-0".to_string(),
        author: "urn:vouchsafe:bench.hash".to_string(),
        deps: vec![],
        data: vec![0u8; 32],
        timestamp: 0,
    })
    .unwrap();

    let mut prev = "op-0".to_string();
    for i in 1..size {
        let id = format!("op-{i}");
        dag.insert(Operation {
            id: id.clone(),
            author: "urn:vouchsafe:bench.hash".to_string(),
            deps: vec![prev.clone()],
            data: vec![(i & 0xff) as u8; 32],
            timestamp: i as u64,
        })
        .unwrap();
        prev = id;
    }
    dag
}

fn bench_compute_missing_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("sync_negotiate");

    for size in [100usize, 1_000] {
        let remote_ids = make_linear_dag(size).operation_ids();
        let local_ids: BTreeSet<String> = BTreeSet::new();

        group.bench_with_input(BenchmarkId::new("compute_missing", size), &size, |b, _| {
            b.iter(|| {
                std::hint::black_box(compute_missing_ops(
                    std::hint::black_box(&local_ids),
                    std::hint::black_box(&remote_ids),
                ));
            });
        });
    }

    group.finish();
}

fn bench_dag_merge(c: &mut Criterion) {
    let mut group = c.benchmark_group("sync_merge");

    for size in [100usize, 1_000] {
        let remote_dag = make_linear_dag(size);

        group.bench_with_input(BenchmarkId::new("dag_merge", size), &size, |b, _| {
            b.iter_batched(
                || (CausalDag::new(), remote_dag.clone()),
                |(mut local, remote)| {
                    std::hint::black_box(local.merge(&remote).unwrap());
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench_compute_missing_ops, bench_dag_merge);
criterion_main!(benches);
