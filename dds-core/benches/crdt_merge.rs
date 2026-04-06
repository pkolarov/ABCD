//! Criterion benchmarks for CRDT merge primitives.
//!
//! - `causal_dag::insert` (the hot path for ingesting a new operation)
//! - `lww_register::merge` (per-attribute conflict resolution)
//!
//! Targets the §10 KPI of <= 0.05 ms p99 per merge.

use criterion::{Criterion, criterion_group, criterion_main};
use dds_core::crdt::causal_dag::{CausalDag, Operation};
use dds_core::crdt::lww_register::LwwRegister;

fn make_op(id: &str, deps: Vec<String>) -> Operation {
    Operation {
        id: id.to_string(),
        author: "urn:vouchsafe:bench.hash".to_string(),
        deps,
        data: vec![0u8; 32],
        timestamp: 0,
    }
}

fn bench_causal_dag_insert(c: &mut Criterion) {
    c.bench_function("causal_dag_insert_linear_chain", |b| {
        b.iter_batched(
            || {
                let mut dag = CausalDag::new();
                dag.insert(make_op("root", vec![])).unwrap();
                dag
            },
            |mut dag| {
                let mut prev = "root".to_string();
                for i in 0..100 {
                    let id = format!("op-{i}");
                    dag.insert(make_op(&id, vec![prev.clone()])).unwrap();
                    prev = id;
                }
                std::hint::black_box(dag);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    c.bench_function("causal_dag_insert_single", |b| {
        let mut dag = CausalDag::new();
        dag.insert(make_op("root", vec![])).unwrap();
        let mut counter = 0u64;
        b.iter(|| {
            counter += 1;
            let id = format!("op-{counter}");
            let _ = dag.insert(make_op(&id, vec!["root".to_string()]));
        });
    });
}

fn bench_lww_register_merge(c: &mut Criterion) {
    c.bench_function("lww_register_merge", |b| {
        let mut a: LwwRegister<String> = LwwRegister::new("alpha".to_string(), 1);
        let mut tick: u64 = 2;
        b.iter(|| {
            let other = LwwRegister::new(format!("v{tick}"), tick);
            tick += 1;
            std::hint::black_box(a.merge(&other));
        });
    });
}

criterion_group!(benches, bench_causal_dag_insert, bench_lww_register_merge);
criterion_main!(benches);
