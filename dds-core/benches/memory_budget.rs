//! Memory-budget validation for in-memory DAG structures.
//!
//! Estimates heap usage of `CausalDag` at 1K and 10K entries and asserts
//! the §10 KPIs:
//!   - 1K-entry directory: ≤ 5 MB heap
//!   - 10K-entry directory: ≤ 50 MB heap
//!
//! Estimation sums owned heap bytes (String contents, Vec payloads) plus
//! conservative BTreeMap node overhead (~48 bytes/entry). This is a
//! lower-bound estimate; the assertion margin keeps it safe.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use dds_core::crdt::causal_dag::{CausalDag, Operation};

// Conservative BTreeMap node overhead per entry (ptr + metadata bookkeeping).
const BTREE_OVERHEAD_PER_ENTRY: usize = 48;

fn make_linear_dag(size: usize) -> CausalDag {
    let mut dag = CausalDag::new();
    dag.insert(Operation {
        id: "op-0".to_string(),
        author: "urn:vouchsafe:bench.hash".to_string(),
        deps: vec![],
        data: vec![0u8; 64],
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
            data: vec![(i & 0xff) as u8; 64],
            timestamp: i as u64,
        })
        .unwrap();
        prev = id;
    }
    dag
}

/// Estimate heap bytes owned by `dag`.
///
/// Counts String content, Vec payloads, Vec/String struct inline sizes,
/// and BTreeMap node overhead. Does not account for allocator alignment
/// padding — actual usage may be slightly higher.
fn estimate_heap_bytes(dag: &CausalDag) -> usize {
    let ids = dag.operation_ids();
    let mut total = 0usize;
    for id in &ids {
        let Some(op) = dag.get(id) else { continue };

        // Heap-allocated string content
        total += op.id.len();
        total += op.author.len();
        total += op.data.len();
        for dep in &op.deps {
            total += dep.len();
            total += size_of::<String>(); // String struct (ptr/len/cap)
        }

        // Vec/String struct inline sizes (stored inside the BTreeMap node)
        total += size_of::<String>(); // id
        total += size_of::<String>(); // author
        total += size_of::<Vec<String>>(); // deps Vec header
        total += size_of::<Vec<u8>>(); // data Vec header

        // BTreeMap node bookkeeping per entry
        total += BTREE_OVERHEAD_PER_ENTRY;
    }
    // BTreeSet<String> for heads — bounded by fan-out; for linear chain = 1
    total += dag.heads().len() * (size_of::<String>() + BTREE_OVERHEAD_PER_ENTRY);
    total
}

fn assert_memory_budget(size: usize, limit_bytes: usize) {
    let dag = make_linear_dag(size);
    let estimated = estimate_heap_bytes(&dag);
    assert!(
        estimated <= limit_bytes,
        "DAG({size} entries): estimated {estimated} bytes exceeds §10 budget of {limit_bytes} bytes"
    );
}

fn bench_dag_construction(c: &mut Criterion) {
    // Validate memory bounds once (outside the hot loop — construction is the
    // expensive part, and dhat-style per-alloc tracking would require a custom
    // global allocator).
    assert_memory_budget(1_000, 5 * 1024 * 1024);
    assert_memory_budget(10_000, 50 * 1024 * 1024);

    let mut group = c.benchmark_group("memory_budget");

    for size in [100usize, 1_000, 10_000] {
        group.bench_with_input(BenchmarkId::new("dag_build", size), &size, |b, &n| {
            b.iter(|| std::hint::black_box(make_linear_dag(n)));
        });
    }

    group.finish();
}

criterion_group!(benches, bench_dag_construction);
criterion_main!(benches);
