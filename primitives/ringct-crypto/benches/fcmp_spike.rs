//! FCMP PR-0 spike benchmarks.
//!
//! ```text
//! cargo bench -p ringct-crypto --features fcmp-spike --bench fcmp_spike
//! ```
//!
//! Results feed `docs/fcmp-pr0-memo.md`. No consensus wiring.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use ringct_crypto::fcmp_spike::{
    embedding::msm_proxy_ristretto, merkle::SparseMerkleTree, naive_fullset, sa_link,
};
use ringct_crypto::native as crypto;

fn fill_tree(n: usize, admit_every: usize) -> SparseMerkleTree {
    let mut t = SparseMerkleTree::new();
    for i in 0..n {
        t.grow_empty();
        if admit_every == 0 || i % admit_every == 0 {
            let (sk, pk) = crypto::random_secret_key();
            let c = crypto::commit((i as u64) + 1, &crypto::random_blinding()).unwrap();
            let _ = sk;
            assert!(t.admit(i as u64, &pk, &c));
        }
    }
    t
}

fn bench_merkle_grow(c: &mut Criterion) {
    let mut group = c.benchmark_group("fcmp_merkle_grow_empty");
    for n in [64usize, 1024, 4096] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| {
                let mut t = SparseMerkleTree::new();
                for _ in 0..n {
                    t.grow_empty();
                }
                black_box(t.root())
            });
        });
    }
    group.finish();
}

fn bench_merkle_admit(c: &mut Criterion) {
    let mut group = c.benchmark_group("fcmp_merkle_admit");
    for n in [64usize, 1024, 4096] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| {
                let mut t = SparseMerkleTree::new();
                let mut pcs = Vec::with_capacity(n);
                for i in 0..n {
                    t.grow_empty();
                    let (_, pk) = crypto::random_secret_key();
                    let c = crypto::commit((i as u64) + 1, &crypto::random_blinding()).unwrap();
                    pcs.push((pk, c));
                }
                for (i, (pk, cm)) in pcs.iter().enumerate() {
                    assert!(t.admit(i as u64, pk, cm));
                }
                black_box(t.root())
            });
        });
    }
    group.finish();
}

fn bench_merkle_root(c: &mut Criterion) {
    let mut group = c.benchmark_group("fcmp_merkle_root");
    for n in [64usize, 1024, 4096, 16384] {
        let t = fill_tree(n, 1);
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| black_box(t.root()));
        });
    }
    group.finish();
}

fn bench_transparent_path(c: &mut Criterion) {
    let mut group = c.benchmark_group("fcmp_transparent_path");
    for n in [64usize, 1024, 4096] {
        let t = fill_tree(n, 1);
        let idx = (n / 2) as u64;
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                let path = t.transparent_path(idx).unwrap();
                black_box(path.encoded_len());
                black_box(path.compute_root())
            });
        });
    }
    group.finish();
}

fn bench_sa_link_open(c: &mut Criterion) {
    let (sk, _) = crypto::random_secret_key();
    let in_b = crypto::random_blinding();
    let ps_b = crypto::random_blinding();
    let st = sa_link::make_open_statement(42_000, &sk, &in_b, &ps_b).unwrap();
    c.bench_function("fcmp_sa_link_open_check", |b| {
        b.iter(|| assert!(sa_link::open_reblind_ok(black_box(&st))));
    });
}

fn bench_msm_proxy(c: &mut Criterion) {
    let mut group = c.benchmark_group("fcmp_msm_proxy_ristretto");
    for n in [16usize, 64, 256, 1024] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| black_box(msm_proxy_ristretto(n)));
        });
    }
    group.finish();
}

fn bench_clsag_baseline(c: &mut Criterion) {
    // Single-shot wall timing printed via criterion for memo baselines.
    c.bench_function("fcmp_clsag_baseline_sign_verify_pair", |b| {
        b.iter(|| {
            let (sign_ms, verify_ms) = naive_fullset::measure_clsag_baseline(1);
            black_box((sign_ms, verify_ms))
        });
    });
}

criterion_group!(
    benches,
    bench_merkle_grow,
    bench_merkle_admit,
    bench_merkle_root,
    bench_transparent_path,
    bench_sa_link_open,
    bench_msm_proxy,
    bench_clsag_baseline,
);
criterion_main!(benches);
