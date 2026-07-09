//! Host-side crypto micro-benchmarks (CLSAG, balance, range proofs).
//!
//! ```text
//! cargo bench -p ringct-crypto --bench crypto
//! ```
//!
//! Results inform `pallet_ringct::weights` engineering estimates until
//! full `frame-benchmarking` numbers replace them.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use ringct_crypto::{clsag, native as crypto};

fn make_ring(n: usize, real: usize, amount: u64, blinding: &[u8; 32]) -> (Vec<u8>, [u8; 32]) {
	let mut blob = Vec::with_capacity(n * 64);
	let mut secret = [0u8; 32];
	for i in 0..n {
		let (sk, pk) = crypto::random_secret_key();
		blob.extend_from_slice(&pk);
		if i == real {
			secret = sk;
			blob.extend_from_slice(&crypto::commit(amount, blinding).unwrap());
		} else {
			blob.extend_from_slice(
				&crypto::commit(i as u64 * 99 + 1, &crypto::random_blinding()).unwrap(),
			);
		}
	}
	(blob, secret)
}

fn bench_clsag_verify(c: &mut Criterion) {
	let mut group = c.benchmark_group("clsag_verify");
	let msg = [7u8; 32];
	for n in [4usize, 8, 16] {
		let blinding = crypto::random_blinding();
		let (ring, secret) = make_ring(n, 0, 1_000, &blinding);
		let res = clsag::sign(&msg, &ring, 0, &secret, &blinding, &crypto::random_blinding())
			.expect("sign");
		group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
			b.iter(|| {
				assert!(clsag::verify(
					black_box(&msg),
					black_box(&ring),
					black_box(&res.pseudo_commitment),
					black_box(&res.key_image),
					black_box(&res.signature),
				));
			});
		});
	}
	group.finish();
}

fn bench_clsag_sign(c: &mut Criterion) {
	let mut group = c.benchmark_group("clsag_sign");
	let msg = [3u8; 32];
	for n in [4usize, 8, 16] {
		let blinding = crypto::random_blinding();
		let (ring, secret) = make_ring(n, n / 2, 42_000, &blinding);
		let real = n / 2;
		group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
			b.iter(|| {
				clsag::sign(
					black_box(&msg),
					black_box(&ring),
					black_box(real),
					black_box(&secret),
					black_box(&blinding),
					black_box(&crypto::random_blinding()),
				)
				.expect("sign");
			});
		});
	}
	group.finish();
}

fn bench_balance(c: &mut Criterion) {
	let b1 = crypto::random_blinding();
	let b2 = crypto::balancing_blinding(&[], &[b1]).unwrap();
	let input = crypto::value_commitment(100);
	let o1 = crypto::commit(60, &b1).unwrap();
	let o2 = crypto::commit(30, &b2).unwrap();
	let outs = [o1, o2].concat();
	c.bench_function("verify_balance_2out", |b| {
		b.iter(|| {
			assert!(crypto::verify_balance(black_box(&input), black_box(&outs), black_box(10)));
		});
	});
}

fn bench_range_proof(c: &mut Criterion) {
	let mut group = c.benchmark_group("range_proof_verify");
	for n in [1usize, 2, 4, 8] {
		let blindings: Vec<[u8; 32]> = (0..n).map(|_| crypto::random_blinding()).collect();
		let values: Vec<u64> = (0..n as u64).map(|i| 1_000 * (i + 1)).collect();
		let (proof, commits) = crypto::prove_range(&values, &blindings).unwrap();
		let commit_blob = commits.concat();
		group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
			b.iter(|| {
				assert!(crypto::verify_range_proof(
					black_box(&proof),
					black_box(&commit_blob)
				));
			});
		});
	}
	group.finish();
}

criterion_group!(
	benches,
	bench_clsag_verify,
	bench_clsag_sign,
	bench_balance,
	bench_range_proof
);
criterion_main!(benches);
