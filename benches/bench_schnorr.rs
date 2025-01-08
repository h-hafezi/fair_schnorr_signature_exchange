use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use fde::schnorr_signature::key::{generate_key_pair, PublicKey, SecretKey};
use fde::schnorr_signature::signer::Signer;
use fde::schnorr_signature::verifier::Verifier;
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;

use ark_vesta::VestaConfig as Config;
// use ark_bls12_381::g1::Config;
use rand::thread_rng;

fn benchmark_sign_and_verify_iterations(c: &mut Criterion) {
    let message = vec![0u8, 1u8, 2u8, 3u8];

    for message_len in [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024] {
        let (sk, pk): (SecretKey<Config>, PublicKey<Config>) = generate_key_pair(&mut thread_rng());
        let signer = Signer::new(sk);
        let verifier = Verifier::new(pk);

        // Benchmark multiple signing iterations
        c.bench_with_input(
            BenchmarkId::new("schnorr_sign_iterations", message_len),
            &message_len,
            |b, &len| {
                b.iter(|| {
                    (0..len).into_par_iter().for_each(|_| {
                        let _ = signer.sign(&message, &mut thread_rng());
                    });
                });
            },
        );

        let sig = signer.sign(&message, &mut thread_rng());

        // Benchmark multiple verification iterations
        c.bench_with_input(
            BenchmarkId::new("schnorr_verify_iterations", message_len),
            &message_len,
            |b, &len| {
                b.iter(|| {
                    (0..len).into_par_iter().for_each(|_| {
                        let _ = verifier.verify(&message, &sig);
                    });
                });
            },
        );
    }
}

// Criterion group and main function
criterion_group!(benches, benchmark_sign_and_verify_iterations);
criterion_main!(benches);
