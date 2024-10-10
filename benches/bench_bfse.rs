use ark_vesta::VestaConfig as Config;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rand::thread_rng;

use fde::blind_fse::signer::BFDESigner;
use fde::blind_fse::verifier::BFDEVerifier;
use fde::schnorr_signature::key::{generate_key_pair, PublicKey, SecretKey};
use fde::schnorr_signature::signer::Signer;
use fde::schnorr_signature::verifier::Verifier;

fn benchmark_schnorr_signature(c: &mut Criterion) {
    let (sk, pk): (SecretKey<Config>, PublicKey<Config>) = generate_key_pair(&mut thread_rng());

    // Non-blind signer/verifier
    let signer = Signer::new(sk);
    let verifier = Verifier::new(pk);

    for message_len in vec![1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024] {
        let message = vec![[0u8, 1u8, 2u8, 3u8].to_vec(); message_len];

        // Blind signer/verifier
        let fde_signer = BFDESigner::new(&signer, message_len);
        let fde_verifier = BFDEVerifier::new(&verifier, message_len);

        // Benchmark fde_signer.second_round
        c.bench_with_input(
            BenchmarkId::new("bfse_signer", message_len),
            &message_len,
            |b, _| {
                let (signer_secret_randomness, m1) = fde_signer.first_round(&mut thread_rng());
                let (_, m2) = fde_verifier.first_round(&m1, &message, &mut thread_rng());
                b.iter(|| {
                    let (_, _) = fde_signer.first_round(&mut thread_rng());
                    fde_signer.second_round(&signer_secret_randomness, &m2, &mut thread_rng());
                });
            },
        );

        // Benchmark fde_verifier.second_round
        c.bench_with_input(
            BenchmarkId::new("bfse_verifier", message_len),
            &message_len,
            |b, _| {
                let (signer_secret_randomness, m1) = fde_signer.first_round(&mut thread_rng());
                let (_, m2) = fde_verifier.first_round(&m1, &message, &mut thread_rng());
                let m3 = fde_signer.second_round(&signer_secret_randomness, &m2, &mut thread_rng());
                b.iter(|| {
                    let (_, _) = fde_verifier.first_round(&m1, &message, &mut thread_rng());
                    fde_verifier.second_round(&m1, &m2, &m3);
                });
            },
        );
    }
}

fn custom_criterion_config() -> Criterion {
    Criterion::default().sample_size(25)
}

// Benchmark group setup
criterion_group! {
    name = bench_fde;
    config = custom_criterion_config();
    targets =  benchmark_schnorr_signature
}

criterion_main!(bench_fde);
