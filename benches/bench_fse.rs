// use ark_vesta::VestaConfig as Config;
use ark_bls12_381::g1::Config;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rand::thread_rng;

use fde::fse::protocol::FSE;
use fde::schnorr_signature::key::{PublicKey, SecretKey};

fn benchmark_schnorr_signature(c: &mut Criterion) {
    let (sk, pk): (SecretKey<Config>, PublicKey<Config>) = FSE::gen_key(&mut thread_rng());

    for message_len in vec![1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024] {
        let message = vec![[0u8, 1u8, 2u8, 3u8].to_vec(); message_len];

        // Benchmark fde_signer.second_round
        c.bench_with_input(
            BenchmarkId::new("fse_signer", message_len),
            &message_len,
            |b, _| {
                b.iter(|| {
                    let _ = FSE::sign(&sk, &message, &mut thread_rng());
                });
            },
        );

        // Benchmark fde_verifier.second_round
        c.bench_with_input(
            BenchmarkId::new("fse_verifier", message_len),
            &message_len,
            |b, _| {
                let  (vec_alpha, r_g, g_k, k) = FSE::sign(&sk, &message, &mut thread_rng());
                b.iter(|| {
                    FSE::verify(&pk, &message, &vec_alpha, &r_g, &g_k);
                    let signatures = FSE::recover(&vec_alpha, &r_g, k);
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
