#[cfg(test)]
mod tests {
    use rand::thread_rng;

    use crate::fde::signer::FDESigner;
    use crate::fde::verifier::FDEVerifier;
    use crate::schnorr_signature::key::{generate_key_pair, PublicKey, SecretKey};
    use crate::schnorr_signature::signer::Signer;
    use crate::schnorr_signature::verifier::Verifier;
    use ark_bn254::g1::Config;

    #[test]
    fn test_schnorr_signature() {
        let message = {
            let mut temp = Vec::new();
            temp.push([0u8, 1u8, 2u8, 3u8].to_vec());
            temp.push([0u8, 1u8, 2u8, 3u8].to_vec());
            temp
        };
        let (sk, pk): (SecretKey<Config>, PublicKey<Config>) = generate_key_pair(&mut thread_rng());

        // non-blind signer/verifier
        let signer = Signer::new(sk);
        let verifier = Verifier::new(pk);

        // blind signer/verifier
        let fde_signer = FDESigner::new(&signer, 2);
        let fde_verifier = FDEVerifier::new(&verifier, 2);

        // interaction
        let (signer_secret_randomness, m1) = fde_signer.first_round(&mut thread_rng());
        let (_, m2) = fde_verifier.first_round(&m1, &message, &mut thread_rng());
        let m3 = fde_signer.second_round(&signer_secret_randomness, &m2, &mut thread_rng());

        assert!(fde_verifier.second_round(&m1, &m2, &m3));
    }
}
