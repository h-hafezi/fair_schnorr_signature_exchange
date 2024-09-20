#[cfg(test)]
mod tests {
    use rand::thread_rng;
    use crate::blind_schnorr_signature::signer::BSSigner;
    use crate::blind_schnorr_signature::verifier::BSVerifier;
    use crate::constant_for_curves::{E};
    use crate::schnorr_signature::key::{generate_key_pair, PublicKey, SecretKey};
    use crate::schnorr_signature::signer::{Signer};
    use crate::schnorr_signature::verifier::{Verifier};

    #[test]
    fn test_schnorr_signature() {
        let message = [0u8, 1u8, 2u8, 3u8];
        let (sk, pk): (SecretKey<E>, PublicKey<E>) = generate_key_pair(&mut thread_rng());

        // non-blind signer/verifier
        let signer = Signer::new(sk);
        let verifier = Verifier::new(pk);

        // blind signer/verifier
        let bs_signer = BSSigner::new(&signer);
        let bs_verifier = BSVerifier::new(&verifier);

        // interaction
        let (signer_secret_randomness, m1) = bs_signer.first_round(&mut thread_rng());
        let (verifier_secret_randomness, m2) = bs_verifier.first_round(&m1, message.to_vec(), &mut thread_rng());
        let m3 = bs_signer.second_round(&signer_secret_randomness, &m2);
        let signature = bs_verifier.second_round(&verifier_secret_randomness, &m1, &m2, &m3);

        assert!(verifier.verify(&message.to_vec(), signature));
    }
}
