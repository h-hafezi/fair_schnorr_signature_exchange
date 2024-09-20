#[cfg(test)]
mod tests {
    use rand::thread_rng;

    use crate::constant_for_curves::{E};
    use crate::schnorr_signature::key::{generate_key_pair, PublicKey, SecretKey};
    use crate::schnorr_signature::signer::{Signer};
    use crate::schnorr_signature::verifier::{Verifier};

    #[test]
    fn test_schnorr_signature() {
        let message = [0u8, 1u8, 2u8, 3u8];
        let (sk, pk): (SecretKey<E>, PublicKey<E>) = generate_key_pair(&mut thread_rng());
        let signer = Signer::new(sk);
        let verifier = Verifier::new(pk);
        let sig = signer.sign(&message.to_vec(), &mut thread_rng());
        assert!(verifier.verify(&message.to_vec(), sig));
    }
}
