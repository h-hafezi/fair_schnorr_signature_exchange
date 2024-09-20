use std::ops::Mul;
use ark_ec::Group;
use ark_ec::pairing::Pairing;
use ark_std::UniformRand;
use rand::Rng;

// Commitment scheme structure with group generators g and h
pub struct CommitmentScheme<E: Pairing> {
    pub g: E::G1,
    pub h: E::G1,
}

// Opening structure, which holds the message m and randomness r
pub struct Opening<E: Pairing> {
    pub m: E::ScalarField,
    pub r: E::ScalarField,
}

pub struct Commitment<E: Pairing> {
    pub com: E::G1,
}

impl<E: Pairing> Opening<E> {
    // Function to generate a new opening given a message `m`
    pub fn new<R: Rng>(m: E::ScalarField, rng: &mut R) -> Self {
        // Randomly generate r
        let r = E::ScalarField::rand(rng);
        Opening { m, r }
    }
}

impl<E: Pairing> CommitmentScheme<E> {
    /// generate the generators
    pub fn new<R: Rng>(rng: &mut R) -> CommitmentScheme<E> {
        CommitmentScheme {
            g: E::G1::generator(),
            h: E::G1::rand(rng),
        }
    }

    /// Function to commit to a message `m`, generating an opening and a commitment
    pub fn commit<R: Rng>(
        &self,
        m: E::ScalarField,
        rng: &mut R,
    ) -> (Opening<E>, Commitment<E>) {
        // Generate the opening (m, r)
        let opening = Opening::new(m, rng);

        // Compute the commitment as g^m * h^r
        let com = self.g.mul(m) + self.h.mul(opening.r);

        // Return the opening and the commitment
        (opening, Commitment { com })
    }

    /// Function to verify that the commitment matches the opening
    pub fn verify(
        &self,
        opening: &Opening<E>,
        com: Commitment<E>,
    ) -> bool {
        // Compute g^m * h^r using the opening
        let expected_commitment = self.g.mul(opening.m) + self.h.mul(opening.r);

        // Check if the computed commitment matches the provided one
        expected_commitment == com.com
    }
}

#[cfg(test)]
mod tests {
    use ark_std::UniformRand;
    use rand::thread_rng;
    use crate::commitment::CommitmentScheme;
    use crate::constant_for_curves::{E, ScalarField};

    type F = ScalarField;

    #[test]
    fn test_commitment() {
        let m = F::rand(&mut thread_rng());
        let commitment_scheme: CommitmentScheme<E> = CommitmentScheme::new(&mut thread_rng());
        let (opening, com) = commitment_scheme.commit(m, &mut thread_rng());
        assert!(commitment_scheme.verify(&opening, com))
    }
}