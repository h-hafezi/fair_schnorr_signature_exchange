use ark_ec::pairing::Pairing;

/// Signature structure
pub struct Signature<E: Pairing> {
    /// R = g^r
    pub r_g: E::G1,

    /// s = r + H(R, m) * sk
    pub s: E::ScalarField,
}
