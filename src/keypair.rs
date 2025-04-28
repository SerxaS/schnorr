use ark_ec::CurveGroup;
use ark_ff::Field;
use rand::rngs::OsRng;

/// A Schnorr keypair with a private scalar and public curve point.
#[derive(Debug, Clone)]
pub struct Keypair<F: Field, G: CurveGroup> {
    pub private_key: F,
    pub public_key: G,
}

impl<F: Field, G: CurveGroup<ScalarField = F>> Keypair<F, G> {
    /// Generates a random keypair.
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let private_key = F::rand(&mut rng);
        let public_key = G::generator() * private_key;

        Keypair {
            private_key,
            public_key,
        }
    }
}
