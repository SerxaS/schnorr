use crate::curve::generator;
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_std::UniformRand;
use rand::thread_rng;

#[derive(Debug)]
pub struct Keypair<F: Field, G: CurveGroup> {
    private_key: F,
    public_key: G,
}

impl<F: Field, G: CurveGroup<ScalarField = F>> Keypair<F, G> {
    pub fn generate() -> Self {
        let mut rng = thread_rng();
        let private_key = F::rand(&mut rng);
        let public_key = generator::<G>() * private_key;

        Keypair {
            private_key,
            public_key,
        }
    }
}
