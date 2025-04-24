use ark_ec::CurveGroup;
use ark_ff::Field;

use crate::poseidon_hash::sponge::PoseidonSponge;

pub trait Transcript<F: Field, G: CurveGroup> {
    fn absorb_point(&mut self, point: G);
    fn absorb_scalar(&mut self, scalar: F);
    fn squeeze_challenge(&mut self) -> F;
}

pub struct PoseidonTranscript<F: Field> {
    sponge: PoseidonSponge<F>,
}

impl<F: Field> PoseidonTranscript<F> {
    pub fn new() -> Self {
        PoseidonTranscript {
            sponge: PoseidonSponge::new(),
        }
    }
}

impl<F: Field, G: CurveGroup> Transcript<F, G> for PoseidonTranscript<F> {
    fn absorb_point(&mut self, point: G) {
        let mut compressed_bytes = Vec::new();
        point.serialize_compressed(&mut compressed_bytes).unwrap();
        let scalar = F::from_random_bytes(&compressed_bytes).unwrap();
        self.sponge.update(&[scalar]);
    }

    fn absorb_scalar(&mut self, scalar: F) {
        self.sponge.update(&[scalar]);
    }

    fn squeeze_challenge(&mut self) -> F {
        PoseidonSponge::squeeze(&mut self.sponge)
    }
}
