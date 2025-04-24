#![allow(non_snake_case)]

use ark_ec::CurveGroup;
use ark_ff::Field;
use rand::thread_rng;

use crate::{curve::generator, keypair::Keypair, transcript::Transcript};

pub struct Signature<F: Field, G: CurveGroup> {
    pub R: G,
    pub s: F,
}
impl<F: Field, G: CurveGroup<ScalarField = F>> Signature<F, G> {
    pub fn sign(
        keypair: &Keypair<F, G>,
        transcript: &mut impl Transcript<F, G>,
        message: F,
    ) -> Self {
        let mut rng = thread_rng();
        let r = F::rand(&mut rng);
        let R = generator::<G>() * r;

        transcript.absorb_point(R);
        transcript.absorb_point(keypair.public_key);
        transcript.absorb_scalar(message);

        let challenge = transcript.squeeze_challenge();
        let s = r + challenge * keypair.private_key;

        Signature { R, s }
    }

    pub fn verify(
        &self,
        public_key: G,
        transcript: &mut impl Transcript<F, G>,
        message: F,
    ) -> bool {
        transcript.absorb_point(self.R);
        transcript.absorb_point(public_key);
        transcript.absorb_scalar(message);

        let challenge = transcript.squeeze_challenge();
        let lhs = generator::<G>() * self.s;
        let rhs = (public_key * challenge) + self.R;

        lhs == rhs
    }
}
