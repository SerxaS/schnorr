#![allow(non_snake_case)]

use ark_ec::CurveGroup;
use ark_ff::Field;
use rand::random;

use crate::{keypair::Keypair, signature::Signature, transcript::Transcript};

#[derive(Debug, Clone)]
pub struct MuSig<F: Field, G: CurveGroup> {
    R: G,
    s: F,
}

impl<F: Field, G: CurveGroup<ScalarField = F>> MuSig<F, G> {
    pub fn compute_keyset_challenge(pub_keys: &[G], transcript: &mut impl Transcript<F, G>) -> F {
        for pub_key in pub_keys {
            transcript.absorb_point(*pub_key);
        }
        transcript.squeeze_challenge()
    }

    pub fn compute_agg_pub_key(
        pub_keys: &[G],
        keyset_challenge: F,
        transcript: &mut impl Transcript<F, G>,
    ) -> G {
        let mut agg_pub_key = G::zero();

        for pub_key in pub_keys {
            transcript.absorb_scalar(keyset_challenge);
            transcript.absorb_point(*pub_key);
            let challenge = transcript.squeeze_challenge();

            agg_pub_key += (*pub_key) * challenge;
        }

        agg_pub_key
    }

    pub fn sign(
        keypair: Keypair<F, G>,
        message: F,
        transcript: &mut impl Transcript<F, G>,
        keyset_challenge: F,
    ) {
        let mut rng = rand::thread_rng();
        let r = F::rand(&mut rng);
        let R = G::generator() * r;

        transcript.absorb_point(keypair.public_key);
        transcript.absorb_point(R);
        transcript.absorb_scalar(message);

        let challenge = transcript.squeeze_challenge();

        //let s = r + (challenge * )
    }

    pub fn combine(signatures: &[Signature<F, G>], pub_keys: &[G]) -> (G, F) {
        assert_eq!(signatures.len(), pub_keys.len());

        let agg_R = signatures
            .iter()
            .map(|sig| sig.R)
            .reduce(|a, b| a + b)
            .unwrap();

        let agg_s = signatures
            .iter()
            .map(|sig| sig.s)
            .reduce(|a, b| a + b)
            .unwrap();

        (agg_R, agg_s)
    }

    pub fn verify(&self, message: F, transcript: &mut impl Transcript<F, G>) {}
}
