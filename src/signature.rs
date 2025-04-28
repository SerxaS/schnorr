//! Basic Schnorr signature scheme using a Poseidon-based Fiat–Shamir transcript.
//!
//! Implements:
//! - `Signature::sign`: Sign a message with a keypair
//! - `Signature::verify`: Verify a signature against a message and public key
//!
//! Based on classical Schnorr signatures (Claus Schnorr, Crypto '89),
//! adapted for ZK-friendly applications with Poseidon hashing over Arkworks.

#![allow(non_snake_case)]

use ark_ec::CurveGroup;
use ark_ff::Field;
use rand::rngs::OsRng;

use crate::{keypair::Keypair, transcript::Transcript};

/// A Schnorr signature consisting of a nonce commitment `R` and a response `s`.
#[derive(Debug, Clone)]
pub struct Signature<F: Field, G: CurveGroup> {
    pub R: G,
    pub s: F,
}
impl<F: Field, G: CurveGroup<ScalarField = F>> Signature<F, G> {
    /// Signs a message using the given keypair and Poseidon transcript.
    pub fn sign(
        keypair: &Keypair<F, G>,
        transcript: &mut impl Transcript<F, G>,
        message: F,
    ) -> Self {
        let mut rng = OsRng;
        let r = F::rand(&mut rng);
        let R = G::generator() * r;

        transcript.absorb_point(R);
        transcript.absorb_point(keypair.public_key);
        transcript.absorb_scalar(message);
        let challenge = transcript.squeeze_challenge();

        let s = r + challenge * keypair.private_key;

        Signature { R, s }
    }

    /// Verifies the signature against a message and public key.
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
        let lhs = G::generator() * self.s;
        let rhs = (public_key * challenge) + self.R;

        lhs == rhs
    }
}
