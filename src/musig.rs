//! MuSig multi-signature scheme using Poseidon transcript for Fiat–Shamir.
//!
//! Inspired by:
//! - MuSig (Blockstream Research): https://eprint.iacr.org/2018/068.pdf
//! - Schnorr signatures over Arkworks with ZK-friendly Poseidon hashing
//!
//! This module implements:
//! - Keyset hashing for binding public keys
//! - Public key aggregation
//! - Nonce generation
//! - Signature aggregation and verification

#![allow(non_snake_case)]

use ark_ec::CurveGroup;
use ark_ff::Field;

use crate::{
    keypair::Keypair,
    transcript::{Transcript, poseidon_transcript},
};

/// A MuSig aggregated signature consisting of the aggregated nonce and signature scalar.
#[derive(Debug, Clone)]
pub struct MuSig<F: Field, G: CurveGroup> {
    pub agg_R: G,
    pub agg_s: F,
}

impl<F: Field, G: CurveGroup<ScalarField = F>> MuSig<F, G> {
    /// Computes the keyset challenge from all public keys.
    pub fn keyset_challenge(pub_keys: &[G]) -> F {
        let mut keyset_transcript = poseidon_transcript();

        for pub_key in pub_keys {
            keyset_transcript.absorb_point(*pub_key);
        }
        keyset_transcript.squeeze_challenge()
    }

    /// Aggregates public keys weighted by their keyset challenges.
    pub fn agg_pub_keys(pub_keys: &[G], keyset_challenge: F) -> G {
        let mut agg_pub_key = G::zero();

        for pub_key in pub_keys {
            let mut coeff_transcript = poseidon_transcript();
            coeff_transcript.absorb_scalar(keyset_challenge);
            coeff_transcript.absorb_point(*pub_key);
            let challenge = coeff_transcript.squeeze_challenge();

            agg_pub_key += (*pub_key) * challenge;
        }

        agg_pub_key
    }

    /// Creates a random nonce and its public commitment.
    pub fn create_nonce() -> (F, G) {
        let mut rng = rand::thread_rng();
        let r = F::rand(&mut rng);
        let R = G::generator() * r;

        (r, R)
    }

    /// Signs a message using the keypair and nonces.
    pub fn sign(
        keypair: Keypair<F, G>,
        message: F,
        keyset_challenge: F,
        agg_pub_key: G,
        agg_R: G,
        r: F,
    ) -> F {
        let mut transcript = poseidon_transcript();
        transcript.absorb_point(agg_pub_key);
        transcript.absorb_point(agg_R);
        transcript.absorb_scalar(message);
        let challenge = transcript.squeeze_challenge();

        let mut coeff_transcript = poseidon_transcript();
        coeff_transcript.absorb_scalar(keyset_challenge);
        coeff_transcript.absorb_point(keypair.public_key);
        let coeff_challenge = coeff_transcript.squeeze_challenge();

        let s = r + (challenge * coeff_challenge * keypair.private_key);

        s
    }

    /// Verifies an aggregated MuSig signature.
    pub fn verify(
        &self,
        message: F,
        transcript: &mut impl Transcript<F, G>,
        agg_pub_key: G,
        agg_R: G,
        agg_s: F,
    ) -> bool {
        transcript.absorb_point(agg_pub_key);
        transcript.absorb_point(agg_R);
        transcript.absorb_scalar(message);

        let challenge = transcript.squeeze_challenge();
        let rhs = agg_R + (agg_pub_key * challenge);
        let lhs = G::generator() * agg_s;

        lhs == rhs
    }
}
