//! Poseidon-based Fiat–Shamir transcript for Schnorr and MuSig signatures.
//!
//! Provides:
//! - `Transcript` trait for absorbing points and scalars
//! - `PoseidonTranscript` as a concrete implementation using a Poseidon sponge
//! - Helper function `poseidon_transcript()` to create a boxed transcript
//!
//! Based on Fiat–Shamir transform adapted for ZK-friendly hash functions.

use ark_ec::CurveGroup;
use ark_ff::Field;

use crate::poseidon_hash::sponge::PoseidonSponge;

/// Fiat–Shamir transcript trait with point and scalar absorption.
pub trait Transcript<F: Field, G: CurveGroup> {
    fn absorb_point(&mut self, point: G);
    fn absorb_scalar(&mut self, scalar: F);
    fn squeeze_challenge(&mut self) -> F;
}

/// Poseidon-based implementation of the `Transcript` trait.
#[derive(Debug, Clone)]
pub struct PoseidonTranscript<F: Field> {
    sponge: PoseidonSponge<F>,
}

impl<F: Field> PoseidonTranscript<F> {
    /// Creates a new Poseidon-based transcript.
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
        let field_element = F::from_random_bytes(&compressed_bytes).unwrap();
        self.sponge.update(&[field_element]);
    }

    fn absorb_scalar(&mut self, scalar: F) {
        self.sponge.update(&[scalar]);
    }

    fn squeeze_challenge(&mut self) -> F {
        PoseidonSponge::squeeze(&mut self.sponge)
    }
}

/// Creates a boxed Poseidon transcript instance.
pub fn poseidon_transcript<F: Field, G: CurveGroup>() -> Box<dyn Transcript<F, G>> {
    Box::new(PoseidonTranscript::new())
}
