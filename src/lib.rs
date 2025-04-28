//! Schnorr signatures over elliptic curves with Poseidon-based transcripts.
//!
//! Modules:
//! - `keypair`: Key generation
//! - `signature`: Basic Schnorr signature
//! - `musig`: Multi-signature (MuSig) support
//! - `poseidon_hash`: Native Poseidon sponge hash
//! - `transcript`: Fiat–Shamir transcript abstraction
//! - `test`: Unit tests
//!
//! Inspired by ZK-friendly signature systems and built over the Arkworks ecosystem.

pub mod keypair;
pub mod musig;
pub mod poseidon_hash;
pub mod signature;
pub mod test;
pub mod transcript;
