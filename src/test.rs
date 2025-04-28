//! Unit tests for single Schnorr signatures and MuSig multi-signatures.
//!
//! Tests:
//! - `test_single_signature_valid`: Validates correct signature verification
//! - `test_single_signature_invalid`: Ensures invalid message fails verification
//! - `test_musig_signature_valid`: Tests multi-party MuSig signature aggregation and verification

#![allow(non_snake_case)]

#[cfg(test)]
mod test {
    use crate::{
        keypair::Keypair, musig::MuSig, signature::Signature, transcript::PoseidonTranscript,
    };

    /// Tests that a valid Schnorr signature verifies correctly.
    #[test]
    fn test_single_signature_valid() {
        type F = ark_bn254::Fr;
        type G = ark_bn254::G1Projective;

        let message = F::from(16);
        let keypair = Keypair::<F, G>::generate();

        let mut transcript = PoseidonTranscript::<F>::new();
        let signature = Signature::sign(&keypair, &mut transcript, message);

        let mut verify_transcript = PoseidonTranscript::<F>::new();
        assert!(signature.verify(keypair.public_key, &mut verify_transcript, message))
    }

    /// Tests that an invalid Schnorr signature (wrong message) fails verification.
    #[test]
    fn test_single_signature_invalid() {
        type F = ark_bn254::Fr;
        type G = ark_bn254::G1Projective;

        let message = F::from(16);
        let bad_message = F::from(666);
        let keypair = Keypair::<F, G>::generate();

        let mut transcript = PoseidonTranscript::<F>::new();
        let signature = Signature::sign(&keypair, &mut transcript, message);

        let mut verify_transcript = PoseidonTranscript::<F>::new();
        assert!(!signature.verify(keypair.public_key, &mut verify_transcript, bad_message));
    }

    /// Tests that MuSig aggregated signature with two participants verifies correctly.
    #[test]
    fn test_musig_signature_valid() {
        type F = ark_bn254::Fr;
        type G = ark_bn254::G1Projective;

        let message = F::from(16);

        let k1 = Keypair::<F, G>::generate();
        let (r1, R1) = MuSig::<F, G>::create_nonce();

        let k2 = Keypair::<F, G>::generate();
        let (r2, R2) = MuSig::<F, G>::create_nonce();

        let pub_keys = [k1.public_key, k2.public_key];
        let keyset_challenge = MuSig::keyset_challenge(&pub_keys);
        let agg_pub_keys = MuSig::agg_pub_keys(&pub_keys, keyset_challenge);

        let agg_R = R1 + R2;

        let s1 = MuSig::sign(k1, message, keyset_challenge, agg_pub_keys, agg_R, r1);
        let s2 = MuSig::sign(k2, message, keyset_challenge, agg_pub_keys, agg_R, r2);
        let agg_s = s1 + s2;

        let musig = MuSig { agg_R, agg_s };

        let mut verify_transcript = PoseidonTranscript::new();
        let is_valid = MuSig::verify(
            &musig,
            message,
            &mut verify_transcript,
            agg_pub_keys,
            agg_R,
            agg_s,
        );

        assert!(is_valid, "MuSig verification should succeed!");
    }
}
