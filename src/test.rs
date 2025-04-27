#[cfg(test)]
mod test {
    use crate::{
        keypair::Keypair, musig::MuSig, signature::Signature, transcript::PoseidonTranscript,
    };
    use ark_bn254::{Fr, G1Projective};

    #[test]
    fn test_single_signature_valid() {
        let message = Fr::from(16);
        let keypair = Keypair::<Fr, G1Projective>::generate();

        let mut transcript = PoseidonTranscript::<Fr>::new();
        let signature = Signature::sign(&keypair, &mut transcript, message);

        let mut verify_transcript = PoseidonTranscript::<Fr>::new();
        assert!(signature.verify(keypair.public_key, &mut verify_transcript, message))
    }

    #[test]
    fn test_single_signature_invalid() {
        let message = Fr::from(16);
        let bad_message = Fr::from(666);
        let keypair = Keypair::<Fr, G1Projective>::generate();

        let mut transcript = PoseidonTranscript::<Fr>::new();
        let signature = Signature::sign(&keypair, &mut transcript, message);

        let mut verify_transcript = PoseidonTranscript::<Fr>::new();
        assert!(!signature.verify(keypair.public_key, &mut verify_transcript, bad_message));
    }

    #[test]
    fn test_musig_signature_valid() {
        let message = Fr::from(16);

        let k1 = Keypair::<Fr, G1Projective>::generate();
        let k2 = Keypair::<Fr, G1Projective>::generate();
        let pub_keys = [k1.public_key, k2.public_key];
        let mut transcript = PoseidonTranscript::new();

        let keyset_challenge = MuSig::compute_keyset_challenge(&pub_keys, &mut transcript);
        let agg_pub_key = MuSig::compute_agg_pub_key(&pub_keys, keyset_challenge, &mut transcript);

        let s1 = MuSig::sign(k1, message, &mut transcript, keyset_challenge);
    }
}
