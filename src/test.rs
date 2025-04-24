#[cfg(test)]
mod test {
    use crate::{keypair::Keypair, signature::Signature, transcript::PoseidonTranscript};
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
}
