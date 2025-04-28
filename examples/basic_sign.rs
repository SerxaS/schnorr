//! Simple Schnorr signature example
//!
//! This example demonstrates signing and verifying a field element
//! using a Poseidon transcript over the BN254 curve.

use schnorr_spongefish::{keypair::Keypair, signature::Signature, transcript::PoseidonTranscript};

type F = ark_bn254::Fr;
type G = ark_bn254::G1Projective;

fn main() {
    // Generate a keypair
    let keypair = Keypair::<F, G>::generate();

    // Create a message to sign
    let message_value = 11082015;
    let message = F::from(message_value);

    // Initialize a Poseidon-based transcript for signing
    let mut transcript = PoseidonTranscript::<F>::new();
    let signature = Signature::sign(&keypair, &mut transcript, message);

    // Initialize a fresh transcript for verification
    let mut verify_transcript = PoseidonTranscript::<F>::new();
    let is_valid = signature.verify(keypair.public_key, &mut verify_transcript, message);

    // Output the result
    println!("Signed message: {}", message_value);
    println!("Signature verification passed: {}", is_valid);
}
