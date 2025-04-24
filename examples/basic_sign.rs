//! Basic example of Schnorr signature generation and verification
//! using Poseidon transcript over BN254

use ark_bn254::{Fr, G1Projective};
use schnorr_spongefish::{
    keypair::Keypair,
    signature::Signature,
    transcript::{PoseidonTranscript, Transcript},
};

fn main() {
    // Generate a keypair
    let keypair = Keypair::<Fr, G1Projective>::generate();

    // Create a message as a field element
    let message = Fr::from(11082015);

    // Initialize a Poseidon-based transcript
    let mut transcript = PoseidonTranscript::<Fr>::new();

    // Sign the message
    let sign = Signature::sign(&keypair, &mut transcript, message);

    // Prepare a fresh transcript for verification
    let mut verify_transcript = PoseidonTranscript::<Fr>::new();
    let is_valid = sign.verify(keypair.public_key, &mut verify_transcript, message);

    println!("Signature is valid: {}", is_valid);
}
