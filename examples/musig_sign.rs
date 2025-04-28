//! Example: MuSig signing and verification with two participants

#![allow(non_snake_case)]

use ark_bn254::{Fr, G1Projective};
use schnorr_spongefish::{keypair::Keypair, musig::MuSig, transcript::PoseidonTranscript};

fn main() {
    // Define message to sign
    let message = Fr::from(16);

    // Generate keypairs for two participants and each participant generates their nonce
    let k1 = Keypair::<Fr, G1Projective>::generate();
    let (r1, R1) = MuSig::<Fr, G1Projective>::create_nonce();

    let k2 = Keypair::<Fr, G1Projective>::generate();
    let (r2, R2) = MuSig::<Fr, G1Projective>::create_nonce();

    // Aggregate public keys
    let pub_keys = [k1.public_key, k2.public_key];
    let keyset_challenge = MuSig::keyset_challenge(&pub_keys);
    let agg_pub_key = MuSig::agg_pub_keys(&pub_keys, keyset_challenge);

    // Aggregate nonces
    let agg_R = R1 + R2;

    // Each participant computes their partial signature
    let s1 = MuSig::sign(k1, message, keyset_challenge, agg_pub_key, agg_R, r1);
    let s2 = MuSig::sign(k2, message, keyset_challenge, agg_pub_key, agg_R, r2);

    // Aggregate partial signatures
    let agg_s = s1 + s2;

    // Form the MuSig signature
    let musig = MuSig { agg_R, agg_s };

    // Verify the MuSig signature
    let mut verify_transcript = PoseidonTranscript::new();
    let is_valid = MuSig::verify(
        &musig,
        message,
        &mut verify_transcript,
        agg_pub_key,
        agg_R,
        agg_s,
    );

    println!("MuSig signature is valid: {}", is_valid);
}
