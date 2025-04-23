/// Poseidon Bn254 with 5 = 5 and EXPONENTIATION = 5
pub mod poseidon_bn254_5x5;
use ark_ff::Field;
use std::fmt::Debug;

/// Trait definition of Round parameters of Poseidon
pub trait RoundParams<F: Field>: Sbox<F> + Clone + Debug {
    /// Returns a number of full rounds.
    fn full_rounds() -> usize;
    /// Returns a number of partial rounds.
    fn partial_rounds() -> usize;

    /// Returns total count size.
    fn round_constants_count() -> usize {
        let partial_rounds = Self::partial_rounds();
        let full_rounds = Self::full_rounds();
        (partial_rounds + full_rounds) * 5
    }

    /// Returns round constants array to be used in permutation.
    fn round_constants() -> Vec<F> {
        let round_constants_raw = Self::round_constants_raw();
        let round_constants: Vec<F> = round_constants_raw
            .iter()
            .map(|x| hex_to_field(x))
            .collect();
        assert_eq!(round_constants.len(), Self::round_constants_count());
        round_constants
    }

    /// Returns relevant constants for the given round.
    fn load_round_constants(round: usize, round_consts: &[F]) -> [F; 5] {
        let mut result = [F::ZERO; 5];
        for i in 0..5 {
            result[i] = round_consts[round * 5 + i];
        }
        result
    }

    /// Returns MDS matrix with a size of 5 x 5.
    fn mds() -> [[F; 5]; 5] {
        let mds_raw = Self::mds_raw();
        mds_raw.map(|row| row.map(|item| hex_to_field(item)))
    }

    /// Returns round constants in its hex string form.
    fn round_constants_raw() -> Vec<&'static str>;
    /// Returns MDS martrix in its hex string form.
    fn mds_raw() -> [[&'static str; 5]; 5];
    /// Add round constants to the state values
    /// for the AddRoundConstants operation.
    fn apply_round_constants(state: &[F; 5], round_consts: &[F; 5]) -> [F; 5] {
        let mut next_state = [F::ZERO; 5];
        for i in 0..5 {
            let state = state[i];
            let round_const = round_consts[i];
            let sum = state + round_const;
            next_state[i] = sum;
        }
        next_state
    }
    /// Compute MDS matrix for MixLayer operation.
    fn apply_mds(state: &[F; 5]) -> [F; 5] {
        let mut new_state = [F::ZERO; 5];
        let mds = Self::mds();
        for i in 0..5 {
            for j in 0..5 {
                let mds_ij = &mds[i][j];
                let m_product = state[j] * mds_ij;
                new_state[i] += m_product;
            }
        }
        new_state
    }
}

/// Trait definition for Sbox operation of Poseidon
pub trait Sbox<F: Field> {
    /// Returns the S-box exponentiation for the field element.
    fn sbox_f(f: F) -> F;
    /// Returns the S-box exponentiation of the inverse for the field element.
    fn sbox_inv_f(f: F) -> F;
}

/// Returns congruent field element for the given hex string.
pub fn hex_to_field<F: Field>(s: &str) -> F {
    let s = &s[2..];
    let mut bytes = hex::decode(s).expect("Invalid params");
    bytes.reverse();
    let mut bytes_wide: [u8; 64] = [0; 64];
    bytes_wide[..bytes.len()].copy_from_slice(&bytes[..]);
    F::from_random_bytes(&bytes_wide).unwrap()
}
