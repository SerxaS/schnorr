use ark_ec::CurveGroup;
use ark_ff::Field;

pub trait Transcript {
    fn absorb_point<G: CurveGroup>(point: G);
    fn absorb_scalar<F: Field>(scalar: F);
    fn squeeze_challenge<F: Field>() -> F;
}

// pub struct PoseidonTranscript {
//     sponge: PoseidonSponge,
// }
