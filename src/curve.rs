use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::Field;

pub type Scalar<F: Field> = F;
pub type Point<G: CurveGroup> = G;

/// Returns the generator of the curve
pub fn generator<G: CurveGroup>() -> Point<G> {
    Point::generator()
}
