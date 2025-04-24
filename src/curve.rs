use ark_ec::{CurveGroup, PrimeGroup};

pub type Scalar<F> = F;
pub type Point<G> = G;

/// Returns the generator of the curve
pub fn generator<G: CurveGroup>() -> Point<G> {
    Point::generator()
}
