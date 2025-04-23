use super::Poseidon;
use ark_ff::Field;

/// Constructs objects.
#[derive(Clone, Debug)]
pub struct PoseidonSponge<F: Field> {
    /// Constructs a vector for the inputs.
    inputs: Vec<F>,
    /// Internal state
    state: [F; 5],
}

impl<F: Field> PoseidonSponge<F> {
    /// Create objects.
    pub fn new() -> Self {
        Self {
            inputs: Vec::new(),
            state: [F::ZERO; 5],
        }
    }

    /// Clones and appends all elements from a slice to the vec.
    pub fn update(&mut self, inputs: &[F]) {
        self.inputs.extend_from_slice(inputs);
    }

    /// Absorb the data in and split it into
    /// chunks of size 5.
    fn load_state(chunk: &[F]) -> [F; 5] {
        assert!(chunk.len() <= 5);
        let mut fixed_chunk = [F::ZERO; 5];
        fixed_chunk[..chunk.len()].copy_from_slice(chunk);
        fixed_chunk
    }

    /// Squeeze the data out by
    /// permuting until no more chunks are left.
    pub fn squeeze(&mut self) -> F {
        if self.inputs.is_empty() {
            self.inputs.push(F::ZERO);
        }

        for chunk in self.inputs.chunks(5) {
            let mut input = [F::ZERO; 5];

            // Absorb
            let loaded_state = Self::load_state(chunk);
            for i in 0..5 {
                input[i] = loaded_state[i] + self.state[i];
            }

            // Permute
            let pos = Poseidon::new(input);
            self.state = pos.permute();
        }

        // Clear the inputs, and return the result
        self.inputs.clear();
        self.state[0]
    }
}

impl<F: Field> Default for PoseidonSponge<F> {
    fn default() -> Self {
        Self::new()
    }
}
