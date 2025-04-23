This project provides a modular and zk-friendly implementation of Schnorr signatures over elliptic curve groups using the arkworks ecosystem. It includes:

- Poseidon-based native sponge hashing
- Curve-agnostic keypair and signature logic
- Transcript abstraction designed for Fiat–Shamir transformation
- Plans for full integration with spongefish: a generic, efficient Fiat–Shamir library for public coin protocols

Supports generic `G: CurveGroup` and `F: PrimeField` types, and is designed to be circuit-friendly and recursive-proof ready.
