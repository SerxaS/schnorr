## 🧠 Schnorr Signatures over Arkworks with ZK Transcripts

This project provides a modular and zk-friendly implementation of Schnorr signatures over elliptic curve groups using the [arkworks](https://github.com/arkworks-rs) ecosystem.

---

### 🔧 Features

- ✅ **Poseidon-based sponge hashing** (native implementation)
- ✅ **Curve-agnostic design** using `G: CurveGroup` and `F: PrimeField`
- ✅ **Transcript abstraction** for Fiat–Shamir transformation
- 🔜 **Planned integration with [spongefish](https://github.com/arkworks-rs/spongefish)** — a generic Fiat–Shamir library for public-coin protocols
- 🚀 Designed for **ZK circuits**, **recursive proofs**, and **modular backend swaps**

---

### 📆 Usage

This crate is under active development. Stay tuned for:

- 🔬 Expanded unit tests
- ⛓️ Circuit-ready signature gadgets
- 🧽 Seamless spongefish drop-in support

---

### 📚 Example

You can run the following minimal usage example:

```bash
cargo run --example basic_sign
```

This will:

- Generate a keypair
- Sign a message
- Verify the signature using a Poseidon-based transcript

See [`examples/basic_sign.rs`](examples/basic_sign.rs) for the full code.
