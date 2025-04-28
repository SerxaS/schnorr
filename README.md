# 🔒 Schnorr Signatures and MuSig over Arkworks

This project provides a modular and zk-friendly implementation of Schnorr signatures and MuSig multi-signatures over elliptic curve groups, using the [arkworks](https://github.com/arkworks-rs) ecosystem.

---

### 🔧 Features

- ✅ **Poseidon-based sponge hashing** (native implementation)
- ✅ **Schnorr signatures** over any curve group (`G: CurveGroup`)
- ✅ **MuSig multi-party signatures**: Aggregates signatures from multiple participants
- ✅ **Transcript abstraction** for Fiat–Shamir transformation
- 🚀 Designed for **ZK circuits**, **recursive proofs**, and **modular backend swaps**

---

### 📚 Usage

This crate is under active development. Stay tuned for:

- 🔬 Expanded unit tests
- ⛓️ Circuit-ready signature gadgets
- 🧽 Seamless spongefish drop-in support

---

### ✊️ Basic Example: Single Signature

To see **basic Schnorr signatures** and **MuSig multi-signatures** in action, you can run the following examples:

#### Basic Schnorr Signature Example

You can run a minimal example:

```bash
cargo run --example basic_sign
```

This will:

- Generate a keypair

- Sign a message

- Verify the signature using a Poseidon-based transcript

See examples/basic_sign.rs for full code.

---

### 🔗 MuSig Example: Multi-party Aggregated Signature

To see MuSig multi-signature aggregation across multiple participants, run the following:

```bash
cargo run --example musig_sign
```

This will:

- Aggregate signatures from two participants

- Verify the aggregated MuSig signature using a Poseidon-based transcript

See examples/musig_sign.rs for full code.

---
