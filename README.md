# Silithium

Silithium is a **compact, non-separable hybrid digital signature scheme** combining EC-Schnorr and ML-DSA via fused
Fiat-Shamir.

Unlike simple concatenation, Silithium shares a single challenge across both components, producing signatures that are
smaller, faster, and non-separable by construction.

Based on: [*Compact, Efficient and Non-Separable Hybrid Signatures*](https://ia.cr/2025/2059)
by **Devevey**, **Guerreau**, and **Roméas** (**ANSSI** / **PQShield**, 2025).

## Parameter sets

| Variant      | Curve | ML-DSA    | Security              | VK     | Sig    |
|--------------|-------|-----------|-----------------------|--------|--------|
| Silithium-44 | P-256 | ML-DSA-44 | 128-bit, NIST Level 2 | 1.3 KB | 2.5 KB |
| Silithium-65 | P-384 | ML-DSA-65 | 192-bit, NIST Level 3 | 2.0 KB | 3.4 KB |
| Silithium-87 | P-521 | ML-DSA-87 | 256-bit, NIST Level 5 | 2.6 KB | 4.7 KB |

### Wire sizes

Verifying key = EC compressed point + ML-DSA verifying key.

|    | EC point | ML-DSA VK | Total   |
|----|----------|-----------|---------|
| 44 | 33 B     | 1 312 B   | 1 345 B |
| 65 | 49 B     | 1 952 B   | 2 001 B |
| 87 | 67 B     | 2 592 B   | 2 659 B |

Signature = ML-DSA signature + EC scalar.

|    | ML-DSA sig | EC scalar | Total   |
|----|------------|-----------|---------|
| 44 | 2 420 B    | 32 B      | 2 452 B |
| 65 | 3 309 B    | 48 B      | 3 357 B |
| 87 | 4 627 B    | 66 B      | 4 693 B |

## Usage

```rust
use silithium::{SigningKey, Silithium65};

let sk = SigningKey::::generate();
let vk = sk.verifying_key();

let sig = sk.sign(b"hello silithium");
assert!(vk.verify(b"hello silithium", &sig).is_ok());
```

### Deterministic key generation

```rust
let seed = [0u8; 32]; // use CSPRNG in practice
let sk = SigningKey::::generate_from_seed( & seed);
```

Both keys are derived from a single 32-byte seed via **SHAKE256** with domain separation. 
The same seed always produces the same keypair.

### Serialization

```rust
let vk_bytes = vk.encode();
let vk2 = VerifyingKey::::decode(&vk_bytes)?;

let sig_bytes = sig.encode();
let sig2 = Signature::::decode(&sig_bytes)?;
```

## How it works

Both components share a single challenge `c̃` via fused Fiat–Shamir:
the Schnorr nonce `R` is hashed into `µ = SHAKE256(tr ‖ R ‖ msg)`, which ML-DSA signs. 

The resulting `c̃` doubles as the Schnorr challenge. Verification recovers `R` from the
Schnorr response and checks ML-DSA against the recomputed `µ`.

Neither component can be stripped nor verified independently.

## Features

- `schnorr` (default) — EC-Schnorr signatures
- `zeroize` — zeroize sensitive key material on drop

## Security Warning

⚠️ **This is experimental software. Not audited for production use.**

## License

This project is **dual-licensed** under the following open-source licenses:

- [**MIT License**](LICENSE-MIT)
- [**Apache 2.0 License**](LICENSE-APACHE)

Choose the license that best fits your use case.
