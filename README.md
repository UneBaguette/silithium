# Silithium

Silithium is a **compact, non-separable hybrid digital signature scheme** combining EC-Schnorr and ML-DSA via fused
Fiat-Shamir.

Unlike simple concatenation, Silithium shares a single challenge across both components, producing signatures that are
smaller, faster, and non-separable by construction.

Based on: [*Compact, Efficient and Non-Separable Hybrid Signatures*](https://ia.cr/2025/2059)
by **Devevey**, **Guerreau**, and **Roméas** (**ANSSI** / **PQShield**, 2025).

## Parameter sets

| Variant      | EC curve | ML-DSA    | Classical | Post-quantum | VK size | Sig size |
|--------------|----------|-----------|-----------|--------------|---------|----------|
| Silithium-44 | P-256    | ML-DSA-44 | 128-bit   | NIST Level 2 | 1 345 B | 2 452 B  |
| Silithium-65 | P-384    | ML-DSA-65 | 192-bit   | NIST Level 3 | 2 001 B | 3 357 B  |
| Silithium-87 | P-521    | ML-DSA-87 | 256-bit   | NIST Level 5 | 2 659 B | 4 693 B  |

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

Both components share a challenge through a fused Fiat–Shamir transform:

1. `tr = SHAKE256(vk1 || vk2, 512)` — bind both public keys
2. `R = r·G` — Schnorr nonce commitment (random)
3. `µ = SHAKE256(tr || R || msg, 512)` — fused message
4. `(c̃, z, h) = ML-DSA.Sign(sk2, µ)` — ML-DSA signs µ
5. `x = r + sk1·c̃ mod n` — Schnorr response using ML-DSA's challenge
6. `σ = (mldsa_sig, x)` — composite signature

The Schnorr component is verified implicitly: if `c̃` came from a different `R`, the recomputed `µ` won't match and ML-DSA verification fails. Neither component can be stripped nor verified independently.

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
