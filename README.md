# Silithium


Silithium is a **compact, non-separable hybrid digital signature scheme** combining EC-Schnorr and ML-DSA via fused Fiat-Shamir.

Unlike simple concatenation, Silithium shares a single challenge across both components, producing signatures that are smaller, faster, and non-separable by construction.

## Variants

| Variant          | ML-DSA    | Curve | Signature Size  |
|------------------|-----------|-------|-----------------|
| **Silithium-44** | ML-DSA-44 | P-256 | 2420 + 32 bytes |
| **Silithium-65** | ML-DSA-65 | P-384 | 3309 + 48 bytes |
| **Silithium-87** | ML-DSA-87 | P-521 | 4627 + 66 bytes |
## Usage

```rust
use silithium::{SigningKey, Silithium44};

let sk = SigningKey::::generate();
let vk = sk.verifying_key();

let sig = sk.sign(b"hello silithium");
assert!(vk.verify(b"hello silithium", &sig));
```

## Security Warning

⚠️ **This is experimental software. Not audited for production use.**

## Reference / Resources

Based on: [**Compact, Efficient and Non-Separable Hybrid Signatures**](https://ia.cr/2025/2059)
by Devevey, Guerreau, and Roméas (ANSSI / PQShield, 2025).

## License

This project is **dual-licensed** under the following open-source licenses:

- [**MIT License**](LICENSE-MIT)
- [**Apache 2.0 License**](LICENSE-APACHE)

Choose the license that best fits your use case.

*Note: This project is under active development. Always verify security requirements for production use.*