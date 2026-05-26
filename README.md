# Silithium

Silithium is a **hybrid digital signature scheme** combining the identification schemes underlying **EC-Schnorr** and **ML-DSA**.

The current variant is only the **silithium-44**.

## Current Variants

| Variant          | ML-DSA Variant | Curve | Signature Size |
|------------------|----------------|-------|----------------|
| **silithium-44** | ML-DSA-44      | P-256 | ~2420 + 32     |

## Research Foundation

This implementation is based on the paper:
[**Compact, Efficient and Non-Separable Hybrid Signatures**](https://ia.cr/2025/2059)

(Submitted to IACR, 2025)

## Acknowledgments

- IACR researchers for the foundational hybrid signature framework.
- The cryptographic community for open-source tools and standards.

## License

This project is **dual-licensed** under the following open-source licenses:

- [**MIT License**](LICENSE-MIT)
- [**Apache 2.0 License**](LICENSE-APACHE)

Choose the license that best fits your use case.

*Note: This project is under active development. Always verify security requirements for production use.*