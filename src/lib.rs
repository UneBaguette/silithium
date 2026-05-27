// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2026 Thomas <tom@unebaguette.fr>

//! Silithium: a compact, non-separable hybrid signature scheme combining
//! EC-Schnorr and ML-DSA via fused Fiat-Shamir.
//!
//! Reference: Devevey, Guerreau, Roméas - "Compact, Efficient and Non-Separable
//! Hybrid Signatures" (ePrint 2025/2059).

use getrandom::{SysRng, rand_core::UnwrapErr};
use hybrid_array::Array;
use hybrid_array::typenum::U64;
use ml_dsa::signature::Keypair;
use ml_dsa::{Generate, MlDsa44};
use p256::elliptic_curve::ops::Reduce;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{NonZeroScalar, ProjectivePoint};
use shake::digest::{ExtendableOutput, Update, XofReader};

/// Silithium signing key containing both EC and ML-DSA components.
pub struct SigningKey {
    /// EC-Schnorr secret scalar
    sk1: p256::SecretKey,
    /// EC-Schnorr public key
    vk1: p256::PublicKey,
    /// ML-DSA expanded signing key
    sk2: ml_dsa::ExpandedSigningKey<MlDsa44>,
    /// ML-DSA verifying key
    vk2: ml_dsa::VerifyingKey<MlDsa44>,
    /// Precomputed tr = SHAKE256(vk1 || vk2, 512)
    tr: [u8; 64],
}

/// Silithium verifying key containing both EC and ML-DSA public components.
#[derive(Clone, Debug)]
pub struct VerifyingKey {
    /// EC-Schnorr public key
    vk1: p256::PublicKey,
    /// ML-DSA verifying key
    vk2: ml_dsa::VerifyingKey<MlDsa44>,
    /// Precomputed tr = SHAKE256(vk1 || vk2, 512)
    tr: [u8; 64],
}

/// Silithium signature: the ML-DSA signature (containing c̃, z, h) plus
/// the Schnorr response scalar x.
pub struct Signature {
    /// Full ML-DSA signature (c̃ || z || h in encoded form)
    ml_dsa_sig: ml_dsa::Signature<MlDsa44>,
    /// Schnorr response: x = r + sk1 . c̃ mod n
    x: p256::Scalar,
}

impl SigningKey {
    /// Generate a fresh Silithium-44 keypair.
    pub fn generate() -> Self {
        let sk1 = p256::SecretKey::generate();
        let vk1 = sk1.public_key();

        let ml_dsa_key: ml_dsa::SigningKey<MlDsa44> =
            Generate::generate_from_rng(&mut UnwrapErr(SysRng));

        let sk2 = ml_dsa_key.expanded_key().clone();
        let vk2 = ml_dsa_key.verifying_key();

        let tr = compute_tr(&vk1, &vk2);

        Self {
            sk1,
            vk1,
            sk2,
            vk2,
            tr,
        }
    }

    /// Sign a message using the Silithium hybrid scheme.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        let nonce = NonZeroScalar::generate();
        let nonce_point = (ProjectivePoint::GENERATOR * nonce.as_ref()).to_affine();

        // µ = SHAKE256(tr || R || msg, 512)
        let nonce_bytes = nonce_point.to_sec1_point(false);
        let r_bytes = &nonce_bytes.as_bytes()[1..]; // X || Y brut

        let mut hasher = shake::Shake256::default();

        hasher.update(&self.tr);
        hasher.update(r_bytes);
        hasher.update(msg);

        let mut reader = hasher.finalize_xof();
        let mut mu = [0u8; 64];

        reader.read(&mut mu);

        // (z, c̃, h) = ML-DSA.Sign_mu(sk2, µ)
        let mu: Array<u8, U64> = Array::from(mu); // mu: [u8; 64]
        let ml_dsa_sig = self.sk2.sign_mu_deterministic(&mu);

        // x = r + sk1 . c̃ mod n
        let sig_bytes = ml_dsa_sig.encode();

        let c_tilde_bytes: [u8; 32] = sig_bytes[..32].try_into().unwrap();
        let c_scalar = p256::Scalar::reduce(&p256::U256::from_be_slice(&c_tilde_bytes));

        let sk1_scalar = *self.sk1.to_nonzero_scalar();

        let x = *nonce.as_ref() + sk1_scalar * c_scalar;

        Signature { ml_dsa_sig, x }
    }

    /// Derive the corresponding [`VerifyingKey`].
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey {
            vk1: self.vk1,
            vk2: self.vk2.clone(),
            tr: self.tr,
        }
    }

    /// Access the precomputed `tr` value.
    pub fn tr(&self) -> &[u8; 64] {
        &self.tr
    }
}

impl VerifyingKey {
    /// Access the EC public key.
    pub fn ec_key(&self) -> &p256::PublicKey {
        &self.vk1
    }

    /// Access the ML-DSA verifying key.
    pub fn ml_dsa_key(&self) -> &ml_dsa::VerifyingKey<MlDsa44> {
        &self.vk2
    }

    /// Access the precomputed `tr` value.
    pub fn tr(&self) -> &[u8; 64] {
        &self.tr
    }

    /// Verify a Silithium signature against a message.
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> bool {
        // R = x*G - c*vk1
        let c_tilde = sig.c_tilde();
        let c_scalar = p256::Scalar::reduce(&p256::U256::from_be_slice(&c_tilde));

        let vk1_point = self.vk1.to_projective();
        let r_point = (ProjectivePoint::GENERATOR * sig.x - vk1_point * c_scalar).to_affine();

        // µ = H(tr || R || M)
        let r_bytes = r_point.to_sec1_point(false);
        let r_raw = &r_bytes.as_bytes()[1..];

        let mut hasher = shake::Shake256::default();
        hasher.update(&self.tr);
        hasher.update(r_raw);
        hasher.update(msg);

        let mut reader = hasher.finalize_xof();
        let mut mu = [0u8; 64];
        reader.read(&mut mu);

        // ML-DSA.Verify_mu(vk2, µ, sig)
        let mu: Array<u8, U64> = Array::from(mu);

        self.vk2.verify_mu(&mu, &sig.ml_dsa_sig)
    }
}

impl Signature {
    /// Access the ML-DSA signature component.
    pub fn ml_dsa_sig(&self) -> &ml_dsa::Signature<MlDsa44> {
        &self.ml_dsa_sig
    }

    /// Access the Schnorr response scalar.
    pub fn x(&self) -> &p256::Scalar {
        &self.x
    }

    /// Extract `c_tilde` from the encoded ML-DSA signature.
    /// Per FIPS 204, the signature encoding is c̃ || z || h,
    /// so the first Lambda bytes (32 for MlDsa44) are c̃.
    pub fn c_tilde(&self) -> [u8; 32] {
        use ml_dsa::signature::SignatureEncoding;
        let bytes = <ml_dsa::Signature<MlDsa44>>::to_bytes(&self.ml_dsa_sig);

        let mut c = [0u8; 32];

        c.copy_from_slice(&bytes[..32]);

        c
    }
}

/// Compute tr = SHAKE256(vk1_uncompressed || vk2_encoded, 512 bits).
fn compute_tr(vk1: &p256::PublicKey, vk2: &ml_dsa::VerifyingKey<MlDsa44>) -> [u8; 64] {
    let vk1_bytes = vk1.to_sec1_point(false);
    let vk2_bytes = vk2.encode();

    let mut hasher = shake::Shake256::default();

    hasher.update(vk1_bytes.as_bytes());
    hasher.update(&vk2_bytes);

    let mut reader = hasher.finalize_xof();
    let mut tr = [0u8; 64];

    reader.read(&mut tr);

    tr
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn sign_verify_roundtrip() {
        let sk = SigningKey::generate();
        let vk = sk.verifying_key();
        let msg = b"hello silithium";

        let sig = sk.sign(msg);
        assert!(vk.verify(msg, &sig));
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let sk = SigningKey::generate();
        let vk = sk.verifying_key();

        let sig = sk.sign(b"correct message");
        assert!(!vk.verify(b"wrong message", &sig));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let sk1 = SigningKey::generate();
        let sk2 = SigningKey::generate();
        let msg = b"test";

        let sig = sk1.sign(msg);
        assert!(!sk2.verifying_key().verify(msg, &sig));
    }

    #[test]
    fn sign_empty_message() {
        let sk = SigningKey::generate();
        let vk = sk.verifying_key();

        let sig = sk.sign(b"");
        assert!(vk.verify(b"", &sig));
    }

    #[test]
    fn sign_large_message() {
        let sk = SigningKey::generate();
        let vk = sk.verifying_key();
        let msg = vec![0xABu8; 10_000];

        let sig = sk.sign(&msg);
        assert!(vk.verify(&msg, &sig));
    }

    #[test]
    fn two_signatures_differ() {
        let sk = SigningKey::generate();
        let msg = b"same message";

        let sig1 = sk.sign(msg);
        let sig2 = sk.sign(msg);

        // Nonce is random, so x should differ
        assert_ne!(sig1.x, sig2.x);
    }

    #[test]
    fn verifying_key_tr_matches_signing_key() {
        let sk = SigningKey::generate();
        let vk = sk.verifying_key();

        assert_eq!(sk.tr(), vk.tr());
    }
}
