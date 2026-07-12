// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2026 Thomas <tom@unebaguette.fr>

#![no_std]
#![forbid(unsafe_code)]
#![warn(
    clippy::pedantic,
    missing_docs,
    unused_qualifications
)]
#![allow(clippy::module_name_repetitions)]

//! # Silithium
//!
//! A compact, non-separable hybrid signature scheme combining
//! EC-Schnorr and ML-DSA via fused Fiat–Shamir.
//!
//! Reference: Devevey, Guerreau, Roméas - *Compact, Efficient and
//! Non-Separable Hybrid Signatures* (ePrint 2025/2059).
//!
//! ## Security
//!
//! Silithium provides non-separable hybrid signatures: both the classical
//! (EC-Schnorr) and post-quantum (ML-DSA) components must verify for
//! the signature to be accepted. This protects against:
//!
//! - A break in ML-DSA: the EC-Schnorr component still provides
//!   classical security on the corresponding NIST curve.
//! - A cryptographically relevant quantum computer (CRQC): the ML-DSA
//!   component provides post-quantum security.
//!
//! ## Parameter sets
//!
//! | Name           | EC curve | ML-DSA    | Classical | Post-quantum | VK size  | Sig size |
//! |----------------|----------|-----------|-----------|-------------|----------|----------|
//! | Silithium-44   | P-256    | ML-DSA-44 | 128-bit   | Level 2     | 1 345 B  | 2 452 B  |
//! | Silithium-65   | P-384    | ML-DSA-65 | 192-bit   | Level 3     | 2 001 B  | 3 357 B  |
//! | Silithium-87   | P-521    | ML-DSA-87 | 256-bit   | Level 5     | 2 659 B  | 4 693 B  |
//!
//! ## Key derivation
//!
//! Both signing keys can be derived from a single 32-byte seed using
//! SHAKE256 with domain separation:
//!
//! ```text
//! ec_seed    = SHAKE256("silithium-ec-key" || seed, scalar_size)
//! mldsa_seed = SHAKE256("silithium-pq-key" || seed, 32)
//! ```
//!
//! ## Non-separability
//!
//! The two signature components share a challenge `c̃` through a
//! fused Fiat–Shamir transform. The Schnorr nonce commitment `R`
//! is hashed into `µ = SHAKE256(tr || R || msg)`, which ML-DSA
//! signs. The resulting challenge `c̃` is reused as the Schnorr
//! challenge. Neither component can be stripped nor verified
//! independently.
//!
//! ## Example
//!
//! ```rust
//! use silithium::{SigningKey, Silithium65};
//!
//! let sk = SigningKey::<Silithium65>::generate();
//! let vk = sk.verifying_key();
//!
//! let sig = sk.sign(b"hello silithium");
//! assert!(vk.verify(b"hello silithium", &sig).is_ok());
//! ```
//!
//! ## Features
//!
//! - `schnorr` (default): EC-Schnorr signatures
//! - `zeroize`: Zeroize sensitive key material on drop

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use elliptic_curve::sec1::{FromSec1Point, ModulusSize};
use elliptic_curve::{
    AffinePoint, CurveArithmetic, FieldBytesSize, Group, NonZeroScalar, ProjectivePoint, PublicKey,
    Scalar, SecretKey,
};
use elliptic_curve::{CurveGroup, PrimeField};
use getrandom::{SysRng, rand_core::UnwrapErr};
use hybrid_array::Array;
use hybrid_array::typenum::U64;
use ml_dsa::Generate;
use p256::elliptic_curve::ops::Reduce;
use p256::elliptic_curve::sec1::ToSec1Point;
use shake::digest::{ExtendableOutput, Update, XofReader};
use signature::Keypair;

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// Errors returned by silithium operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Input bytes have an incorrect length.
    InvalidLength,
    /// A public key could not be decoded.
    InvalidPublicKey,
    /// A signature could not be decoded.
    InvalidSignature,
    /// Signature verification failed.
    VerificationFailed,
    /// Failed decoding type
    DecodingFailed,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidLength => write!(f, "invalid length"),
            Self::InvalidPublicKey => write!(f, "invalid public key"),
            Self::InvalidSignature => write!(f, "invalid signature"),
            Self::VerificationFailed => write!(f, "verification failed"),
            Self::DecodingFailed => write!(f, "failed to decode"),
        }
    }
}

/// Trait defining a Silithium parameter set.
pub trait SilithiumParams {
    /// The ML-DSA parameter set.
    type MlDsa: ml_dsa::MlDsaParams;
    /// The elliptic curve.
    type Curve: CurveArithmetic + elliptic_curve::PrimeCurve;

    /// Size of c_tilde in bytes (Lambda from ML-DSA parameter set)
    const LAMBDA: usize;

    /// Size of the EC scalar in bytes (signature overhead)
    const SCALAR_SIZE: usize;
    /// Size of the ML-DSA verifying key in bytes.
    const MLDSA_VK_SIZE: usize;
    /// Size of the ML-DSA signature in bytes.
    const MLDSA_SIG_SIZE: usize;

    /// Size of the SEC1 compressed EC point (SCALAR_SIZE + 1).
    const EC_COMPRESSED_SIZE: usize = Self::SCALAR_SIZE + 1;
    /// Total verifying key: EC_COMPRESSED_SIZE + MLDSA_VK_SIZE.
    const VERIFYING_KEY_SIZE: usize = Self::EC_COMPRESSED_SIZE + Self::MLDSA_VK_SIZE;
    /// Total signature: MLDSA_SIG_SIZE + SCALAR_SIZE.
    const SIGNATURE_SIZE: usize = Self::MLDSA_SIG_SIZE + Self::SCALAR_SIZE;

    /// Reduce c_tilde bytes to a scalar on the curve
    fn reduce_c_tilde(c_tilde: &[u8]) -> Scalar<Self::Curve>;

    /// Reduce arbitrary bytes to a scalar on the curve.
    fn scalar_from_bytes(bytes: &[u8]) -> Scalar<Self::Curve>;
}

/// P-256 + ML-DSA-44 (128-bit classical, NIST Level 2).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Silithium44;

impl SilithiumParams for Silithium44 {
    type MlDsa = ml_dsa::MlDsa44;
    type Curve = p256::NistP256;
    const LAMBDA: usize = 32;
    const SCALAR_SIZE: usize = 32;
    const MLDSA_VK_SIZE: usize = size_of::<ml_dsa::EncodedVerifyingKey<ml_dsa::MlDsa44>>();
    const MLDSA_SIG_SIZE: usize = size_of::<ml_dsa::EncodedSignature<ml_dsa::MlDsa44>>();

    fn reduce_c_tilde(c_tilde: &[u8]) -> p256::Scalar {
        Self::scalar_from_bytes(c_tilde)
    }

    fn scalar_from_bytes(bytes: &[u8]) -> p256::Scalar {
        let uint = <p256::NistP256 as elliptic_curve::Curve>::Uint::from_be_slice(bytes);

        p256::Scalar::reduce(&uint)
    }
}

/// P-384 + ML-DSA-65 (192-bit classical, NIST Level 3).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Silithium65;

impl SilithiumParams for Silithium65 {
    type MlDsa = ml_dsa::MlDsa65;
    type Curve = p384::NistP384;
    const LAMBDA: usize = 48;
    const SCALAR_SIZE: usize = 48;
    const MLDSA_VK_SIZE: usize = size_of::<ml_dsa::EncodedVerifyingKey<ml_dsa::MlDsa65>>();
    const MLDSA_SIG_SIZE: usize = size_of::<ml_dsa::EncodedSignature<ml_dsa::MlDsa65>>();

    fn reduce_c_tilde(c_tilde: &[u8]) -> p384::Scalar {
        Self::scalar_from_bytes(c_tilde)
    }

    fn scalar_from_bytes(bytes: &[u8]) -> p384::Scalar {
        let mut padded = [0u8; 48]; // FieldBytes size for P-384
        let offset = padded.len().saturating_sub(bytes.len());

        padded[offset..].copy_from_slice(bytes);

        let uint = <p384::NistP384 as elliptic_curve::Curve>::Uint::from_be_slice(&padded);

        p384::Scalar::reduce(&uint)
    }
}

/// P-521 + ML-DSA-87 (256-bit classical, NIST Level 5).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Silithium87;

impl SilithiumParams for Silithium87 {
    type MlDsa = ml_dsa::MlDsa87;
    type Curve = p521::NistP521;
    const LAMBDA: usize = 64;
    const SCALAR_SIZE: usize = 66;
    const MLDSA_VK_SIZE: usize = size_of::<ml_dsa::EncodedVerifyingKey<ml_dsa::MlDsa87>>();
    const MLDSA_SIG_SIZE: usize = size_of::<ml_dsa::EncodedSignature<ml_dsa::MlDsa87>>();

    fn reduce_c_tilde(c_tilde: &[u8]) -> p521::Scalar {
        Self::scalar_from_bytes(c_tilde)
    }

    fn scalar_from_bytes(bytes: &[u8]) -> p521::Scalar {
        let mut padded = [0u8; 72]; // Uint size for P-521 (U576 = 72 bytes on 64-bit)
        let offset = padded.len().saturating_sub(bytes.len());

        padded[offset..].copy_from_slice(bytes);

        let uint = <p521::NistP521 as elliptic_curve::Curve>::Uint::from_be_slice(&padded);

        p521::Scalar::reduce(&uint)
    }
}

/// Silithium signing key containing both EC and ML-DSA components.
pub struct SigningKey<P: SilithiumParams> {
    /// EC-Schnorr secret scalar
    sk1: SecretKey<P::Curve>,
    /// EC-Schnorr public key
    vk1: PublicKey<P::Curve>,
    /// ML-DSA expanded signing key
    sk2: ml_dsa::ExpandedSigningKey<P::MlDsa>,
    /// ML-DSA verifying key
    vk2: ml_dsa::VerifyingKey<P::MlDsa>,
    /// Precomputed tr = SHAKE256(vk1 || vk2, 512)
    tr: [u8; 64],
}

#[cfg(feature = "zeroize")]
impl<P: SilithiumParams> Drop for SigningKey<P> {
    fn drop(&mut self) {
        self.tr.zeroize();
    }
}

impl<P> SigningKey<P>
where
    P: SilithiumParams,
    AffinePoint<P::Curve>: ToSec1Point<P::Curve> + FromSec1Point<P::Curve>,
    FieldBytesSize<P::Curve>: ModulusSize,
{
    /// Generate a fresh keypair from OS randomness.
    pub fn generate() -> Self {
        let sk1 = SecretKey::generate();
        let vk1 = sk1.public_key();

        let ml_dsa_key: ml_dsa::SigningKey<P::MlDsa> =
            Generate::generate_from_rng(&mut UnwrapErr(SysRng));

        let sk2 = ml_dsa_key.expanded_key().clone();
        let vk2 = ml_dsa_key.verifying_key();

        let tr = compute_tr::<P>(&vk1, &vk2);

        Self {
            sk1,
            vk1,
            sk2,
            vk2,
            tr,
        }
    }

    /// Generate a keypair deterministically from a 32-byte seed.
    ///
    /// ```text
    /// ec_seed    = SHAKE256("silithium-ec-key" || seed, scalar_size)
    /// mldsa_seed = SHAKE256("silithium-pq-key" || seed, 32)
    /// ```
    pub fn generate_from_seed(seed: &[u8; 32]) -> Self {
        let mut xof = shake::Shake256::default();

        xof.update(b"silithium-ec-key");
        xof.update(seed);

        let mut reader = xof.finalize_xof();
        let mut ec_bytes = vec![0u8; P::SCALAR_SIZE];

        reader.read(&mut ec_bytes);

        let scalar = P::scalar_from_bytes(&ec_bytes);

        let nz: NonZeroScalar<P::Curve> = Option::from(NonZeroScalar::<P::Curve>::new(scalar))
            .expect("silithium: ec_seed reduced to zero (p < 2^-256)");

        let sk1 = SecretKey::<P::Curve>::from(nz);
        let vk1 = sk1.public_key();

        let mut xof = shake::Shake256::default();

        xof.update(b"silithium-pq-key");
        xof.update(seed);

        let mut reader = xof.finalize_xof();
        let mut ml_seed = [0u8; 32];

        reader.read(&mut ml_seed);

        let ml_key = ml_dsa::SigningKey::<P::MlDsa>::from_seed(&ml_dsa::B32::from(ml_seed));
        let sk2 = ml_key.expanded_key().clone();
        let vk2 = ml_key.verifying_key();
        let tr = compute_tr::<P>(&vk1, &vk2);

        #[cfg(feature = "zeroize")]
        {
            ec_bytes.zeroize();
            ml_seed.zeroize();
        }

        Self {
            sk1,
            vk1,
            sk2,
            vk2,
            tr,
        }
    }

    /// Sign a message using the Silithium hybrid scheme (via fused Fiat–Shamir).
    pub fn sign(&self, msg: &[u8]) -> Signature<P> {
        let nonce = NonZeroScalar::<P::Curve>::generate();
        let r_point = (ProjectivePoint::<P::Curve>::generator() * nonce.as_ref()).to_affine();

        // µ = SHAKE256(tr || R || msg, 512)
        let r_enc = r_point.to_sec1_point(false);
        let r_bytes = &r_enc.as_bytes()[1..]; // X || Y brut

        let mut xof = shake::Shake256::default();

        xof.update(&self.tr);
        xof.update(r_bytes);
        xof.update(msg);

        let mut reader = xof.finalize_xof();
        let mut mu = [0u8; 64];

        reader.read(&mut mu);

        // (z, c̃, h) = ML-DSA.Sign_mu(sk2, µ)
        let ml_dsa_sig = self.sk2.sign_mu_deterministic(&Array::<u8, U64>::from(mu)); // mu: [u8; 64]

        // x = r + sk1 . c̃ mod n
        let sig_bytes = ml_dsa_sig.encode();

        let c_scalar = P::reduce_c_tilde(&sig_bytes[..P::LAMBDA]);

        let x = *nonce.as_ref() + *self.sk1.to_nonzero_scalar() * c_scalar;

        Signature {
            ml_dsa_sig,
            sigma_ec: x,
        }
    }

    /// Access the precomputed `tr` value.
    pub fn tr(&self) -> &[u8; 64] {
        &self.tr
    }
}

impl<P> Keypair for SigningKey<P>
where
    P: SilithiumParams + Clone,
    AffinePoint<P::Curve>: ToSec1Point<P::Curve> + FromSec1Point<P::Curve>,
    FieldBytesSize<P::Curve>: ModulusSize,
{
    type VerifyingKey = VerifyingKey<P>;

    /// Derive the corresponding [`VerifyingKey`].
    fn verifying_key(&self) -> Self::VerifyingKey {
        VerifyingKey {
            vk1: self.vk1,
            vk2: self.vk2.clone(),
            tr: self.tr,
        }
    }
}

/// Silithium verifying key containing both EC and ML-DSA public components.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifyingKey<P: SilithiumParams> {
    /// EC-Schnorr public key
    vk1: PublicKey<P::Curve>,
    /// ML-DSA verifying key
    vk2: ml_dsa::VerifyingKey<P::MlDsa>,
    /// Precomputed tr = SHAKE256(vk1 || vk2, 512)
    tr: [u8; 64],
}

impl<P> VerifyingKey<P>
where
    P: SilithiumParams,
    AffinePoint<P::Curve>: ToSec1Point<P::Curve> + FromSec1Point<P::Curve>,
    FieldBytesSize<P::Curve>: ModulusSize,
{
    /// Encode: `ec_compressed || mldsa_vk`.
    pub fn encode(&self) -> Vec<u8> {
        let ec = self.vk1.to_sec1_point(true);
        let ml = self.vk2.encode();

        let mut out = Vec::with_capacity(ec.as_bytes().len() + ml.len());

        out.extend_from_slice(ec.as_bytes());
        out.extend_from_slice(&ml);

        out
    }

    /// Decode from `ec_compressed || mldsa_vk`.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != P::VERIFYING_KEY_SIZE {
            return Err(Error::InvalidLength);
        }

        let (ec_raw, ml_raw) = bytes.split_at(P::EC_COMPRESSED_SIZE);

        let vk1 =
            PublicKey::<P::Curve>::from_sec1_bytes(ec_raw).map_err(|_| Error::InvalidPublicKey)?;

        let mut ml_buf = ml_dsa::EncodedVerifyingKey::<P::MlDsa>::default();

        ml_buf.copy_from_slice(ml_raw);

        let vk2 = ml_dsa::VerifyingKey::<P::MlDsa>::decode(&ml_buf);

        let tr = compute_tr::<P>(&vk1, &vk2);

        Ok(Self { vk1, vk2, tr })
    }

    /// Verify a Silithium signature against a message.
    pub fn verify(&self, msg: &[u8], sig: &Signature<P>) -> Result<(), Error> {
        // R = x*G - c*vk1
        let c_tilde = sig.c_tilde();
        let c_scalar = P::reduce_c_tilde(&c_tilde);

        let r_prime = (ProjectivePoint::<P::Curve>::generator() * sig.sigma_ec
            - self.vk1.to_projective() * c_scalar)
            .to_affine();

        // µ = H(tr || R || M)
        let r_enc = r_prime.to_sec1_point(false);
        let r_raw = &r_enc.as_bytes()[1..];

        let mut xof = shake::Shake256::default();

        xof.update(&self.tr);
        xof.update(r_raw);
        xof.update(msg);

        let mut reader = xof.finalize_xof();
        let mut mu = [0u8; 64];

        reader.read(&mut mu);

        // ML-DSA.Verify_mu(vk2, µ, sig)
        if self
            .vk2
            .verify_mu(&Array::<u8, U64>::from(mu), &sig.ml_dsa_sig)
        {
            Ok(())
        } else {
            Err(Error::VerificationFailed)
        }
    }

    /// Access the EC public key.
    pub fn ec_key(&self) -> &PublicKey<P::Curve> {
        &self.vk1
    }

    /// Access the ML-DSA verifying key.
    pub fn ml_dsa_key(&self) -> &ml_dsa::VerifyingKey<P::MlDsa> {
        &self.vk2
    }

    /// Access the precomputed `tr` value.
    pub fn tr(&self) -> &[u8; 64] {
        &self.tr
    }
}

/// Silithium signature: the ML-DSA signature (containing c̃, z, h) plus
/// the Schnorr response scalar x.
#[derive(Debug, PartialEq)]
pub struct Signature<P: SilithiumParams> {
    /// Full ML-DSA signature (c̃ || z || h in encoded form)
    ml_dsa_sig: ml_dsa::Signature<P::MlDsa>,
    /// Schnorr response: x = r + sk1 . c̃ mod n
    sigma_ec: Scalar<P::Curve>,
}

impl<P: SilithiumParams> Signature<P> {
    /// Encode: `mldsa_sig || ec_scalar`.
    pub fn encode(&self) -> Vec<u8> {
        let ml = self.ml_dsa_sig.encode();
        let ec = self.sigma_ec.to_repr();

        let mut out = Vec::with_capacity(ml.len() + ec.len());

        out.extend_from_slice(&ml);
        out.extend_from_slice(ec.as_ref());

        out
    }

    /// Decode from `mldsa_sig || ec_scalar`.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != P::SIGNATURE_SIZE {
            return Err(Error::InvalidLength);
        }

        let (ml_raw, ec_raw) = bytes.split_at(P::MLDSA_SIG_SIZE);

        let mut ml_buf = ml_dsa::EncodedSignature::<P::MlDsa>::default();

        ml_buf.copy_from_slice(ml_raw);

        let ml_dsa_sig =
            ml_dsa::Signature::<P::MlDsa>::decode(&ml_buf).ok_or(Error::InvalidSignature)?;

        let ec_repr = elliptic_curve::FieldBytes::<P::Curve>::try_from(ec_raw)
            .map_err(|_| Error::InvalidLength)?;
        let sigma_ec =
            Option::from(Scalar::<P::Curve>::from_repr(ec_repr)).ok_or(Error::InvalidSignature)?;

        Ok(Self {
            ml_dsa_sig,
            sigma_ec,
        })
    }

    /// Access the ML-DSA signature component.
    pub fn ml_dsa_sig(&self) -> &ml_dsa::Signature<P::MlDsa> {
        &self.ml_dsa_sig
    }

    /// Access the Schnorr response scalar.
    pub fn x(&self) -> &Scalar<P::Curve> {
        &self.sigma_ec
    }

    /// Extract `c_tilde` from the encoded ML-DSA signature.
    /// Per FIPS 204, the signature encoding is c̃ || z || h,
    /// so the first Lambda bytes (32 for MlDsa44) are c̃.
    pub(crate) fn c_tilde(&self) -> Vec<u8> {
        use signature::SignatureEncoding;

        let bytes = <ml_dsa::Signature<P::MlDsa>>::to_bytes(&self.ml_dsa_sig);

        bytes[..P::LAMBDA].to_vec()
    }
}

/// Compute tr = SHAKE256(vk1_uncompressed || vk2_encoded, 512 bits).
fn compute_tr<P>(vk1: &PublicKey<P::Curve>, vk2: &ml_dsa::VerifyingKey<P::MlDsa>) -> [u8; 64]
where
    P: SilithiumParams,
    AffinePoint<P::Curve>: ToSec1Point<P::Curve> + FromSec1Point<P::Curve>,
    FieldBytesSize<P::Curve>: ModulusSize,
{
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
    macro_rules! silithium_tests {
        ($name:ident, $params:ty) => {
            mod $name {
                use super::super::*;
                use alloc::vec;

                #[test]
                fn sign_verify() {
                    let sk = SigningKey::<$params>::generate();
                    let vk = sk.verifying_key();
                    let sig = sk.sign(b"hello silithium");
                    assert!(vk.verify(b"hello silithium", &sig).is_ok());
                }

                #[test]
                fn wrong_message() {
                    let sk = SigningKey::<$params>::generate();
                    let vk = sk.verifying_key();
                    let sig = sk.sign(b"correct");
                    assert_eq!(vk.verify(b"wrong", &sig), Err(Error::VerificationFailed));
                }

                #[test]
                fn wrong_key() {
                    let sk1 = SigningKey::<$params>::generate();
                    let sk2 = SigningKey::<$params>::generate();
                    let sig = sk1.sign(b"test");
                    assert!(sk2.verifying_key().verify(b"test", &sig).is_err());
                }

                #[test]
                fn empty_message() {
                    let sk = SigningKey::<$params>::generate();
                    let vk = sk.verifying_key();
                    let sig = sk.sign(b"");
                    assert!(vk.verify(b"", &sig).is_ok());
                }

                #[test]
                fn large_message() {
                    let sk = SigningKey::<$params>::generate();
                    let vk = sk.verifying_key();
                    let msg = vec![0xABu8; 10_000];
                    let sig = sk.sign(&msg);
                    assert!(vk.verify(&msg, &sig).is_ok());
                }

                #[test]
                fn nonce_randomness() {
                    let sk = SigningKey::<$params>::generate();
                    let sig1 = sk.sign(b"same");
                    let sig2 = sk.sign(b"same");
                    assert_ne!(sig1.sigma_ec, sig2.sigma_ec);
                }

                #[test]
                fn tr_consistency() {
                    let sk = SigningKey::<$params>::generate();
                    let vk = sk.verifying_key();
                    assert_eq!(sk.tr(), vk.tr());
                }

                #[test]
                fn seed_deterministic() {
                    let seed = [0x42u8; 32];
                    let sk1 = SigningKey::<$params>::generate_from_seed(&seed);
                    let sk2 = SigningKey::<$params>::generate_from_seed(&seed);
                    assert_eq!(sk1.verifying_key().encode(), sk2.verifying_key().encode());
                }

                #[test]
                fn seed_sign_verify() {
                    let sk = SigningKey::<$params>::generate_from_seed(&[0x42u8; 32]);
                    let vk = sk.verifying_key();
                    let sig = sk.sign(b"seeded");
                    assert!(vk.verify(b"seeded", &sig).is_ok());
                }

                #[test]
                fn different_seeds() {
                    let sk1 = SigningKey::<$params>::generate_from_seed(&[0u8; 32]);
                    let sk2 = SigningKey::<$params>::generate_from_seed(&[1u8; 32]);
                    assert_ne!(sk1.verifying_key().encode(), sk2.verifying_key().encode());
                }

                #[test]
                fn vk_encode_size() {
                    let sk = SigningKey::<$params>::generate();
                    assert_eq!(
                        sk.verifying_key().encode().len(),
                        <$params>::VERIFYING_KEY_SIZE
                    );
                }

                #[test]
                fn sig_encode_size() {
                    let sk = SigningKey::<$params>::generate();
                    assert_eq!(sk.sign(b"sz").encode().len(), <$params>::SIGNATURE_SIZE);
                }

                #[test]
                fn vk_roundtrip() {
                    let sk = SigningKey::<$params>::generate();
                    let vk = sk.verifying_key();
                    let bytes = vk.encode();
                    let vk2 = VerifyingKey::<$params>::decode(&bytes).unwrap();
                    assert_eq!(vk.encode(), vk2.encode());
                }

                #[test]
                fn sig_roundtrip() {
                    let sk = SigningKey::<$params>::generate();
                    let sig = sk.sign(b"rt");
                    let bytes = sig.encode();
                    let sig2 = Signature::<$params>::decode(&bytes).unwrap();
                    assert_eq!(sig.encode(), sig2.encode());
                }

                #[test]
                fn verify_after_deserialization() {
                    let sk = SigningKey::<$params>::generate();
                    let vk = sk.verifying_key();
                    let msg = b"deser";

                    let sig_bytes = sk.sign(msg).encode();
                    let vk_bytes = vk.encode();

                    let vk2 = VerifyingKey::<$params>::decode(&vk_bytes).unwrap();
                    let sig2 = Signature::<$params>::decode(&sig_bytes).unwrap();
                    assert!(vk2.verify(msg, &sig2).is_ok());
                }

                #[test]
                fn vk_decode_bad_length() {
                    assert_eq!(
                        VerifyingKey::<$params>::decode(&[0; 3]),
                        Err(Error::InvalidLength)
                    );
                }

                #[test]
                fn sig_decode_bad_length() {
                    assert_eq!(
                        Signature::<$params>::decode(&[0; 3]),
                        Err(Error::InvalidLength)
                    );
                }

                #[test]
                fn vk_decode_garbage() {
                    let garbage = vec![0xFFu8; <$params>::VERIFYING_KEY_SIZE];
                    assert!(VerifyingKey::<$params>::decode(&garbage).is_err());
                }

                #[test]
                fn keypair_trait() {
                    let sk = SigningKey::<$params>::generate();
                    let vk: VerifyingKey<$params> = Keypair::verifying_key(&sk);
                    let sig = sk.sign(b"kp");
                    assert!(vk.verify(b"kp", &sig).is_ok());
                }

                #[cfg(feature = "zeroize")]
                #[test]
                fn drop_no_panic() {
                    drop(SigningKey::<$params>::generate());
                }
            }
        };
    }

    silithium_tests!(silithium44, Silithium44);
    silithium_tests!(silithium65, Silithium65);
    silithium_tests!(silithium87, Silithium87);
}
