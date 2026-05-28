// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2026 Thomas <tom@unebaguette.fr>

//! Silithium: a compact, non-separable hybrid signature scheme combining
//! EC-Schnorr and ML-DSA via fused Fiat-Shamir.
//!
//! Reference: Devevey, Guerreau, Roméas - "Compact, Efficient and Non-Separable
//! Hybrid Signatures" (ePrint 2025/2059).

use elliptic_curve::CurveGroup;
use elliptic_curve::sec1::{FromSec1Point, ModulusSize};
use elliptic_curve::{
    AffinePoint, CurveArithmetic, FieldBytesSize, Group, NonZeroScalar, ProjectivePoint, PublicKey,
    Scalar, SecretKey,
};
use getrandom::{SysRng, rand_core::UnwrapErr};
use hybrid_array::Array;
use hybrid_array::typenum::U64;
use ml_dsa::Generate;
use ml_dsa::signature::Keypair;
use p256::elliptic_curve::ops::Reduce;
use p256::elliptic_curve::sec1::ToSec1Point;
use shake::digest::{ExtendableOutput, Update, XofReader};

pub trait SilithiumParams {
    type MlDsa: ml_dsa::MlDsaParams;
    type Curve: CurveArithmetic + elliptic_curve::PrimeCurve;

    /// Size of c_tilde in bytes (Lambda from ML-DSA parameter set)
    const LAMBDA: usize;

    /// Size of the EC scalar in bytes (signature overhead)
    const SCALAR_SIZE: usize;

    /// Reduce c_tilde bytes to a scalar on the curve
    fn reduce_c_tilde(c_tilde: &[u8]) -> Scalar<Self::Curve>;
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

/// Silithium verifying key containing both EC and ML-DSA public components.
#[derive(Clone, Debug)]
pub struct VerifyingKey<P: SilithiumParams> {
    /// EC-Schnorr public key
    vk1: PublicKey<P::Curve>,
    /// ML-DSA verifying key
    vk2: ml_dsa::VerifyingKey<P::MlDsa>,
    /// Precomputed tr = SHAKE256(vk1 || vk2, 512)
    tr: [u8; 64],
}

/// Silithium signature: the ML-DSA signature (containing c̃, z, h) plus
/// the Schnorr response scalar x.
pub struct Signature<P: SilithiumParams> {
    /// Full ML-DSA signature (c̃ || z || h in encoded form)
    ml_dsa_sig: ml_dsa::Signature<P::MlDsa>,
    /// Schnorr response: x = r + sk1 . c̃ mod n
    sigma_ec: Scalar<P::Curve>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Silithium44;
impl SilithiumParams for Silithium44 {
    type MlDsa = ml_dsa::MlDsa44;
    type Curve = p256::NistP256;
    const LAMBDA: usize = 32;
    const SCALAR_SIZE: usize = 32;

    fn reduce_c_tilde(c_tilde: &[u8]) -> p256::Scalar {
        let uint = <p256::NistP256 as elliptic_curve::Curve>::Uint::from_be_slice(c_tilde);

        p256::Scalar::reduce(&uint)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Silithium65;
impl SilithiumParams for Silithium65 {
    type MlDsa = ml_dsa::MlDsa65;
    type Curve = p384::NistP384;
    const LAMBDA: usize = 48;
    const SCALAR_SIZE: usize = 48;

    fn reduce_c_tilde(c_tilde: &[u8]) -> p384::Scalar {
        let mut padded = [0u8; 48]; // FieldBytes size for P-384
        let offset = padded.len().saturating_sub(c_tilde.len());

        padded[offset..].copy_from_slice(c_tilde);

        let uint = <p384::NistP384 as elliptic_curve::Curve>::Uint::from_be_slice(&padded);

        p384::Scalar::reduce(&uint)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Silithium87;
impl SilithiumParams for Silithium87 {
    type MlDsa = ml_dsa::MlDsa87;
    type Curve = p521::NistP521;
    const LAMBDA: usize = 64;
    const SCALAR_SIZE: usize = 66;

    fn reduce_c_tilde(c_tilde: &[u8]) -> p521::Scalar {
        let mut padded = [0u8; 72]; // Uint size for P-521 (U576 = 72 bytes on 64-bit)
        let offset = padded.len().saturating_sub(c_tilde.len());

        padded[offset..].copy_from_slice(c_tilde);

        let uint = <p521::NistP521 as elliptic_curve::Curve>::Uint::from_be_slice(&padded);

        p521::Scalar::reduce(&uint)
    }
}

impl<P> SigningKey<P>
where
    P: SilithiumParams,
    AffinePoint<P::Curve>: ToSec1Point<P::Curve> + FromSec1Point<P::Curve>,
    FieldBytesSize<P::Curve>: ModulusSize,
{
    /// Generate a fresh Silithium-44 keypair.
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

    /// Sign a message using the Silithium hybrid scheme.
    pub fn sign(&self, msg: &[u8]) -> Signature<P> {
        let nonce = NonZeroScalar::<P::Curve>::generate();
        let generator = ProjectivePoint::<P::Curve>::generator();
        let nonce_point = (generator * nonce.as_ref()).to_affine();

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

        let c_tilde_bytes = &sig_bytes[..P::LAMBDA];
        let c_scalar = P::reduce_c_tilde(c_tilde_bytes);

        let sk1_scalar = *self.sk1.to_nonzero_scalar();

        let x = *nonce.as_ref() + sk1_scalar * c_scalar;

        Signature {
            ml_dsa_sig,
            sigma_ec: x,
        }
    }

    /// Derive the corresponding [`VerifyingKey`].
    pub fn verifying_key(&self) -> VerifyingKey<P> {
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

impl<P> VerifyingKey<P>
where
    P: SilithiumParams,
    AffinePoint<P::Curve>: ToSec1Point<P::Curve> + FromSec1Point<P::Curve>,
    FieldBytesSize<P::Curve>: ModulusSize,
{
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

    /// Verify a Silithium signature against a message.
    pub fn verify(&self, msg: &[u8], sig: &Signature<P>) -> bool {
        // R = x*G - c*vk1
        let c_tilde = sig.c_tilde();
        let c_scalar = P::reduce_c_tilde(&c_tilde);

        let generator = ProjectivePoint::<P::Curve>::generator();

        let vk1_point = self.vk1.to_projective();
        let r_point = (generator * sig.sigma_ec - vk1_point * c_scalar).to_affine();

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

impl<P: SilithiumParams> Signature<P> {
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
    pub fn c_tilde(&self) -> Vec<u8> {
        use ml_dsa::signature::SignatureEncoding;

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

                #[test]
                fn sign_verify_roundtrip() {
                    let sk = SigningKey::<$params>::generate();
                    let vk = sk.verifying_key();
                    let msg = b"hello silithium";

                    let sig = sk.sign(msg);
                    assert!(vk.verify(msg, &sig));
                }

                #[test]
                fn verify_rejects_wrong_message() {
                    let sk = SigningKey::<$params>::generate();
                    let vk = sk.verifying_key();

                    let sig = sk.sign(b"correct message");
                    assert!(!vk.verify(b"wrong message", &sig));
                }

                #[test]
                fn verify_rejects_wrong_key() {
                    let sk1 = SigningKey::<$params>::generate();
                    let sk2 = SigningKey::<$params>::generate();
                    let msg = b"test";

                    let sig = sk1.sign(msg);
                    assert!(!sk2.verifying_key().verify(msg, &sig));
                }

                #[test]
                fn sign_empty_message() {
                    let sk = SigningKey::<$params>::generate();
                    let vk = sk.verifying_key();

                    let sig = sk.sign(b"");
                    assert!(vk.verify(b"", &sig));
                }

                #[test]
                fn sign_large_message() {
                    let sk = SigningKey::<$params>::generate();
                    let vk = sk.verifying_key();
                    let msg = vec![0xABu8; 10_000];

                    let sig = sk.sign(&msg);
                    assert!(vk.verify(&msg, &sig));
                }

                #[test]
                fn two_signatures_differ() {
                    let sk = SigningKey::<$params>::generate();
                    let msg = b"same message";

                    let sig1 = sk.sign(msg);
                    let sig2 = sk.sign(msg);

                    assert_ne!(sig1.sigma_ec, sig2.sigma_ec);
                }

                #[test]
                fn verifying_key_tr_matches_signing_key() {
                    let sk = SigningKey::<$params>::generate();
                    let vk = sk.verifying_key();

                    assert_eq!(sk.tr(), vk.tr());
                }
            }
        };
    }

    silithium_tests!(silithium44, Silithium44);
    silithium_tests!(silithium65, Silithium65);
    silithium_tests!(silithium87, Silithium87);
}
