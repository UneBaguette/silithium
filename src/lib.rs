// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2026 Thomas <tom@unebaguette.fr>

use ml_dsa::Generate;
use getrandom::{SysRng, rand_core::UnwrapErr};
use ml_dsa::signature::Keypair;
use p256::elliptic_curve::sec1::ToSec1Point;
use shake::digest::{ExtendableOutput, Update, XofReader};

pub struct SigningKey {
    // EC-Schnorr
    sk1: p256::SecretKey,
    vk1: p256::PublicKey,
    // ML-DSA
    sk2: ml_dsa::ExpandedSigningKey<ml_dsa::MlDsa44>,
    vk2: ml_dsa::VerifyingKey<ml_dsa::MlDsa44>,
    // Precomputed
    tr: [u8; 64],
}

pub struct VerifyingKey {
    vk1: p256::PublicKey,
    vk2: ml_dsa::VerifyingKey<ml_dsa::MlDsa44>,
    tr: [u8; 64],
}

pub struct Signature {
    ml_dsa_sig: ml_dsa::Signature<ml_dsa::MlDsa44>,
    x: p256::Scalar,
}

pub fn generate_keypair() -> SigningKey {
    let sk1 = p256::SecretKey::generate();
    let vk1 = sk1.public_key();

    let key: ml_dsa::SigningKey<ml_dsa::MlDsa44> = Generate::generate_from_rng(&mut UnwrapErr(SysRng));

    let sk2= key.expanded_key().clone();
    let vk2 = key.verifying_key();

    let vk1_bytes = vk1.to_sec1_point(false);
    let vk2_bytes = vk2.encode();

    let vk1_result = vk1_bytes.as_bytes();

    let mut tr = shake::Shake256::default();

    tr.update(&vk1_result);
    tr.update(&vk2_bytes);

    let mut tr_reader = tr.finalize_xof();

    let mut tr = [0u8; 64];

    tr_reader.read(tr.as_mut());

    SigningKey {
        sk1,
        vk1,
        sk2,
        vk2,
        tr
    }
}
