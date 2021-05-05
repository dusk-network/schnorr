// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bytes::Serializable;
use dusk_pki::{PublicKey, SecretKey};
use dusk_plonk::bls12_381::BlsScalar;
use schnorr::Signature;

#[test]
// TestSignVerify
fn sign_verify() {
    let sk = SecretKey::random(&mut rand::thread_rng());
    let message = BlsScalar::random(&mut rand::thread_rng());
    let pk = PublicKey::from(&sk);

    let sig = Signature::new(&sk, &mut rand::thread_rng(), message);

    assert!(sig.verify(&pk, message));
}

#[test]
// Test to see failure with random Public Key
fn test_wrong_keys() {
    let sk = SecretKey::random(&mut rand::thread_rng());
    let wrong_sk = SecretKey::random(&mut rand::thread_rng());
    let message = BlsScalar::random(&mut rand::thread_rng());

    let sig = Signature::new(&sk, &mut rand::thread_rng(), message);

    // Derive random public key
    let pk = PublicKey::from(&wrong_sk);

    assert!(!sig.verify(&pk, message));
}

#[test]
fn to_from_bytes() {
    let sk = SecretKey::random(&mut rand::thread_rng());
    let message = BlsScalar::random(&mut rand::thread_rng());

    let sig = Signature::new(&sk, &mut rand::thread_rng(), message);
    assert_eq!(sig, Signature::from_bytes(&sig.to_bytes()).unwrap());
}
