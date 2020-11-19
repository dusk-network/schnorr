// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg(feature = "std")]
use dusk_bls12_381::BlsScalar;
use schnorr::double_key::{PublicKeyPair, SecretKey};

#[test]
// TestSignVerify
fn sign_verify() {
    let sk = SecretKey::new(&mut rand::thread_rng());
    let message = BlsScalar::random(&mut rand::thread_rng());
    let pk_pair = PublicKeyPair::from(&sk);

    let sig = sk.sign(&mut rand::thread_rng(), message);
    let b = sig.verify(&pk_pair, message);

    assert!(b.is_ok());
}

#[test]
// Test to see failure with random Public Key
fn test_wrong_keys() {
    let sk = SecretKey::new(&mut rand::thread_rng());
    let wrong_sk = SecretKey::new(&mut rand::thread_rng());
    let message = BlsScalar::random(&mut rand::thread_rng());

    let sig = sk.sign(&mut rand::thread_rng(), message);

    // Derive random public key
    let pk_pair = PublicKeyPair::from(&wrong_sk);
    let b = sig.verify(&pk_pair, message);

    assert!(b.is_err());
}
