// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg(feature = "std")]
use dusk_bls12_381::BlsScalar;
use schnorr::single_key::{PublicKey, SecretKey};

#[test]
// TestSignVerify
fn sign_verify() {
    let sk = SecretKey::new(&mut rand::thread_rng());
    let message = BlsScalar::random(&mut rand::thread_rng());
    let pk = PublicKey::from(&sk);

    let sig = sk.sign(&mut rand::thread_rng(), message);
    let b = sig.verify(&pk, message);

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
    let pk = PublicKey::from(&wrong_sk);
    let b = sig.verify(&pk, message);

    assert!(b.is_err());
}

#[test]
fn to_from_bytes() {
    let sk = SecretKey::new(&mut rand::thread_rng());
    assert_eq!(sk, SecretKey::from_bytes(&sk.to_bytes()).unwrap());
    let message = BlsScalar::random(&mut rand::thread_rng());
    let pk = PublicKey::from(&sk);
    assert_eq!(pk, PublicKey::from_bytes(&pk.to_bytes()).unwrap());
    let sig = sk.sign(&mut rand::thread_rng(), message);
    use schnorr::single_key::Signature;
    assert_eq!(sig, Signature::from_bytes(&sig.to_bytes()).unwrap());
}
