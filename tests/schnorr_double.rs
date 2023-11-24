// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;
use dusk_bytes::Serializable;
use dusk_schnorr::{PublicKeyDouble, SecretKey, SignatureDouble};
use ff::Field;
use rand::rngs::StdRng;
use rand::SeedableRng;

#[test]
fn sign_verify() {
    let mut rng = StdRng::seed_from_u64(2321u64);

    let sk = SecretKey::random(&mut rng);
    let message = BlsScalar::random(&mut rng);
    let pk_double: PublicKeyDouble = sk.into();

    let sig = sk.sign_double(&mut rng, message);

    assert!(sig.verify(&pk_double, message));
}

#[test]
fn test_wrong_keys() {
    let mut rng = StdRng::seed_from_u64(2321u64);

    let sk = SecretKey::random(&mut rng);
    let message = BlsScalar::random(&mut rng);

    let sig = sk.sign_double(&mut rng, message);

    // Derive random public key
    let wrong_sk = SecretKey::random(&mut rng);
    let pk_double: PublicKeyDouble = wrong_sk.into();

    assert!(!sig.verify(&pk_double, message));
}

#[test]
fn to_from_bytes() {
    let mut rng = StdRng::seed_from_u64(2321u64);

    let sk = SecretKey::random(&mut rng);
    let message = BlsScalar::random(&mut rng);

    let sig = sk.sign_double(&mut rng, message);
    assert_eq!(sig, SignatureDouble::from_bytes(&sig.to_bytes()).unwrap());
}
