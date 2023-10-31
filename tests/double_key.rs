// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;
use dusk_schnorr::{DoubleSignature, NoteSecretKey, PublicKeyPair};
use ff::Field;
use rand::rngs::StdRng;
use rand::SeedableRng;

#[test]
fn signature_verify() {
    let mut rng = StdRng::seed_from_u64(2321u64);

    let sk = NoteSecretKey::random(&mut rng);
    let message = BlsScalar::random(&mut rng);
    let pk_pair: PublicKeyPair = sk.into();

    let signature = DoubleSignature::new(&sk, &mut rng, message);

    assert!(signature.verify(&pk_pair, message));
}

#[test]
fn test_wrong_keys() {
    let mut rng = StdRng::seed_from_u64(2321u64);

    let sk = NoteSecretKey::random(&mut rng);
    let wrong_sk = NoteSecretKey::random(&mut rng);
    let message = BlsScalar::random(&mut rng);

    let signature = DoubleSignature::new(&sk, &mut rng, message);

    // Derive random public key
    let pk_pair: PublicKeyPair = wrong_sk.into();

    assert!(!signature.verify(&pk_pair, message));
}
