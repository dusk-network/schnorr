// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;
use dusk_schnorr::{NotePublicKeyPair, NoteSecretKey};
use rand::rngs::StdRng;
use rand::SeedableRng;

#[test]
fn signature_verify() {
    let mut rng = StdRng::seed_from_u64(2321u64);

    let sk = NoteSecretKey::random(&mut rng);
    let message = BlsScalar::uni_random(&mut rng);
    let pk_pair: NotePublicKeyPair = sk.into();

    let sig = sk.sign_double(&mut rng, message);

    assert!(sig.verify(&pk_pair, message));
}

#[test]
fn test_wrong_keys() {
    let mut rng = StdRng::seed_from_u64(2321u64);

    let sk = NoteSecretKey::random(&mut rng);
    let message = BlsScalar::uni_random(&mut rng);

    let sig = sk.sign_double(&mut rng, message);

    // Derive random public key
    let wrong_sk = NoteSecretKey::random(&mut rng);
    let pk_pair: NotePublicKeyPair = wrong_sk.into();

    assert!(!sig.verify(&pk_pair, message));
}
