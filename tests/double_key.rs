// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;
use dusk_pki::SecretKey;
use dusk_schnorr::{Proof, PublicKeyPair};
use rand::rngs::StdRng;
use rand::SeedableRng;

#[test]
fn proof_verify() {
    let rng = &mut StdRng::seed_from_u64(2321u64);

    let sk = SecretKey::random(rng);
    let message = BlsScalar::random(rng);
    let pk_pair: PublicKeyPair = sk.into();

    let proof = Proof::new(&sk, rng, message);

    assert!(proof.verify(&pk_pair, message));
}

#[test]
fn test_wrong_keys() {
    let rng = &mut StdRng::seed_from_u64(2321u64);

    let sk = SecretKey::random(rng);
    let wrong_sk = SecretKey::random(rng);
    let message = BlsScalar::random(rng);

    let proof = Proof::new(&sk, rng, message);

    // Derive random public key
    let pk_pair: PublicKeyPair = wrong_sk.into();

    assert!(!proof.verify(&pk_pair, message));
}
