// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::Scalar;

#[cfg(test)]
mod integrations {
    use super::*;
    use Schnorr::{SecretKey, PublicKeyPair, Message};

    #[test]
    // TestSignVerify
    fn sign_verify() {
        let secret = SecretKey::new(&mut rand::thread_rng());
        let message = Message(Scalar::random(&mut rand::thread_rng()));

        let (sig, pk_pair, h) = secret.sign(&message);
        let b = sig.verify(&pk_pair, h);

        assert!(b.is_ok());
    }
}

    // #[test]
    // // Test to see failure with wrong Public Key
    // fn test_wrong_keys() {
    //     let keypair = KeyPair::new(&mut rand::thread_rng()).unwrap();
    //     let mut rng = rand::thread_rng();
    //
    //     let message = Message(Scalar::random(&mut rng));
    //
    //     let a = keypair.sign(&message);
    //     let b = a.verify(&message, &PublicKey::new(&mut rand::thread_rng()).unwrap());
    //
    //     assert!(b.is_err());
    // }

