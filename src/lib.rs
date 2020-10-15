// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

mod error;

use crate::error::Error;
use dusk_bls12_381::Scalar;
use dusk_jubjub::{AffinePoint, ExtendedPoint, Fr, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use poseidon252::perm_uses::fixed_hash::two_outputs;
use poseidon252::sponge::sponge::sponge_hash;
use rand::{CryptoRng, Rng};
use std::io;
use std::io::{Read, Write};

#[derive(Default, Clone, Copy, Debug)]
pub struct Message(pub Scalar);


pub struct SecretKey(pub Fr);
impl SecretKey {
    /// This will create a new [`SecretKey`] from a scalar
    /// of the Field Fr.
    pub fn new<T>(rand: &mut T) -> SecretKey
    where
        T: Rng + CryptoRng,
    {
        let scalar = Fr::random(rand);

        SecretKey(scalar)
    }

    /// This will create a new [`PublicKeyPair`] from a given [`SecretKey`].
    pub fn to_public_key_pair(&self) -> PublicKeyPair {
        let pk = AffinePoint::from(GENERATOR_EXTENDED * self.0);
        let pk_prime = AffinePoint::from(GENERATOR_NUMS_EXTENDED * self.0);

        PublicKeyPair {
            public_key: pk,
            public_key_prime: pk_prime,
        }
    }

    pub fn sign(&self, message: &Message) -> (Signature, PublicKeyPair, Scalar) {
        /// Generate Key pair from secret key
        /// pk = sk * G
        /// pk_prime = sk * G_NUMS
        let pk_pair = self.to_public_key_pair();

        /// Create random scalar value for scheme, r
        let r = Fr::random(&mut rand::thread_rng());

        /// Derive two affine points from r, to sign with the message
        /// R = r * G
        /// R_prime = r * G_NUMS
        let R = AffinePoint::from(GENERATOR_EXTENDED * r);
        let R_prime = AffinePoint::from(GENERATOR_NUMS_EXTENDED * r);

        /// Hash the input message, H(m)
        let h = sponge_hash(&[message.0]);

        /// Compute challenge value, c = H(pk_r||pk_r_prime||h);
        let c = sponge_hash(&[
            h,
            pk_pair.public_key.get_x(),
            pk_pair.public_key.get_y(),
            pk_pair.public_key_prime.get_x(),
            pk_pair.public_key_prime.get_y(),
        ]);

        /// Convert r into a Bls Scalar for use in arithmetic
        /// operations
        let r_1 = Scalar::from(r);

        /// Compute scalar signature, u = r - c * sk,
        let u_a: Scalar = r_1 - (c * Scalar::from(self.0));
        let u = Fr::from_raw(*u_a.reduce().internal_repr());

        (
            Signature {
                U: u,
                R: R,
                R_prime: R_prime,
            },
            pk_pair,
            h,
        )
    }
}

pub struct PublicKeyPair {
    pub public_key: AffinePoint,
    pub public_key_prime: AffinePoint,
}

impl From<&SecretKey> for PublicKeyPair {
    fn from(sk: &SecretKey) -> Self {
        PublicKeyPair::from_secret(sk)
    }
}

impl PublicKeyPair {
    /// This will create a new ['PublicKeyPair'] from a ['SecretKey'].
    pub fn from_secret(secret: &SecretKey) -> PublicKeyPair {
        let secret = SecretKey::new(&mut rand::thread_rng());
        let pk = AffinePoint::from(GENERATOR_EXTENDED * secret.0);
        let pk_prime = AffinePoint::from(GENERATOR_NUMS_EXTENDED * &secret.0);
        PublicKeyPair {
            public_key: pk,
            public_key_prime: pk_prime,
        }
    }
}

/// An Schnorr signature, produced by signing a [`Message`] with a
/// [`SecretKey`].
#[allow(non_snake_case)]
#[derive(Clone, Copy, Debug)]
pub struct Signature {
    U: Fr,
    R: AffinePoint,
    R_prime: AffinePoint,
}

impl Signature {
    /// Function to verify that two given point in a Schnorr signature
    /// have the same DLP
    pub fn verify(&self, pk_pair: &PublicKeyPair, h: Scalar) -> Result<(), Error> {
        /// Compute challenge value, c = H(pk_r||pk_r_prime||h);
        let c = sponge_hash(&[
            h,
            pk_pair.public_key.get_x(),
            pk_pair.public_key.get_y(),
            pk_pair.public_key_prime.get_x(),
            pk_pair.public_key_prime.get_y(),
        ]);

        /// Compute verification steps
        /// u * G + c * pk
        let point_1 = AffinePoint::from(
            (GENERATOR_EXTENDED * self.U)
                + (ExtendedPoint::from(pk_pair.public_key)
                    * Fr::from_raw(*c.reduce().internal_repr())),
        );
        /// u * G + c * pk
        let point_2 = AffinePoint::from(
            (GENERATOR_NUMS_EXTENDED * self.U)
                + (ExtendedPoint::from(pk_pair.public_key_prime)
                * Fr::from_raw(*c.reduce().internal_repr())),
        );

        match point_1.eq(&self.R) && point_2.eq(&self.R_prime) {
            true => Ok(()),
            false => Err(Error::InvalidSignature),
        }
    }
}
