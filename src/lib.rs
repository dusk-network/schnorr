// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

mod error;

use crate::error::Error;
use dusk_bls12_381::Scalar as BlsScalar;
use dusk_jubjub::{
    AffinePoint, ExtendedPoint, Fr as JubJubScalar, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED,
};
use poseidon252::perm_uses::fixed_hash::two_outputs;
use poseidon252::sponge::sponge::sponge_hash;
use rand::{CryptoRng, Rng};
use std::io;
use std::io::{Read, Write};

#[derive(Default, Clone, Copy, Debug)]
pub struct Message(pub BlsScalar);

pub struct SecretKey(pub JubJubScalar);
impl SecretKey {
    /// This will create a new [`SecretKey`] from a scalar
    /// of the Field JubJubScalar.
    pub fn new<T>(rand: &mut T) -> SecretKey
    where
        T: Rng + CryptoRng,
    {
        let fr = JubJubScalar::random(rand);

        SecretKey(fr)
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

    pub fn sign(&self, message: &Message) -> (Signature, PublicKeyPair, BlsScalar) {
        /// Generate Key pair from secret key
        /// pk = sk * G
        /// pk_prime = sk * G_NUMS
        let pk_pair = self.to_public_key_pair();

        /// Create random scalar value for scheme, r
        let r = JubJubScalar::random(&mut rand::thread_rng());

        /// Derive two affine points from r, to sign with the message
        /// R = r * G
        /// R_prime = r * G_NUM
        let R = AffinePoint::from(GENERATOR_EXTENDED * r);
        let R_prime = AffinePoint::from(GENERATOR_NUMS_EXTENDED * r);

        /// Hash the input message, H(m)
        let h = sponge_hash(&[message.0]);

        /// Compute challenge value, c = H(pk_r||pk_r_prime||h);
        let c = sponge_hash(&[R.get_x(), R.get_y(), R_prime.get_x(), R_prime.get_y(), h]);
        let c = JubJubScalar::from_raw(*c.reduce().internal_repr());

        /// Convert r into a Bls Scalar for use in arithmetic
        /// operations

        /// Compute scalar signature, u = r - c * sk,
        let u = r - (c * self.0);
        //        let u = JubJubScalar::from_raw(*u_a.reduce().internal_repr());

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
    pub U: JubJubScalar,
    pub R: AffinePoint,
    pub R_prime: AffinePoint,
}

impl Signature {
    /// Function to verify that two given point in a Schnorr signature
    /// have the same DLP
    pub fn verify(&self, pk_pair: &PublicKeyPair, h: BlsScalar) -> Result<(), Error> {
        /// Compute challenge value, c = H(pk_r||pk_r_prime||h);
        let c = sponge_hash(&[
            self.R.get_x(),
            self.R.get_y(),
            self.R_prime.get_x(),
            self.R_prime.get_y(),
            h,
        ]);

        let c = JubJubScalar::from_raw(*c.reduce().internal_repr());

        /// Compute verification steps
        /// u * G + c * pk
        let point_1 = AffinePoint::from(
            (GENERATOR_EXTENDED * self.U) + (ExtendedPoint::from(pk_pair.public_key) * c),
        );
        /// u * G_nums + c * pk_prime
        let point_2 = AffinePoint::from(
            (GENERATOR_NUMS_EXTENDED * self.U)
                + (ExtendedPoint::from(pk_pair.public_key_prime) * c),
        );

        match point_1.eq(&self.R) && point_2.eq(&self.R_prime) {
            true => Ok(()),
            false => Err(Error::InvalidSignature),
        }
    }
}
