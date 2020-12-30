// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![allow(non_snake_case)]

#[allow(unused_imports)]
use crate::error::Error;
#[cfg(feature = "canon")]
use canonical::Canon;
#[cfg(feature = "canon")]
use canonical_derive::Canon;
#[allow(unused_imports)]
use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{
    JubJubExtended, JubJubScalar, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED,
};
#[cfg(feature = "std")]
use poseidon252::sponge::sponge::sponge_hash;
use rand::Rng;
use rand_core::CryptoRng;
#[cfg(feature = "std")]
use rand_core::RngCore;

/// Method to create a challenge hash for signature scheme
#[cfg(feature = "std")]
pub fn challenge_hash(
    R: JubJubExtended,
    R_prime: JubJubExtended,
    message: BlsScalar,
) -> JubJubScalar {
    let h = sponge_hash(&[message]);
    let R_scalar = R.to_hash_inputs();
    let R_prime_scalar = R_prime.to_hash_inputs();

    let c_hash = sponge_hash(&[
        R_scalar[0],
        R_scalar[1],
        R_prime_scalar[0],
        R_prime_scalar[1],
        h,
    ]);

    // NOTE: 251 is used, instead of 252, as truncating to even numbers allow us
    // to align with the perform bitwise operations in circuit.
    let c_hash = c_hash & BlsScalar::pow_of_2(251).sub(&BlsScalar::one());

    // NOTE: This should never fail as we are truncating the BLS scalar
    // to be less than the JubJub modulus.
    Option::from(JubJubScalar::from_bytes(&c_hash.to_bytes()))
        .expect("Failed to truncate BlsScalar")
}

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "canon", derive(Canon))]
pub struct SecretKey(JubJubScalar);

impl From<JubJubScalar> for SecretKey {
    fn from(s: JubJubScalar) -> SecretKey {
        SecretKey(s)
    }
}

impl From<&JubJubScalar> for SecretKey {
    fn from(s: &JubJubScalar) -> SecretKey {
        SecretKey(*s)
    }
}

impl AsRef<JubJubScalar> for SecretKey {
    fn as_ref(&self) -> &JubJubScalar {
        &self.0
    }
}

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

    // Signs a chosen message with a given secret key
    // using the dusk variant of the Schnorr signature scheme.
    #[cfg(feature = "std")]
    pub fn sign<R>(&self, rng: &mut R, message: BlsScalar) -> Signature
    where
        R: RngCore + CryptoRng,
    {
        // Create random scalar value for scheme, r
        let r = JubJubScalar::random(rng);

        // Derive two points from r, to sign with the message
        // R = r * G
        // R_prime = r * G_NUM
        let R = GENERATOR_EXTENDED * r;
        let R_prime = GENERATOR_NUMS_EXTENDED * r;

        // Compute challenge value, c = H(R||R_prime||H(m));
        let c = challenge_hash(R, R_prime, message);

        // Compute scalar signature, U = r - c * sk,
        let U = r - (c * self.0);

        Signature { U, R, R_prime }
    }
}

#[derive(Debug, Default, Copy, Clone, PartialEq)]
#[cfg_attr(feature = "canon", derive(Canon))]
pub struct PublicKeyPair {
    public_key: JubJubExtended,
    public_key_prime: JubJubExtended,
}

impl From<&SecretKey> for PublicKeyPair {
    fn from(sk: &SecretKey) -> Self {
        let public_key = GENERATOR_EXTENDED * sk.0;
        let public_key_prime = GENERATOR_NUMS_EXTENDED * sk.0;

        PublicKeyPair {
            public_key,
            public_key_prime,
        }
    }
}

/// An Schnorr signature, produced by signing a message with a
/// [`SecretKey`].

#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "canon", derive(Canon))]
pub struct Signature {
    U: JubJubScalar,
    R: JubJubExtended,
    R_prime: JubJubExtended,
}

impl Signature {
    #[allow(non_snake_case)]
    pub fn U(&self) -> &JubJubScalar {
        &self.U
    }

    #[allow(non_snake_case)]
    pub fn R(&self) -> &JubJubExtended {
        &self.R
    }

    #[allow(non_snake_case)]
    pub fn R_prime(&self) -> &JubJubExtended {
        &self.R_prime
    }

    /// Function to verify that two given point in a Schnorr signature
    /// have the same DLP
    #[cfg(feature = "std")]
    pub fn verify(
        &self,
        public_key_pair: &PublicKeyPair,
        message: BlsScalar,
    ) -> Result<(), Error> {
        // Compute challenge value, c = H(R||R_prime||H(m));
        let c = challenge_hash(self.R, self.R_prime, message);

        // Compute verification steps
        // u * G + c * public_key
        let point_1 =
            (GENERATOR_EXTENDED * self.U) + (public_key_pair.public_key * c);
        // u * G_nums + c * public_key_prime
        let point_2 = (GENERATOR_NUMS_EXTENDED * self.U)
            + (public_key_pair.public_key_prime * c);

        match point_1.eq(&self.R) && point_2.eq(&self.R_prime) {
            true => Ok(()),
            false => Err(Error::InvalidSignature),
        }
    }
}
