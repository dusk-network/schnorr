// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::error::Error;
use dusk_plonk::bls12_381::Scalar as BlsScalar;
use dusk_plonk::jubjub::{
    ExtendedPoint, Fr as JubJubScalar, GENERATOR_EXTENDED,
    GENERATOR_NUMS_EXTENDED,
};
use poseidon252::sponge::sponge::sponge_hash;
use rand::Rng;
use rand_core::{CryptoRng, RngCore};

/// Method to create a challenge hash for signature scheme
#[allow(non_snake_case)]
pub fn challenge_hash(
    R: ExtendedPoint,
    R_prime: ExtendedPoint,
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
pub struct SecretKey(JubJubScalar);

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
    #[allow(non_snake_case)]
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
pub struct PublicKeyPair {
    public_key: ExtendedPoint,
    public_key_prime: ExtendedPoint,
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
#[allow(non_snake_case)]
#[derive(Clone, Copy, Debug)]
pub struct Signature {
    U: JubJubScalar,
    R: ExtendedPoint,
    R_prime: ExtendedPoint,
}

impl Signature {
    /// Function to verify that two given point in a Schnorr signature
    /// have the same DLP
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