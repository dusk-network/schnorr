// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::error::Error;
use dusk_plonk::bls12_381::Scalar as BlsScalar;
use dusk_plonk::jubjub::{
    ExtendedPoint, Fr as JubJubScalar, GENERATOR_EXTENDED,
};
use poseidon252::sponge::sponge::sponge_hash;
use rand::Rng;
use rand_core::{CryptoRng, RngCore};

/// Method to create a challenge hash for signature scheme
#[allow(non_snake_case)]
pub fn challenge_hash(R: ExtendedPoint, message: BlsScalar) -> JubJubScalar {
    let h = sponge_hash(&[message]);
    let R_scalar = R.to_hash_inputs();

    let c_hash = sponge_hash(&[R_scalar[0], R_scalar[1], h]);

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

        // Derive a points from r, to sign with the message
        // R = r * G
        let R = GENERATOR_EXTENDED * r;

        // Compute challenge value, c = H(R||H(m));
        let c = challenge_hash(R, message);

        // Compute scalar signature, U = r - c * sk,
        let U = r - (c * self.0);

        Signature { U, R }
    }
}

#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub struct PublicKey(ExtendedPoint);

impl From<&SecretKey> for PublicKey {
    fn from(sk: &SecretKey) -> Self {
        let public_key = GENERATOR_EXTENDED * sk.0;

        PublicKey(public_key)
    }
}

/// An Schnorr signature, produced by signing a message with a
/// [`SecretKey`].
#[allow(non_snake_case)]
#[derive(Clone, Copy, Debug)]
pub struct Signature {
    U: JubJubScalar,
    R: ExtendedPoint,
}

impl Signature {
    /// Function to verify that a given point in a Schnorr signature
    /// have the same DLP
    pub fn verify(
        &self,
        public_key: &PublicKey,
        message: BlsScalar,
    ) -> Result<(), Error> {
        // Compute challenge value, c = H(R||H(m));
        let c = challenge_hash(self.R, message);

        // Compute verification steps
        // u * G + c * public_key
        let point_1 = (GENERATOR_EXTENDED * self.U) + (public_key.0 * c);

        match point_1.eq(&self.R) {
            true => Ok(()),
            false => Err(Error::InvalidSignature),
        }
    }
}