// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::error::Error;
#[cfg(feature = "canon")]
use canonical::Canon;
#[cfg(feature = "canon")]
use canonical_derive::Canon;
use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{
    JubJubAffine, JubJubExtended, JubJubScalar, GENERATOR_EXTENDED,
};
use poseidon252::sponge::hash;
use rand_core::{CryptoRng, RngCore};

#[allow(non_snake_case)]
/// Method to create a challenge hash for signature scheme
pub fn challenge_hash(R: JubJubExtended, message: BlsScalar) -> JubJubScalar {
    let h = hash(&[message]);
    let R_scalar = R.to_hash_inputs();

    let c_hash = hash(&[R_scalar[0], R_scalar[1], h]);

    // NOTE: 251 is used, instead of 252, as truncating to even numbers allow us
    // to align with the perform bitwise operations in circuit.
    let c_hash = c_hash & BlsScalar::pow_of_2(251).sub(&BlsScalar::one());

    // NOTE: This should never fail as we are truncating the BLS scalar
    // to be less than the JubJub modulus.
    Option::from(JubJubScalar::from_bytes(&c_hash.to_bytes()))
        .expect("Failed to truncate BlsScalar")
}

#[allow(non_snake_case)]
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
    /// This will create a random [`SecretKey`] from a scalar
    /// of the Field JubJubScalar.
    pub fn new<T>(rand: &mut T) -> SecretKey
    where
        T: RngCore + CryptoRng,
    {
        let fr = JubJubScalar::random(rand);

        SecretKey(fr)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&self.0.to_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        match Option::from(JubJubScalar::from_bytes(bytes)) {
            Some(scalar) => Ok(SecretKey(scalar)),
            _ => Err(Error::SerialisationError),
        }
    }

    #[allow(non_snake_case)]
    // Signs a chosen message with a given secret key
    // using the dusk variant of the Schnorr signature scheme.
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
#[cfg_attr(feature = "canon", derive(Canon))]
pub struct PublicKey(JubJubExtended);

impl From<&SecretKey> for PublicKey {
    fn from(sk: &SecretKey) -> Self {
        let public_key = GENERATOR_EXTENDED * sk.0;

        PublicKey(public_key)
    }
}

impl From<JubJubExtended> for PublicKey {
    fn from(p: JubJubExtended) -> PublicKey {
        PublicKey(p)
    }
}

impl From<&JubJubExtended> for PublicKey {
    fn from(p: &JubJubExtended) -> PublicKey {
        PublicKey(*p)
    }
}

impl AsRef<JubJubExtended> for PublicKey {
    fn as_ref(&self) -> &JubJubExtended {
        &self.0
    }
}

impl PublicKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        JubJubAffine::from(self.0).to_bytes()
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        match Option::<JubJubAffine>::from(JubJubAffine::from_bytes(*bytes)) {
            Some(point) => Ok(PublicKey(JubJubExtended::from(point))),
            _ => Err(Error::SerialisationError),
        }
    }
}

/// An Schnorr signature, produced by signing a message with a
/// [`SecretKey`].
#[allow(non_snake_case)]
#[derive(PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "canon", derive(Canon))]
pub struct Signature {
    U: JubJubScalar,
    R: JubJubExtended,
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

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut arr = [0u8; 64];
        arr[0..32].copy_from_slice(&self.U.to_bytes()[..]);
        arr[32..64].copy_from_slice(&JubJubAffine::from(self.R).to_bytes()[..]);
        arr
    }

    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self, Error> {
        let mut bytes_scalar = [0u8; 32];
        let mut bytes_point = [0u8; 32];
        // Read U
        bytes_scalar.copy_from_slice(&bytes[0..32]);
        // Read R
        bytes_point.copy_from_slice(&bytes[32..64]);
        match (
            Option::<JubJubScalar>::from(JubJubScalar::from_bytes(
                &bytes_scalar,
            )),
            Option::<JubJubAffine>::from(JubJubAffine::from_bytes(bytes_point)),
        ) {
            (Some(scalar), Some(point)) => Ok(Signature {
                U: scalar,
                R: JubJubExtended::from(point),
            }),
            _ => Err(Error::SerialisationError),
        }
    }

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
