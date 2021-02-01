// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![allow(non_snake_case)]

#[cfg(feature = "canon")]
use canonical::Canon;
#[cfg(feature = "canon")]
use canonical_derive::Canon;
#[allow(unused_imports)]
use dusk_bls12_381::BlsScalar;
use dusk_bytes::{DeserializableSlice, Error as BytesError, Serializable};
use dusk_jubjub::{JubJubScalar, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use dusk_pki::{PublicKey, SecretKey};
use poseidon252::sponge::hash;
use rand_core::{CryptoRng, RngCore};

/// Method to create a challenge hash for signature scheme
fn challenge_hash(R: PublicKeyPair, message: BlsScalar) -> JubJubScalar {
    let h = hash(&[message]);
    let R_scalar = (R.0).0.as_ref().to_hash_inputs();
    let R_prime_scalar = (R.0).1.as_ref().to_hash_inputs();

    let c = hash(&[
        R_scalar[0],
        R_scalar[1],
        R_prime_scalar[0],
        R_prime_scalar[1],
        h,
    ]);

    super::truncate_bls_to_jubjub(c)
}

#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "canon", derive(Canon))]

/// Structure repesenting a pair of [`PublicKey`] generated from a [`SecretKey`]
pub struct PublicKeyPair(pub(crate) (PublicKey, PublicKey));

impl PublicKeyPair {
    /// R ecc generator point
    pub fn R(&self) -> &PublicKey {
        &self.0 .0
    }

    /// R ecc generator nums point
    pub fn R_prime(&self) -> &PublicKey {
        &self.0 .1
    }
}

impl From<&SecretKey> for PublicKeyPair {
    fn from(sk: &SecretKey) -> Self {
        let public_key = PublicKey::from(sk);
        let public_key_prime =
            PublicKey::from(GENERATOR_NUMS_EXTENDED * sk.as_ref());

        PublicKeyPair((public_key, public_key_prime))
    }
}

impl From<SecretKey> for PublicKeyPair {
    fn from(sk: SecretKey) -> Self {
        (&sk).into()
    }
}

impl Serializable<64> for PublicKeyPair {
    type Error = BytesError;

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[..32].copy_from_slice(&(self.0).0.to_bytes()[..]);
        buf[32..].copy_from_slice(&(self.0).0.to_bytes()[..]);
        buf
    }

    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        Ok(PublicKeyPair((
            PublicKey::from_slice(&bytes[..32])?,
            PublicKey::from_slice(&bytes[32..])?,
        )))
    }
}

#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "canon", derive(Canon))]
pub struct Proof {
    u: JubJubScalar,
    keys: PublicKeyPair,
}

impl Proof {
    pub fn u(&self) -> &JubJubScalar {
        &self.u
    }

    pub fn keys(&self) -> &PublicKeyPair {
        &self.keys
    }

    /// An Schnorr signature, produced by signing a message with a
    /// [`SecretKey`].
    // Signs a chosen message with a given secret key
    // using the dusk variant of the Schnorr signature scheme.
    pub fn new<R>(sk: &SecretKey, rng: &mut R, message: BlsScalar) -> Self
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
        let keys =
            PublicKeyPair((PublicKey::from(R), PublicKey::from(R_prime)));
        // Compute challenge value, c = H(R||R_prime||H(m));
        let c = challenge_hash(keys, message);

        // Compute scalar signature, U = r - c * sk,
        let u = r - (c * sk.as_ref());

        Self { u, keys }
    }

    /// Function to verify that two given point in a Schnorr signature
    /// have the same DLP
    pub fn verify(
        &self,
        public_key_pair: &PublicKeyPair,
        message: BlsScalar,
    ) -> bool {
        // Compute challenge value, c = H(R||R_prime||H(m));
        let c = challenge_hash(self.keys, message);

        // Compute verification steps
        // u * G + c * public_key
        let point_1 = (GENERATOR_EXTENDED * self.u)
            + ((public_key_pair.0).0.as_ref() * c);
        // u * G_nums + c * public_key_prime
        let point_2 = (GENERATOR_NUMS_EXTENDED * self.u)
            + ((public_key_pair.0).1.as_ref() * c);

        point_1.eq(self.keys.R().as_ref())
            && point_2.eq(self.keys.R_prime().as_ref())
    }
}

impl Serializable<96> for Proof {
    type Error = BytesError;

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[..32].copy_from_slice(&self.u.to_bytes()[..]);
        buf[32..].copy_from_slice(&self.keys.to_bytes()[..]);
        buf
    }

    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let u = JubJubScalar::from_slice(&bytes[..32])?;
        let keys = PublicKeyPair::from_slice(&bytes[32..])?;

        Ok(Self { u, keys })
    }
}
