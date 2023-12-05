// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! # Secret Key Module
//!
//! This module provides the `SecretKey`, essential for signing messages,
//! proving ownership. It facilitates the generation of a Schnorr signatures,
//! supporting both single and double signature schemes.

use dusk_bls12_381::BlsScalar;
use dusk_bytes::{Error, HexDebug, Serializable};
use dusk_jubjub::{JubJubScalar, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use rand_core::{CryptoRng, RngCore};

use crate::{DoubleSignature, Signature};

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

/// Structure repesenting a [`SecretKey`], represented as a private scalar
/// in the JubJub scalar field.
///
/// ## Examples
///
/// Generating a random `SecretKey` and signing a message with single and
/// double signatures:
/// ```
/// use dusk_schnorr::SecretKey;
/// use rand::rngs::StdRng;
/// use rand::SeedableRng;
///
/// let mut rng = StdRng::seed_from_u64(12345);
/// let secret_key = SecretKey::random(&mut rng);
/// ```
#[allow(non_snake_case)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, HexDebug)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct SecretKey(pub(crate) JubJubScalar);

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
    pub fn random<T>(rand: &mut T) -> SecretKey
    where
        T: RngCore + CryptoRng,
    {
        let fr = JubJubScalar::random(rand);

        SecretKey(fr)
    }
}

impl Serializable<32> for SecretKey {
    type Error = Error;

    fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        let secret_key = match JubJubScalar::from_bytes(bytes).into() {
            Some(sk) => sk,
            None => return Err(Error::InvalidData),
        };
        Ok(Self(secret_key))
    }
}

impl SecretKey {
    /// Signs a chosen message with a given secret key using the dusk variant
    /// of the Schnorr signature scheme.
    ///
    /// This function performs the following cryptographic operations:
    /// - Generates a random nonce `r`.
    /// - Computes `R = r * G`.
    /// - Computes the challenge `c = H(R || m)`.
    /// - Computes the signature `u = r - c * sk`.
    ///
    /// ## Parameters
    ///
    /// - `rng`: Reference to the random number generator.
    /// - `message`: The message in [`BlsScalar`] to be signed.
    ///
    /// ## Returns
    ///
    /// Returns a new [`Signature`] containing the `u` scalar and `R` point.
    #[allow(non_snake_case)]
    pub fn sign<R>(&self, rng: &mut R, msg: BlsScalar) -> Signature
    where
        R: RngCore + CryptoRng,
    {
        // Create random scalar value for scheme, r
        let r = JubJubScalar::random(rng);

        // Derive a points from r, to sign with the message
        // R = r * G
        let R = GENERATOR_EXTENDED * r;

        // Compute challenge value, c = H(R||m);
        let c = crate::signatures::challenge_hash(&R, msg);

        // Compute scalar signature, U = r - c * sk,
        let u = r - (c * self.as_ref());

        Signature::new(u, R)
    }

    /// Constructs a new `Signature` instance by signing a given message with
    /// a `SecretKey`.
    ///
    /// Utilizes a secure random number generator to create a unique random
    /// scalar, and subsequently computes public key points `(R, R')` and a
    /// scalar signature `u`.
    ///
    /// # Parameters
    ///
    /// * `rng`: Cryptographically secure random number generator.
    /// * `message`: Message as a `BlsScalar`.
    ///
    /// # Returns
    ///
    /// A new [`DoubleSignature`] instance.
    #[allow(non_snake_case)]
    pub fn sign_double<R>(
        &self,
        rng: &mut R,
        message: BlsScalar,
    ) -> DoubleSignature
    where
        R: RngCore + CryptoRng,
    {
        // Create random scalar value for scheme, r
        let r = JubJubScalar::random(rng);

        // Derive two points from r, to sign with the message
        // R = r * G
        // R_prime = r * G'
        let R = GENERATOR_EXTENDED * r;
        let R_prime = GENERATOR_NUMS_EXTENDED * r;
        // Compute challenge value, c = H(R||R_prime||m);
        let c =
            crate::signatures::double::challenge_hash(&R, &R_prime, message);

        // Compute scalar signature, u = r - c * sk,
        let u = r - (c * self.as_ref());

        DoubleSignature::new(u, R, R_prime)
    }
}
