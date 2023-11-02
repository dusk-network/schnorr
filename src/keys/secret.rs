// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;
use dusk_bytes::{Error, HexDebug, Serializable};
use dusk_jubjub::{JubJubScalar, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use rand_core::{CryptoRng, RngCore};

use crate::{DoubleSignature, NotePublicKey, PublicKeyPair, Signature};

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

/// Structure repesenting a secret key
#[allow(non_snake_case)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, HexDebug)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct NoteSecretKey(pub(crate) JubJubScalar);

impl From<JubJubScalar> for NoteSecretKey {
    fn from(s: JubJubScalar) -> NoteSecretKey {
        NoteSecretKey(s)
    }
}

impl From<&JubJubScalar> for NoteSecretKey {
    fn from(s: &JubJubScalar) -> NoteSecretKey {
        NoteSecretKey(*s)
    }
}

impl AsRef<JubJubScalar> for NoteSecretKey {
    fn as_ref(&self) -> &JubJubScalar {
        &self.0
    }
}

impl NoteSecretKey {
    /// This will create a random [`NoteSecretKey`] from a scalar
    /// of the Field JubJubScalar.
    pub fn random<T>(rand: &mut T) -> NoteSecretKey
    where
        T: RngCore + CryptoRng,
    {
        let fr = JubJubScalar::random(rand);

        NoteSecretKey(fr)
    }
}

impl Serializable<32> for NoteSecretKey {
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

impl NoteSecretKey {
    /// Signs a chosen message with a given secret key
    /// using the dusk variant of the Schnorr signature scheme.
    ///
    /// This function performs the following cryptographic operations:
    /// - Generates a random nonce `r`.
    /// - Computes `R = r * G`.
    /// - Computes the challenge `c = H(R || H(m))`.
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
    pub fn sign_single<R>(&self, rng: &mut R, msg: BlsScalar) -> Signature
    where
        R: RngCore + CryptoRng,
    {
        // Create random scalar value for scheme, r
        let r = JubJubScalar::random(rng);

        // Derive a points from r, to sign with the message
        // R = r * G
        let R = GENERATOR_EXTENDED * r;

        // Compute challenge value, c = H(R||H(m));
        let c = crate::signatures::single_key::challenge_hash(&R, msg);

        // Compute scalar signature, U = r - c * sk,
        let u = r - (c * self.as_ref());

        Signature::new(u, R)
    }

    /// Constructs a new `Signature` instance by signing a given message with
    /// a `NoteSecretKey`.
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
        // R_prime = r * G_NUM
        let R = GENERATOR_EXTENDED * r;
        let R_prime = GENERATOR_NUMS_EXTENDED * r;
        let keys = PublicKeyPair((
            NotePublicKey::from(R),
            NotePublicKey::from(R_prime),
        ));
        // Compute challenge value, c = H(R||R_prime||H(m));
        let c = crate::signatures::double_key::challenge_hash(&keys, message);

        // Compute scalar signature, U = r - c * sk,
        let u = r - (c * self.as_ref());

        DoubleSignature::new(u, keys)
    }
}
