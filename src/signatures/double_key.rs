// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! # Double-Key Schnorr Signature
//!
//! This module implements a Schnorr signature scheme with a double-key
//! mechanism. It is primarily used in Phoenix to allow for proof delegation
//! without leaking the secret key.
//!
//! The module includes the [`PublicKeyPair`] and [`Signature`] structs. The
//! [`PublicKeyPair`] struct contains the public key pairs `(R, R')`, where `R`
//! is generated from standard generator point `G`, and the other from generator
//! point `G_NUM`. The [`Signature`] struct holds the scalar `u` and a
//! [`PublicKeyPair`].

use dusk_bytes::{DeserializableSlice, Error as BytesError, Serializable};
use dusk_jubjub::{GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use dusk_plonk::prelude::*;
use dusk_poseidon::sponge::truncated;

use crate::{NotePublicKey, NoteSecretKey};

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

/// Function that creates a challenge hash for the signature scheme.
///
/// ## Parameters
///
/// - 'R': A [`PublicKeyPair`] that consists of `(R, R')` public keys.
/// - `message`: A `BlsScalar` representing the message to be signed.
///
/// ## Returns
///
/// A `JubJubScalar` representing the challenge hash.
#[allow(non_snake_case)]
pub(crate) fn challenge_hash(
    keys: &PublicKeyPair,
    message: BlsScalar,
) -> JubJubScalar {
    let R_scalar = keys.R().as_ref().to_hash_inputs();
    let R_prime_scalar = keys.R_prime().as_ref().to_hash_inputs();

    truncated::hash(&[
        R_scalar[0],
        R_scalar[1],
        R_prime_scalar[0],
        R_prime_scalar[1],
        message,
    ])
}

/// Structure representing a pair of [`NotePublicKey`] objects generated from a
/// [`NoteSecretKey`].
///
/// The `PublicKeyPair` struct contains two types of public keys, `(R, R')`,
/// which are generated from different bases. Specifically, `R` is generated
/// from the standard generator point `G`, and `R'` is generated from `G_NUM`.
///
/// This construct allows for a double-key mechanism to enable more advanced
/// uses then the single-key variant. For example, it is used in Phoenix for
/// proof delegation while preventing the leakage of secret keys.
///
/// ## Fields
///
/// - `(R, R')`: Pair of public keys, where `R` is generated from the standard
///   generator point `G` and `R'` is generated from `G_NUM`.
///
/// ## Example
/// ```
/// use rand::thread_rng;
/// use dusk_schnorr::{NoteSecretKey, PublicKeyPair};
///
/// let sk = NoteSecretKey::random(&mut thread_rng());
/// let pk_pair = PublicKeyPair::from(&sk);
/// ```
#[derive(Default, Clone, Copy, Debug)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct PublicKeyPair(pub(crate) (NotePublicKey, NotePublicKey));

impl PublicKeyPair {
    /// Returns the `NotePublicKey` corresponding to the standard elliptic curve
    /// generator point `G`.
    #[allow(non_snake_case)]
    pub fn R(&self) -> &NotePublicKey {
        &self.0 .0
    }

    /// Returns the `NotePublicKey` corresponding to the secondary elliptic
    /// curve generator point `G_NUM`.
    #[allow(non_snake_case)]
    pub fn R_prime(&self) -> &NotePublicKey {
        &self.0 .1
    }
}

impl From<&NoteSecretKey> for PublicKeyPair {
    fn from(sk: &NoteSecretKey) -> Self {
        let public_key = NotePublicKey::from(sk);
        let public_key_prime =
            NotePublicKey::from(GENERATOR_NUMS_EXTENDED * sk.as_ref());

        PublicKeyPair((public_key, public_key_prime))
    }
}

impl From<NoteSecretKey> for PublicKeyPair {
    fn from(sk: NoteSecretKey) -> Self {
        (&sk).into()
    }
}

impl Serializable<64> for PublicKeyPair {
    type Error = BytesError;

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[..32].copy_from_slice(&(self.0).0.to_bytes()[..]);
        buf[32..].copy_from_slice(&(self.0).1.to_bytes()[..]);
        buf
    }

    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        Ok(PublicKeyPair((
            NotePublicKey::from_slice(&bytes[..32])?,
            NotePublicKey::from_slice(&bytes[32..])?,
        )))
    }
}

/// Structure representing a Schnorr signature with a double-key
/// mechanism.
///
/// ## Fields
///
/// - `u`: A [`JubJubScalar`] scalar value representing part of the Schnorr
///   signature.
/// - `keys`: A [`PublicKeyPair`] encapsulating the public keys `(R, R')`.
///
/// ## Example
/// ```
/// use rand::rngs::StdRng;
/// use rand::SeedableRng;
/// use dusk_schnorr::{NoteSecretKey, PublicKeyPair, DoubleSignature};
/// use dusk_bls12_381::BlsScalar;
///
/// let mut rng = StdRng::seed_from_u64(2321u64);
///
/// let sk = NoteSecretKey::random(&mut rng);
/// let message = BlsScalar::uni_random(&mut rng);
/// let pk_pair: PublicKeyPair = sk.into();
///
/// let signature = sk.sign_double(&mut rng, message);
///
/// assert!(signature.verify(&pk_pair, message));
/// ```
#[derive(Default, Clone, Copy, Debug)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct Signature {
    u: JubJubScalar,
    keys: PublicKeyPair,
}

impl Signature {
    /// Returns the `JubJubScalar` `u` component of the Schnorr signature.
    pub fn u(&self) -> &JubJubScalar {
        &self.u
    }

    /// Returns the `PublicKeyPair` that comprises the Schnorr signature.
    pub fn keys(&self) -> &PublicKeyPair {
        &self.keys
    }

    /// Creates a new [`DoubleSignature`]
    pub(crate) fn new(u: JubJubScalar, keys: PublicKeyPair) -> Self {
        Self { u, keys }
    }

    /// Verifies that two given points in a Schnorr signature share the same
    /// Discrete Logarithm Problem (DLP).
    ///
    /// It computes the challenge scalar and verifies the equality of points,
    /// thereby ensuring the signature is valid.
    ///
    /// # Parameters
    ///
    /// * `public_key_pair`: Reference to a `PublicKeyPair`.
    /// * `message`: Message as a `BlsScalar`.
    ///
    /// # Returns
    ///
    /// A boolean value indicating the validity of the Schnorr signature.
    pub fn verify(
        &self,
        public_key_pair: &PublicKeyPair,
        message: BlsScalar,
    ) -> bool {
        // Compute challenge value, c = H(R||R_prime||H(m));
        let c = challenge_hash(self.keys(), message);

        // Compute verification steps
        // u * G + c * public_key
        let point_1 =
            (GENERATOR_EXTENDED * self.u) + (public_key_pair.R().as_ref() * c);
        // u * G_nums + c * public_key_prime
        let point_2 = (GENERATOR_NUMS_EXTENDED * self.u)
            + (public_key_pair.R_prime().as_ref() * c);

        point_1.eq(self.keys.R().as_ref())
            && point_2.eq(self.keys.R_prime().as_ref())
    }

    /// Appends the `DoubleKey` as a witness to the cricuit composed by the
    /// `Composer`.
    ///
    /// # Feature
    ///
    /// This function is only available when the "alloc" feature is enabled.
    ///
    /// # Parameters
    ///
    /// * `composer`: Mutable reference to a `Composer`.
    ///
    /// # Returns
    ///
    /// A tuple comprising the `Witness` of scalar `u`, and `WitnessPoint`s of
    /// `(R, R')`.
    #[cfg(feature = "alloc")]
    pub fn to_witness<C: Composer>(
        &self,
        composer: &mut C,
    ) -> (Witness, WitnessPoint, WitnessPoint) {
        let u = composer.append_witness(self.u);
        let r = composer.append_point(self.keys.R().as_ref());
        let r_p = composer.append_point(self.keys.R_prime().as_ref());

        (u, r, r_p)
    }
}

impl Serializable<96> for Signature {
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
