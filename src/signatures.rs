// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! # Schnorr Signature
//!
//! This module provides functionality for a Schnorr-based signature.
//! Given a fixed generator-point `G` (in our case [`GENERATOR_EXTENDED`]),
//! the [`Signature`] consists of the tuple `(u, R)`, where
//! ```text
//! u = r - sk*c
//! ```
//! for random `r`, secret key `sk` and challenge hash `c = hash(R || m)`, and
//! ```text
//! R = sk * G
//! ```
//! the point resulting by adding the generator point `sk` times
//! to itself.
//!
//! Given the public key `PK: JubJubExtended = sk * G` and signature `(u, R)`
//! the verifier can verify the authenticity of the signature by checking:
//! ```text
//! u * G + c * PK == R
//! ```
//!
//! For the double signature, check the [`double`] module.

pub(crate) mod double;

use dusk_bytes::{DeserializableSlice, Error as BytesError, Serializable};
use dusk_jubjub::{JubJubExtended, JubJubScalar, GENERATOR_EXTENDED};
use dusk_plonk::prelude::*;
use dusk_poseidon::sponge::truncated::hash;

use crate::PublicKey;

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

/// An Schnorr signature, produced by signing a message with a [`SecretKey`].
///
/// ## Fields
///
/// - `u`: A [`JubJubScalar`]
/// - `R`: A [`JubJubExtended`] point
///
/// ## Feature Flags
///
/// - `rkyv-impl`: Allows for archiving of `Signature`.
///
/// ## Example
///
/// ```
/// use dusk_bls12_381::BlsScalar;
/// use dusk_schnorr::{PublicKey, SecretKey, Signature};
/// use rand::rngs::StdRng;
/// use rand::SeedableRng;
/// use ff::Field;
///
/// let mut rng = StdRng::seed_from_u64(1234u64);
///
/// let sk = SecretKey::random(&mut rng);
/// let message = BlsScalar::random(&mut rng);
/// let pk = PublicKey::from(&sk);
///
/// // Sign the message
/// let signature = sk.sign(&mut rng, message);
///
/// // Verify the signature
/// assert!(signature.verify(&pk, message));
/// ```
///
/// [`SecretKey`]: [`crate::SecretKey`]
#[allow(non_snake_case)]
#[derive(Default, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct Signature {
    u: JubJubScalar,
    R: JubJubExtended,
}

impl Signature {
    /// Exposes the `u` scalar of the Schnorr signature.
    pub fn u(&self) -> &JubJubScalar {
        &self.u
    }

    /// Exposes the `R` point of the Schnorr signature.
    #[allow(non_snake_case)]
    pub fn R(&self) -> &JubJubExtended {
        &self.R
    }

    /// Creates a new single key [`Signature`] with the given parameters
    #[allow(non_snake_case)]
    pub(crate) fn new(u: JubJubScalar, R: JubJubExtended) -> Self {
        Self { u, R }
    }

    /// Verifies the Schnorr signature against a given public key and
    /// message.
    ///
    /// This function computes a challenge hash using the stored `R` point and
    /// the provided message, then performs the verification by checking that:
    /// ```text
    /// u * G + c * PK == R
    /// ```
    ///
    /// ## Parameters
    ///
    /// - `pk`: Reference to the [`PublicKey`] against which the signature is
    ///   verified.
    /// - `message`: The message in [`BlsScalar`] format.
    ///
    /// ## Returns
    ///
    /// Returns a boolean value indicating the verification result. `true` if
    /// verification is successful, `false` otherwise.
    pub fn verify(&self, pk: &PublicKey, message: BlsScalar) -> bool {
        // Compute challenge value, c = H(R||m);
        let c = challenge_hash(self.R(), message);

        // Compute verification steps
        // u * G + c * PK
        let point_1 = (GENERATOR_EXTENDED * self.u) + (pk.as_ref() * c);

        point_1.eq(&self.R)
    }

    /// Appends the single key as a witness to the circuit composed by the
    /// [`Composer`].
    ///
    /// ## Parameters
    ///
    /// - `composer`: Mutable reference to the Plonk `Composer`.
    ///
    /// ## Returns
    ///
    /// Returns a tuple `(Witness, WitnessPoint)` containing converted `u` and
    /// `R` fields.
    #[cfg(feature = "alloc")]
    pub fn append<C: Composer>(
        &self,
        composer: &mut C,
    ) -> (Witness, WitnessPoint) {
        let u = composer.append_witness(self.u);
        let r = composer.append_point(self.R);

        (u, r)
    }
}

impl Serializable<64> for Signature {
    type Error = BytesError;

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[..32].copy_from_slice(&self.u.to_bytes()[..]);
        buf[32..].copy_from_slice(&JubJubAffine::from(self.R).to_bytes()[..]);
        buf
    }

    #[allow(non_snake_case)]
    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let u = JubJubScalar::from_slice(&bytes[..32])?;
        let R = JubJubExtended::from(JubJubAffine::from_slice(&bytes[32..])?);

        Ok(Self { u, R })
    }
}

// Create a challenge hash for the standard signature scheme.
#[allow(non_snake_case)]
pub(crate) fn challenge_hash(
    R: &JubJubExtended,
    message: BlsScalar,
) -> JubJubScalar {
    let R_coordinates = R.to_hash_inputs();

    hash(&[R_coordinates[0], R_coordinates[1], message])
}
