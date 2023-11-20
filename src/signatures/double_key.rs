// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! # Double-Key Schnorr Signature
//!
//! This module implements a Schnorr signature scheme with a double-key
//! mechanism.
//!
//! The module includes the [`Signature`] struct , which holds the scalar `u`
//! and two nonce points `R` and `R'`.

use dusk_bytes::{DeserializableSlice, Error as BytesError, Serializable};
use dusk_jubjub::{GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use dusk_plonk::prelude::*;
use dusk_poseidon::sponge::truncated;

use crate::PublicKeyPair;

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

/// Function that creates a challenge hash for the signature scheme.
///
/// ## Parameters
///
/// - 'R': A [`JubJubExtended`] point representing the nonce generated with the
///   generator point [`G`].
/// - 'R_prime': A [`JubJubExtended`] point representing the nonce generated
///   with the generator point [`G_NUMS`].
/// - `message`: A `BlsScalar` representing the message to be signed.
///
/// ## Returns
///
/// A `JubJubScalar` representing the challenge hash.
///
/// [`G`]: `GENERATOR_EXTENDED`
/// [`G_NUMS`]: `GENERATOR_NUMS_EXTENDED`
#[allow(non_snake_case)]
pub(crate) fn challenge_hash(
    R: &JubJubExtended,
    R_prime: &JubJubExtended,
    message: BlsScalar,
) -> JubJubScalar {
    let R_coordinates = R.to_hash_inputs();
    let R_p_coordinates = R_prime.to_hash_inputs();

    truncated::hash(&[
        R_coordinates[0],
        R_coordinates[1],
        R_p_coordinates[0],
        R_p_coordinates[1],
        message,
    ])
}

/// Structure representing a Schnorr signature with a double-key
/// mechanism.
///
/// ## Fields
///
/// - `u`: A [`JubJubScalar`] scalar value representing part of the Schnorr
///   signature.
/// - 'R': A [`JubJubExtended`] point representing the nonce generated with the
///   generator point [`G`].
/// - 'R_prime': A [`JubJubExtended`] point representing the nonce generated
///   with the generator point [`G_NUMS`].
///
/// ## Example
/// ```
/// use rand::rngs::StdRng;
/// use rand::SeedableRng;
/// use dusk_schnorr::{SecretKey, PublicKeyPair, DoubleSignature};
/// use dusk_bls12_381::BlsScalar;
///
/// let mut rng = StdRng::seed_from_u64(2321u64);
///
/// let sk = SecretKey::random(&mut rng);
/// let message = BlsScalar::uni_random(&mut rng);
/// let pk_pair: PublicKeyPair = sk.into();
///
/// let signature = sk.sign_double(&mut rng, message);
///
/// assert!(signature.verify(&pk_pair, message));
/// ```
///
/// [`G`]: `GENERATOR_EXTENDED`
/// [`G_NUMS`]: `GENERATOR_NUMS_EXTENDED`
#[derive(Default, Clone, Copy, Debug)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
#[allow(non_snake_case)]
pub struct Signature {
    u: JubJubScalar,
    R: JubJubExtended,
    R_prime: JubJubExtended,
}

impl Signature {
    /// Returns the `JubJubScalar` `u` component of the Schnorr signature.
    pub fn u(&self) -> &JubJubScalar {
        &self.u
    }

    /// Returns the nonce point `R`
    #[allow(non_snake_case)]
    pub fn R(&self) -> &JubJubExtended {
        &self.R
    }

    /// Returns the nonce point `R_prime`
    #[allow(non_snake_case)]
    pub fn R_prime(&self) -> &JubJubExtended {
        &self.R_prime
    }

    /// Creates a new [`DoubleSignature`]
    #[allow(non_snake_case)]
    pub(crate) fn new(
        u: JubJubScalar,
        R: JubJubExtended,
        R_prime: JubJubExtended,
    ) -> Self {
        Self { u, R, R_prime }
    }

    /// Verifies that two given points in a Schnorr signature share the same
    /// Discrete Logarithm Problem (DLP).
    ///
    /// It computes the challenge scalar and verifies the equality of points,
    /// thereby ensuring the signature is valid.
    ///
    /// # Parameters
    ///
    /// * `pk_pair`: [`PublicKeyPair`] corresponding to the secret key used for
    ///   the signature
    /// * `mgs_hash`: Message hashed to a `BlsScalar`.
    ///
    /// # Returns
    ///
    /// A boolean value indicating the validity of the Schnorr signature.
    #[allow(non_snake_case)]
    pub fn verify(&self, pk_pair: &PublicKeyPair, msg_hash: BlsScalar) -> bool {
        // Compute challenge value, c = H(R||R_prime||H(m));
        let c = challenge_hash(self.R(), self.R_prime(), msg_hash);

        // Compute verification steps
        // u * G + c * public_key
        let point_1 =
            (GENERATOR_EXTENDED * self.u) + (pk_pair.pk().as_ref() * c);
        // u * G_nums + c * public_key_prime
        let point_2 = (GENERATOR_NUMS_EXTENDED * self.u)
            + (pk_pair.pk_prime().as_ref() * c);

        // Verify point equations
        // point_1 = R && point_2 = R_prime
        point_1.eq(self.R()) && point_2.eq(self.R_prime())
    }

    /// Appends the `Signature` as a witness to the cricuit composed by the
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
    /// `R` and `R'`.
    #[cfg(feature = "alloc")]
    pub fn append<C: Composer>(
        &self,
        composer: &mut C,
    ) -> (Witness, WitnessPoint, WitnessPoint) {
        let u = composer.append_witness(self.u);
        let r = composer.append_point(self.R());
        let r_p = composer.append_point(self.R_prime());

        (u, r, r_p)
    }
}

impl Serializable<96> for Signature {
    type Error = BytesError;

    #[allow(non_snake_case)]
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let R_affine: JubJubAffine = self.R().into();
        let R_p_affine: JubJubAffine = self.R_prime().into();

        let mut buf = [0u8; Self::SIZE];
        buf[..32].copy_from_slice(&self.u.to_bytes()[..]);
        buf[32..64].copy_from_slice(&R_affine.to_bytes()[..]);
        buf[64..].copy_from_slice(&R_p_affine.to_bytes()[..]);
        buf
    }

    #[allow(non_snake_case)]
    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let u = JubJubScalar::from_slice(&bytes[..32])?;
        let R: JubJubExtended =
            JubJubAffine::from_slice(&bytes[32..64])?.into();
        let R_prime: JubJubExtended =
            JubJubAffine::from_slice(&bytes[64..])?.into();

        Ok(Self { u, R, R_prime })
    }
}
