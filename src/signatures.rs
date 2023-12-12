// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! # Schnorr Signature
//!
//! This module provides functionality for a Schnorr-based signature, a
//! Schnorr-based double signature and a Schnorr-based signature with variable
//! generator.

use dusk_bytes::{DeserializableSlice, Error as BytesError, Serializable};
use dusk_jubjub::{JubJubExtended, JubJubScalar};
use dusk_plonk::prelude::*;
use dusk_poseidon::sponge::truncated::hash;

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

/// An Schnorr signature, produced by signing a message with a [`SecretKey`].
///
/// ## Fields
///
/// - `u`: A [`JubJubScalar`]
/// - `R`: A [`JubJubExtended`] point
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
/// assert!(pk.verify(&signature, message));
/// ```
///
/// [`SecretKey`]: [`crate::SecretKey`]
#[derive(Default, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
#[allow(non_snake_case)]
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

    /// Appends the single key as a witness to the circuit composed by the
    /// [`Composer`].
    ///
    /// # Feature
    ///
    /// Only available with the "alloc" feature enabled.
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
        // TODO: check whether the signature should be appended as public
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

/// Structure representing a Schnorr signature with a double-key mechanism.
///
/// # Feature
///
/// Only available with the "double" feature enabled.
///
/// ## Fields
///
/// - `u`: A [`JubJubScalar`] scalar value representing part of the Schnorr
///   signature.
/// - 'R': A [`JubJubExtended`] point representing the nonce generated with the
///   generator point [`G`].
/// - 'R_prime': A [`JubJubExtended`] point representing the nonce generated
///   with the generator point [`G'`].
///
/// ## Example
/// ```
/// use rand::rngs::StdRng;
/// use rand::SeedableRng;
/// use dusk_schnorr::{SecretKey, PublicKeyDouble, SignatureDouble};
/// use dusk_bls12_381::BlsScalar;
/// use ff::Field;
///
/// let mut rng = StdRng::seed_from_u64(2321u64);
///
/// let sk = SecretKey::random(&mut rng);
/// let message = BlsScalar::random(&mut rng);
/// let pk_double: PublicKeyDouble = sk.into();
///
/// let signature = sk.sign_double(&mut rng, message);
///
/// assert!(pk_double.verify(&signature, message));
/// ```
///
/// [`G`]: `GENERATOR_EXTENDED`
/// [`G'`]: `GENERATOR_NUMS_EXTENDED`
#[derive(Default, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
#[cfg(feature = "double")]
#[allow(non_snake_case)]
pub struct SignatureDouble {
    u: JubJubScalar,
    R: JubJubExtended,
    R_prime: JubJubExtended,
}

#[cfg(feature = "double")]
impl SignatureDouble {
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

    /// Creates a new [`SignatureDouble`]
    #[allow(non_snake_case)]
    pub(crate) fn new(
        u: JubJubScalar,
        R: JubJubExtended,
        R_prime: JubJubExtended,
    ) -> Self {
        Self { u, R, R_prime }
    }

    /// Appends the `Signature` as a witness to the circuit composed by the
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
        // TODO: check whether the signature should be public
        let u = composer.append_witness(self.u);
        let r = composer.append_point(self.R());
        let r_p = composer.append_point(self.R_prime());

        (u, r, r_p)
    }
}

#[cfg(feature = "double")]
impl Serializable<96> for SignatureDouble {
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

// Create a challenge hash for the double signature scheme.
#[cfg(feature = "double")]
#[allow(non_snake_case)]
pub(crate) fn challenge_hash_double(
    R: &JubJubExtended,
    R_prime: &JubJubExtended,
    message: BlsScalar,
) -> JubJubScalar {
    let R_coordinates = R.to_hash_inputs();
    let R_p_coordinates = R_prime.to_hash_inputs();

    hash(&[
        R_coordinates[0],
        R_coordinates[1],
        R_p_coordinates[0],
        R_p_coordinates[1],
        message,
    ])
}

/// An Schnorr SignatureVarGen, produced by signing a message with a
/// [`SecretKeyVarGen`].
///
/// The `SignatureVarGen` struct encapsulates variables of the Schnorr scheme.
///
/// # Feature
///
/// Only available with the "var_generator" feature enabled.
///
/// ## Fields
///
/// - `u`: A [`JubJubScalar`] scalar representing the Schnorr signature.
/// - `R`: A [`JubJubExtended`] point produced as part of the Schnorr signature.
///
/// ## Example
///
/// ```
/// use dusk_bls12_381::BlsScalar;
/// use dusk_schnorr::{PublicKeyVarGen, SecretKeyVarGen, SignatureVarGen};
/// use rand::rngs::StdRng;
/// use rand::SeedableRng;
/// use ff::Field;
///
/// let mut rng = StdRng::seed_from_u64(1234u64);
///
/// let sk = SecretKeyVarGen::random(&mut rng);
/// let message = BlsScalar::random(&mut rng);
/// let pk = PublicKeyVarGen::from(&sk);
///
/// // Sign the message
/// let signature = sk.sign(&mut rng, message);
///
/// // Verify the signature
/// assert!(pk.verify(&signature, message));
/// ```
///
/// [`SecretKeyVarGen`]: [`crate::SecretKeyVarGen`]
#[allow(non_snake_case)]
#[derive(Default, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
#[cfg(feature = "var_generator")]
pub struct SignatureVarGen {
    u: JubJubScalar,
    R: JubJubExtended,
}

#[cfg(feature = "var_generator")]
impl SignatureVarGen {
    /// Exposes the `u` scalar of the Schnorr SignatureVarGen.
    pub fn u(&self) -> &JubJubScalar {
        &self.u
    }

    /// Exposes the `R` point of the Schnorr SignatureVarGen.
    #[allow(non_snake_case)]
    pub fn R(&self) -> &JubJubExtended {
        &self.R
    }

    /// Creates a new single key [`SignatureVarGen`] with the given parameters
    #[allow(non_snake_case)]
    pub(crate) fn new(u: JubJubScalar, R: JubJubExtended) -> Self {
        Self { u, R }
    }

    /// Appends the single key as a witness to the circuit composed by the
    /// [`Composer`].
    ///
    /// # Feature
    ///
    /// Only available with the "alloc" feature enabled.
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
        // TODO: check whether the signature should be public
        let u = composer.append_witness(self.u);
        let r = composer.append_point(self.R);

        (u, r)
    }
}

#[cfg(feature = "var_generator")]
impl Serializable<64> for SignatureVarGen {
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
