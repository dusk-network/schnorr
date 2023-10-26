// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! # Single-key Schnorr Signature
//!
//! This module provides functionality for Schnorr-based signatures using a
//! single key. It includes the `Signature` struct and relevant methods for
//! signature generation and verification.

use dusk_bytes::{DeserializableSlice, Error as BytesError, Serializable};
use dusk_jubjub::GENERATOR_EXTENDED;
use dusk_pki::{PublicKey, SecretKey};
use dusk_poseidon::sponge;
use rand_core::{CryptoRng, RngCore};

use dusk_plonk::prelude::*;

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

#[allow(non_snake_case)]
/// Method to create a challenge hash for signature scheme
fn challenge_hash(R: JubJubExtended, message: BlsScalar) -> JubJubScalar {
    let R_scalar = R.to_hash_inputs();

    sponge::truncated::hash(&[R_scalar[0], R_scalar[1], message])
}

/// An Schnorr signature, produced by signing a message with a
/// [`SecretKey`].
///
/// The `Signature` struct encapsulates variables of the Schnorr scheme.
///
/// ## Fields
///
/// - `u`: The `u` scalar representing the Schnorr signature.
/// - `R`: The `R` point produced as part of the Schnorr signature.
///
/// ## Feature Flags
///
/// - `rkyv-impl`: Allows for archiving of `Signature`.
/// 
/// ## Example
///
/// ```
/// use dusk_bls12_381::BlsScalar;
/// use dusk_pki::{PublicKey, SecretKey};
/// use dusk_schnorr::Signature;
/// use ff::Field;
/// use rand::rngs::StdRng;
/// use rand::SeedableRng;
///
/// let mut rng = StdRng::seed_from_u64(1234u64);
///
/// let sk = SecretKey::random(&mut rng);
/// let message = BlsScalar::random(&mut rng);
/// let pk = PublicKey::from(&sk);
///
/// // Sign the message
/// let signature = Signature::new(&sk, &mut rng, message);
///
/// // Verify the signature
/// assert!(signature.verify(&pk, message));
/// ```
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
    /// - `sk`: Reference to the `SecretKey` for signing.
    /// - `rng`: Reference to the random number generator.
    /// - `message`: The message in `BlsScalar` to be signed.
    ///
    /// ## Returns
    ///
    /// Returns a new `Signature` containing the `u` scalar and `R` point.
    #[allow(non_snake_case)]
    pub fn new<R>(sk: &SecretKey, rng: &mut R, message: BlsScalar) -> Self
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
        let u = r - (c * sk.as_ref());

        Signature { u, R }
    }

    /// Verifies the Schnorr signature against a given public key and message.
    ///
    /// This function computes a challenge hash using the stored `R` point and
    /// the provided message, then performs the verification by checking the
    /// equality of `u * G + c * public_key` and `R`.
    ///
    /// ## Parameters
    ///
    /// - `public_key`: Reference to the `PublicKey` against which the signature
    ///   is verified.
    /// - `message`: The message in `BlsScalar` format.
    ///
    /// ## Returns
    ///
    /// Returns a boolean value indicating the verification result. `true` if
    /// verification is successful, `false` otherwise.
    pub fn verify(&self, public_key: &PublicKey, message: BlsScalar) -> bool {
        // Compute challenge value, c = H(R||H(m));
        let c = challenge_hash(self.R, message);

        // Compute verification steps
        // u * G + c * public_key
        let point_1 = (GENERATOR_EXTENDED * self.u) + (public_key.as_ref() * c);

        point_1.eq(&self.R)
    }

    /// Converts the `Signature` fields to their witness equivalents.
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
    pub fn to_witness<C: Composer>(
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
