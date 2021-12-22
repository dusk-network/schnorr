// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#[cfg(feature = "canon")]
use canonical_derive::Canon;
use dusk_bytes::{DeserializableSlice, Error as BytesError, Serializable};
use dusk_jubjub::GENERATOR_EXTENDED;
use dusk_pki::{PublicKey, SecretKey};
use dusk_poseidon::sponge;
use rand_core::{CryptoRng, RngCore};

use dusk_plonk::prelude::*;

#[allow(non_snake_case)]
/// Method to create a challenge hash for signature scheme
fn challenge_hash(R: JubJubExtended, message: BlsScalar) -> JubJubScalar {
    let R_scalar = R.to_hash_inputs();

    sponge::truncated::hash(&[R_scalar[0], R_scalar[1], message])
}

/// An Schnorr signature, produced by signing a message with a
/// [`SecretKey`].
#[allow(non_snake_case)]
#[derive(PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "canon", derive(Canon))]
pub struct Signature {
    u: JubJubScalar,
    R: JubJubExtended,
}

impl Signature {
    pub fn u(&self) -> &JubJubScalar {
        &self.u
    }

    #[allow(non_snake_case)]
    pub fn R(&self) -> &JubJubExtended {
        &self.R
    }

    /// Signs a chosen message with a given secret key
    /// using the dusk variant of the Schnorr signature scheme.
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

    /// Function to verify that a given point in a Schnorr signature
    /// have the same DLP
    pub fn verify(&self, public_key: &PublicKey, message: BlsScalar) -> bool {
        // Compute challenge value, c = H(R||H(m));
        let c = challenge_hash(self.R, message);

        // Compute verification steps
        // u * G + c * public_key
        let point_1 = (GENERATOR_EXTENDED * self.u) + (public_key.as_ref() * c);

        point_1.eq(&self.R)
    }

    #[cfg(feature = "alloc")]
    pub fn to_witness(
        &self,
        composer: &mut TurboComposer,
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
