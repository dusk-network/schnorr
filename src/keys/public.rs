// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! # Public Key Module
//!
//! This module provides the public key components for the Schnorr signature
//! scheme, necessary for verifying signature validity. It includes single and
//! pair-based public keys. Public keys in this context are points on the JubJub
//! elliptic curve generated from the [`SecretKey`], which provide the basis
//! for signature verification.
use dusk_bytes::{DeserializableSlice, Error, HexDebug, Serializable};
use dusk_jubjub::{
    JubJubAffine, JubJubExtended, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED,
};

use crate::SecretKey;

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

/// Structure repesenting a [`PublicKey`] an extended point on the JubJub
/// curve [`JubJubExtended`]. This public key allows for the verification of
/// signatures created with its corresponding secret key without revealing the
/// secret key itself.
///
/// ## Examples
///
/// Generating a random `SecretKey` and signing a message with single and
/// double signatures: ```rust
/// use dusk_schnorr::{SecretKey, PublicKey, PublicKeyPair};
/// use dusk_bls12_381::BlsScalar;
/// use rand::rngs::StdRng;
/// use rand::SeedableRng;
///
/// let mut rng = StdRng::seed_from_u64(12345);
/// let secret_key = SecretKey::random(&mut rng);
///
/// let pk = PublicKey::from(&sk);
/// let pk_pair: PublicKeyPair::from(&sk);
/// ```
#[derive(Default, Copy, Clone, HexDebug)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct PublicKey(pub(crate) JubJubExtended);

impl From<&SecretKey> for PublicKey {
    fn from(sk: &SecretKey) -> Self {
        let public_key = GENERATOR_EXTENDED * sk.0;

        PublicKey(public_key)
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.get_u() * other.0.get_z() == other.0.get_u() * self.0.get_z()
            && self.0.get_v() * other.0.get_z()
                == other.0.get_v() * self.0.get_z()
    }
}

impl Eq for PublicKey {}

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

impl Serializable<32> for PublicKey {
    type Error = Error;

    fn to_bytes(&self) -> [u8; 32] {
        JubJubAffine::from(self.0).to_bytes()
    }

    fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        let public_key: JubJubAffine =
            match JubJubAffine::from_bytes(*bytes).into() {
                Some(pk) => pk,
                None => return Err(Error::InvalidData),
            };
        Ok(Self(public_key.into()))
    }
}

impl PublicKey {
    /// Create a public key from its internal parts
    ///
    /// The public keys are generated from a bijective function that takes a
    /// secret keys domain. If keys are generated directly from curve
    /// points, there is no guarantee a secret key exists - in fact, the
    /// discrete logarithm property will guarantee the secret key cannot be
    /// extracted from this public key.
    ///
    /// If you opt to generate the keys manually, be sure you have its secret
    /// counterpart - otherwise this key will be of no use.
    pub const fn from_raw_unchecked(key: JubJubExtended) -> Self {
        Self(key)
    }
}

/// Structure representing a pair of [`PublicKey`] objects generated from a
/// [`SecretKey`].
///
/// The `PublicKeyPair` struct contains two public keys: `(pk, pk')`,
/// which are generated from different bases.
/// Specifically: `pk = sk * G` with the standard generator point [`G`],
/// and `pk' = sk * G_NUMS` with generator point [`G_NUMS`].
///
/// This construct allows for a double-key mechanism to enable more advanced
/// uses then the single-key variant. For example, it is used in Phoenix for
/// proof delegation while preventing the leakage of secret keys.
///
/// ## Fields
///
/// - `(pk, pk')`: A [`PublicKey`] pair
///
/// ## Example
/// ```
/// use rand::thread_rng;
/// use dusk_schnorr::{SecretKey, PublicKeyPair};
///
/// let sk = SecretKey::random(&mut thread_rng());
/// let pk_pair = PublicKeyPair::from(&sk);
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
pub struct PublicKeyPair(pub(crate) PublicKey, pub(crate) PublicKey);

impl PublicKeyPair {
    /// Returns the `PublicKey` corresponding to the standard elliptic curve
    /// generator point `sk * G`.
    #[allow(non_snake_case)]
    pub fn pk(&self) -> &PublicKey {
        &self.0
    }

    /// Returns the `PublicKey` corresponding to the secondary elliptic
    /// curve generator point `sk * G_NUM`.
    #[allow(non_snake_case)]
    pub fn pk_prime(&self) -> &PublicKey {
        &self.1
    }
}

impl From<&SecretKey> for PublicKeyPair {
    fn from(sk: &SecretKey) -> Self {
        let public_key = PublicKey::from(sk);
        let public_key_prime =
            PublicKey::from(GENERATOR_NUMS_EXTENDED * sk.as_ref());

        PublicKeyPair(public_key, public_key_prime)
    }
}

impl From<SecretKey> for PublicKeyPair {
    fn from(sk: SecretKey) -> Self {
        (&sk).into()
    }
}

impl Serializable<64> for PublicKeyPair {
    type Error = Error;

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[..32].copy_from_slice(&self.0.to_bytes()[..]);
        buf[32..].copy_from_slice(&self.1.to_bytes()[..]);
        buf
    }

    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let pk: JubJubExtended = JubJubAffine::from_slice(&bytes[..32])?.into();
        let pk_prime: JubJubExtended =
            JubJubAffine::from_slice(&bytes[32..])?.into();
        Ok(PublicKeyPair(pk.into(), pk_prime.into()))
    }
}
