// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bytes::{DeserializableSlice, Error, HexDebug, Serializable};
use dusk_jubjub::{
    JubJubAffine, JubJubExtended, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED,
};

use crate::NoteSecretKey;

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

/// Structure repesenting a [`NotePublicKey`]
#[derive(Default, Copy, Clone, HexDebug)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct NotePublicKey(pub(crate) JubJubExtended);

impl From<&NoteSecretKey> for NotePublicKey {
    fn from(sk: &NoteSecretKey) -> Self {
        let public_key = GENERATOR_EXTENDED * sk.0;

        NotePublicKey(public_key)
    }
}

impl PartialEq for NotePublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.get_u() * other.0.get_z() == other.0.get_u() * self.0.get_z()
            && self.0.get_v() * other.0.get_z()
                == other.0.get_v() * self.0.get_z()
    }
}

impl Eq for NotePublicKey {}

impl From<JubJubExtended> for NotePublicKey {
    fn from(p: JubJubExtended) -> NotePublicKey {
        NotePublicKey(p)
    }
}

impl From<&JubJubExtended> for NotePublicKey {
    fn from(p: &JubJubExtended) -> NotePublicKey {
        NotePublicKey(*p)
    }
}

impl AsRef<JubJubExtended> for NotePublicKey {
    fn as_ref(&self) -> &JubJubExtended {
        &self.0
    }
}

impl Serializable<32> for NotePublicKey {
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

impl NotePublicKey {
    /// Create a note public key from its internal parts
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

/// Structure representing a pair of [`NotePublicKey`] objects generated from a
/// [`NoteSecretKey`].
///
/// The `NotePublicKeyPair` struct contains two public keys: `(pk, pk')`,
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
/// - `(pk, pk')`: A [`NotePublicKey`] pair
///
/// ## Example
/// ```
/// use rand::thread_rng;
/// use dusk_schnorr::{NoteSecretKey, NotePublicKeyPair};
///
/// let sk = NoteSecretKey::random(&mut thread_rng());
/// let pk_pair = NotePublicKeyPair::from(&sk);
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
pub struct NotePublicKeyPair(pub(crate) (NotePublicKey, NotePublicKey));

impl NotePublicKeyPair {
    /// Returns the `NotePublicKey` corresponding to the standard elliptic curve
    /// generator point `sk * G`.
    #[allow(non_snake_case)]
    pub fn pk(&self) -> &NotePublicKey {
        &self.0 .0
    }

    /// Returns the `NotePublicKey` corresponding to the secondary elliptic
    /// curve generator point `sk * G_NUM`.
    #[allow(non_snake_case)]
    pub fn pk_prime(&self) -> &NotePublicKey {
        &self.0 .1
    }
}

impl From<&NoteSecretKey> for NotePublicKeyPair {
    fn from(sk: &NoteSecretKey) -> Self {
        let public_key = NotePublicKey::from(sk);
        let public_key_prime =
            NotePublicKey::from(GENERATOR_NUMS_EXTENDED * sk.as_ref());

        NotePublicKeyPair((public_key, public_key_prime))
    }
}

impl From<NoteSecretKey> for NotePublicKeyPair {
    fn from(sk: NoteSecretKey) -> Self {
        (&sk).into()
    }
}

impl Serializable<64> for NotePublicKeyPair {
    type Error = Error;

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[..32].copy_from_slice(&(self.0).0.to_bytes()[..]);
        buf[32..].copy_from_slice(&(self.0).1.to_bytes()[..]);
        buf
    }

    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let pk: JubJubExtended = JubJubAffine::from_slice(&bytes[..32])?.into();
        let pk_prime: JubJubExtended =
            JubJubAffine::from_slice(&bytes[32..])?.into();
        Ok(NotePublicKeyPair((pk.into(), pk_prime.into())))
    }
}
