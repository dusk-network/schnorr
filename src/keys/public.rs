// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use super::secret::NoteSecretKey;
use dusk_bytes::{Error, HexDebug, Serializable};
use dusk_jubjub::{JubJubAffine, JubJubExtended, GENERATOR_EXTENDED};

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
