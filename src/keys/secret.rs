// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bytes::{Error, HexDebug, Serializable};
use dusk_jubjub::JubJubScalar;
use rand_core::{CryptoRng, RngCore};

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
