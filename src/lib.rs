// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![doc = include_str!("../README.md")]
#![no_std]

mod keys;
mod signatures;

#[cfg(feature = "alloc")]
pub mod gadgets;

#[deprecated(note = "Please use DoubleSignature instead")]
pub type Proof = signatures::double::Signature;

pub use keys::public::{PublicKey, PublicKeyDouble};
pub use keys::secret::SecretKey;
pub use signatures::double::Signature as DoubleSignature;
pub use signatures::Signature;
