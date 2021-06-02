// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![no_std]

pub mod gadgets;
mod key_variants;

pub use key_variants::double_key::{Proof, PublicKeyPair};
pub use key_variants::single_key::Signature;
