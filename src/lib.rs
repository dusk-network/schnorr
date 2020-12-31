// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg_attr(not(feature = "std"), no_std)]

mod error;
mod key_variants;

#[cfg(feature = "std")]
pub mod zk;

pub use key_variants::{double_key, single_key};
