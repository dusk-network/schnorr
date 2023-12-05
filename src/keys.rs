// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! # Keys
//!
//! Modules for the secret and public keys.
//!
//! - `public`: Contains the public key and double public key. Used in signature
//!   verification.
//! - `secret`: Contains the secret key. Used for signing messages.

pub mod public;
pub mod secret;
