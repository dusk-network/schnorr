// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! # Signatures
//!
//! Modules for single-key and double-key Schnorr signatures.
//!
//! - `single_key`: Standard Schnorr signature.
//! - `double_key`: Advanced Schnorr signature with double-key mechanism.
pub mod double_key;
pub mod single_key;
