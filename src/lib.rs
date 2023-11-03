// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! # Schnorr Signatures
//!
//! `schnorr_signatures` is a no-std library implementing the schnorr signature
//! scheme. This library is optimized for zero-knowledge proof applications.
//! It relies on cryptographic primitives such as the Poseidon Hash and the
//! JubJub elliptic Curve.
//!
//! ## Features
//!
//! - **Single-Key Signatures**: Provides the traditional Schnorr single-key
//!   signature functionalities.
//! - **Double-Key Signatures**: Extends to double-key variants for specialized
//!   use-cases.
//! - **Zero-Knowledge Gadgets**: The library offers pluggable zero-knowledge
//!   gadgets when compiled with the `alloc` feature.
//! - **No-Std Support**: This library has a `no_std` feature, making it
//!   compatible for embedded systems.
//!
//! ## Modules
//!
//! - `signatures`: Contains implementations for both single-key and double-key
//!   variants of Schnorr signatures.
//! - `gadgets`: Provides zero-knowledge gadgets for use in circuits. Available
//!   only when compiled with the `alloc` feature.
#![no_std]

mod keys;
mod signatures;

#[cfg(feature = "alloc")]
pub mod gadgets;

#[deprecated(note = "Please use DoubleSignature instead")]
pub type Proof = signatures::double_key::Signature;

pub use keys::public::{NotePublicKey, NotePublicKeyPair};
pub use keys::secret::NoteSecretKey;
pub use signatures::double_key::Signature as DoubleSignature;
pub use signatures::single_key::Signature;
