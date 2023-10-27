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
//!
//! ## Modules
//!
//! - `key_variants`: Contains implementations for both single-key and
//!   double-key variants of Schnorr signatures.
//! - `gadgets`: Provides zero-knowledge gadgets for use in circuits. Available
//!   only when compiled with the `alloc` feature.
//!
//! ## Examples
//!
//! ### Single Key - Signing and verifying a message
//!
//! ```
//! use dusk_bls12_381::BlsScalar;
//! use dusk_pki::{PublicKey, SecretKey};
//! use dusk_schnorr::Signature;
//! use ff::Field;
//! use rand::rngs::StdRng;
//! use rand::SeedableRng;
//!
//! let mut rng = StdRng::seed_from_u64(1234u64);
//!
//! let sk = SecretKey::random(&mut rng);
//! let message = BlsScalar::random(&mut rng);
//! let pk = PublicKey::from(&sk);
//!
//! // Sign the message
//! let signature = Signature::new(&sk, &mut rng, message);
//!
//! // Verify the signature
//! assert!(signature.verify(&pk, message));
//! ```
//!
//! ### Double Key - Signing and verifying a message
//!
//! ```
//! use dusk_bls12_381::BlsScalar;
//! use dusk_pki::SecretKey;
//! use dusk_schnorr::{Proof, PublicKeyPair};
//! use ff::Field;
//! use rand::rngs::StdRng;
//! use rand::SeedableRng;
//!
//! let mut rng = StdRng::seed_from_u64(2321u64);
//!
//! let sk = SecretKey::random(&mut rng);
//! let message = BlsScalar::random(&mut rng);
//! let pk_pair: PublicKeyPair = sk.into();
//!
//! let proof = Proof::new(&sk, &mut rng, message);
//!
//! assert!(proof.verify(&pk_pair, message));
//! ```
#![no_std]

mod key_variants;

#[cfg(feature = "alloc")]
pub mod gadgets;

pub use key_variants::double_key::{Proof, PublicKeyPair};
pub use key_variants::single_key::Signature;
