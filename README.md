# dusk-schnorr
![Build Status](https://github.com/dusk-network/schnorr/workflows/Continuous%20integration/badge.svg)
[![Repository](https://img.shields.io/badge/github-schnorr-blueviolet?logo=github)](https://github.com/dusk-network/schnorr)
[![Documentation](https://img.shields.io/badge/docs-schnorr-blue?logo=rust)](https://docs.rs/schnorr/)

This crate provides a Rust implementation of the Schnorr signature scheme for the JubJub elliptic curve group, using the Poseidon hash function. This implementation is designed by the [Dusk](https://dusk.network) team.

## About
The Schnorr signature scheme, named after its creator Claus Schnorr, is a digital signature scheme renowned for its simplicity. The scheme provides a simple method of creating short signatures. 

The implementation has been created using the
Poseidon hash function, the paper for which can
be found [here](https://eprint.iacr.org/2019/458.pdf).

For a reference to the algorithm, please see the 
[docs](https://app.gitbook.com/@dusk-network/s/specs/proposals/rfc/rfc-17).

## Library Structure
The library is partitioned into two components:

- **Keys**: Module containing the secret note key structure for signing messages, and the public note key & keypair structures used in verification.
- **Signatures**: Module containing functions to verify the validity of Schnorr signatures.
- **Gadgets**: Contains the Plonk gadgets for signature verification.

## Usage
To integrate the `dusk-schnorr` crate into your project, add it with the following command:
```bash
cargo add dusk-schnorr
```

A basic example demonstrating how to generate and verify a Schnorr signature:
```rust
use dusk_bls12_381::BlsScalar;
use dusk_schnorr::{NotePublicKey, NoteSecretKey, Signature};
use rand::rngs::StdRng;
use rand::SeedableRng;

fn main() {
    // Create random number generator with a seed
    let mut rng = StdRng::seed_from_u64(1234u64);

    // Key generation
    let sk = NoteSecretKey::random(&mut rng);
    let pk = NotePublicKey::from(&sk);

    // Sign the message in the form of a BLS scalar
    let message = BlsScalar::uni_random(&mut rng);
    let signature = sk.sign_single(&mut rng, message);

    // Verify the signature
    let is_valid = signature.verify(&pk, message);
    assert!(is_valid, "The signature should be valid.");
}
```

## Licensing
This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at http://mozilla.org/MPL/2.0/.

Copyright (c) DUSK NETWORK. All rights reserved.