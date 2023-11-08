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

## Schnorr Sigma Protocol

The signature scheme implemented within the Phoenix protocol is based on the Schnorr Sigma protocol, compiled alongside the Fiat–Shamir transformation, to serve as a non-interactive signature scheme. Specifically, the Phoenix protocol employs a variant that utilizes double keys, enabling the delegation of computational processes within the protocol's later stages.

### Signature Scheme Description

The details of the signature scheme are as follows:

- **Setup**: A secret key `sk` is sampled from the finite field `F_t`, and corresponding public keys are computed as `pk = sk * G` and `pk' = sk * G'`, where `G` and `G'` are generators of the JubJub elliptic curve group `J`. The public key pair is represented as `(pk, pk')`.

- **Signing Process**: To sign a message `m` using the secret key `sk`, a random scalar `r` is drawn from `F_t`. The commitment points `(R, R')` are calculated by multiplying `r` with the base points `G` and `G'`. A challenge `c` is derived by hashing the tuple `(m, R, R')`, and the response `u` is computed as `u = r - c * sk`. The signature is then the tuple `(R, R', u)`.

- **Verification Procedure**: Given a public key pair `(pk, pk')`, a message `m`, and a signature `(R, R', u)`, the verification involves recalculating the challenge `c` using the hash of `(m, R, R')` and checking if the equalities `R = u * G + c * pk` and `R' = u * G' + c * pk'` are satisfied. If both equalities hold, the signature is deemed valid.

### Notes on Security and Implementation

The implemented signature scheme is existentially unforgeable under chosen-message attacks assuming the hardness of the discrete logarithm problem in the random oracle model. This property is detailed in Section 12.5.1 of Katz and Lindell's Introduction to Modern Cryptography.

While the basic Schnorr signature scheme is a widely recognized construct, the double-key variant as employed by Phoenix is a novel introduction. In the context of the transaction protocol, this allows for the delegation of proof computations without compromising the confidentiality of the signer's secret key.

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
    assert!(signature.verify(&pk, message), "The signature should be valid.");
}
```

## Licensing
This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at http://mozilla.org/MPL/2.0/.

Copyright (c) DUSK NETWORK. All rights reserved.