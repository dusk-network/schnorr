# Schnorr
![Build Status](https://github.com/dusk-network/schnorr/workflows/Continuous%20integration/badge.svg)
[![Repository](https://img.shields.io/badge/github-schnorr-blueviolet?logo=github)](https://github.com/dusk-network/schnorr)
[![Documentation](https://img.shields.io/badge/docs-schnorr-blue?logo=rust)](https://docs.rs/schnorr/)

Implementation of the Schnorr for JubJub curve
group using Poseidon as the hash function.
Implementation designed by the [dusk](https://dusk.network)
team. 

## About
The Schnorr signature algorithm, given its namesake
by its creator Claus Schnorr, is a digital signature 
scheme which provides a simple method of creating 
short signatures. 

The implementation has been created using the
Poseidon hash function, the paper for which can
be found [here](https://eprint.iacr.org/2019/458.pdf).

For a reference to the algorithm, please see the 
[docs](https://app.gitbook.com/@dusk-network/s/specs/proposals/rfc/rfc-17).

**This structure of this library is as follows:**

- Signature Generation
- Signature Verification

## Licensing
This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at http://mozilla.org/MPL/2.0/.

Copyright (c) DUSK NETWORK. All rights reserved.