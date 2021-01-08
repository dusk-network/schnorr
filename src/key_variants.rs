// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;
use dusk_jubjub::JubJubScalar;

pub mod double_key;
pub mod single_key;

/// Truncate a BLS Scalar to jubjub for safe conversion
pub fn truncate_bls_to_jubjub(c: BlsScalar) -> JubJubScalar {
    // Let the bitmask size be `m`
    // Considering the field size of jubjub is 251 bits, `m < 251`
    // Plonk logical gates will accept only even `m + 1`, so `(m + 1) % 2 == 0`
    //
    // Plonk logical gates will perform the operation from the base bls `r` of
    // 255 bits + 1. `d = r + 1 - (m + 1) = 4`. But, `d = 4` don't respect the
    // previously set constraint, so it must be 6.
    //
    // This way, the scalar will be truncated to `m = r - d = 255 - 6 = 249
    // bits`
    //
    // The constant below is equivalent to 2^250 - 1
    let c = c & BlsScalar([
        0x432667a3f7cfca74,
        0x7905486e121a84be,
        0x19c02884cfe90d12,
        0xa62ffba6a1323be,
    ]);

    JubJubScalar::from_raw(c.reduce().0)
}
