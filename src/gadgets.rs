// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use dusk_poseidon::sponge::truncated;

use dusk_plonk::prelude::*;

/// Assert the correctness of the schnorr signature without using the secret key
/// as witness.
pub fn single_key_verify<C: Composer>(
    composer: &mut C,
    u: Witness,
    r: WitnessPoint,
    k: WitnessPoint,
    m: Witness,
) -> Result<(), Error> {
    let r_x = *r.x();
    let r_y = *r.y();

    let c = [r_x, r_y, m];
    let c = truncated::gadget(composer, &c);

    let s_a = composer.component_mul_generator(u, GENERATOR_EXTENDED)?;
    let s_b = composer.component_mul_point(c, k);
    let s = composer.component_add_point(s_a, s_b);

    composer.assert_equal_point(r, s);

    Ok(())
}

/// Assert the correctness of the schnorr proof without using the secret key as
/// witness.
pub fn double_key_verify<C: Composer>(
    composer: &mut C,
    u: Witness,
    r: WitnessPoint,
    r_p: WitnessPoint,
    k: WitnessPoint,
    k_p: WitnessPoint,
    m: Witness,
) -> Result<(), Error> {
    let r_x = *r.x();
    let r_y = *r.y();

    let r_p_x = *r_p.x();
    let r_p_y = *r_p.y();

    let c = [r_x, r_y, r_p_x, r_p_y, m];
    let c = truncated::gadget(composer, &c);

    let s_a = composer.component_mul_generator(u, GENERATOR_EXTENDED)?;
    let s_b = composer.component_mul_point(c, k);
    let s = composer.component_add_point(s_a, s_b);

    let s_p_a = composer.component_mul_generator(u, GENERATOR_NUMS_EXTENDED)?;
    let s_p_b = composer.component_mul_point(c, k_p);
    let s_p = composer.component_add_point(s_p_a, s_p_b);

    composer.assert_equal_point(r, s);
    composer.assert_equal_point(r_p, s_p);

    Ok(())
}
