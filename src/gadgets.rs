// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_plonk::constraint_system::ecc::Point;
use dusk_plonk::jubjub::{GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use dusk_plonk::prelude::*;
use dusk_poseidon::sponge;

/// Given `R`, assert the signature `u` is correct for `PK` over `message`.
///
/// `R` is expected to be generated from [`crate::single_key::SecretKey::sign`]
#[allow(non_snake_case)]
pub fn single_key_verify(
    composer: &mut StandardComposer,
    R: Point,
    u: Variable,
    PK: Point,
    message: Variable,
) {
    let c_hash = sponge::gadget(composer, &[*R.x(), *R.y(), message]);

    let m = composer.add_witness_to_circuit_description(BlsScalar::zero());
    let c = composer.xor_gate(c_hash, m, 250);

    let p1_l = composer.fixed_base_scalar_mul(u, GENERATOR_EXTENDED);
    let p1_r = composer.variable_base_scalar_mul(c, PK);
    let p1 = composer.point_addition_gate(p1_l, p1_r);

    composer.assert_equal_point(p1, R);
}

/// Given `(R, R_prime)`, assert the signature `u` is correct for the pair `(PK,
/// PK_prime)` over `message`.
///
/// `(R, R_prime, u)` is expected to be generated from
/// [`crate::double_key::SecretKey::sign`]
#[allow(non_snake_case)]
pub fn double_key_verify(
    composer: &mut StandardComposer,
    R: Point,
    R_prime: Point,
    u: Variable,
    PK: Point,
    PK_prime: Point,
    message: Variable,
) {
    let c_hash = sponge::gadget(
        composer,
        &[*R.x(), *R.y(), *R_prime.x(), *R_prime.y(), message],
    );

    let m = composer.add_witness_to_circuit_description(BlsScalar::zero());
    let c = composer.xor_gate(c_hash, m, 250);

    let p1_l = composer.fixed_base_scalar_mul(u, GENERATOR_EXTENDED);
    let p1_r = composer.variable_base_scalar_mul(c, PK);
    let p1 = composer.point_addition_gate(p1_l, p1_r);

    let p2_l = composer.fixed_base_scalar_mul(u, GENERATOR_NUMS_EXTENDED);
    let p2_r = composer.variable_base_scalar_mul(c, PK_prime);
    let p2 = composer.point_addition_gate(p2_l, p2_r);

    composer.assert_equal_point(p1, R);
    composer.assert_equal_point(p2, R_prime);
}
