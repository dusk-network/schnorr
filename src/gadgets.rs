// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! # Schnorr Signature Gadgets
//!
//! This module provides Plonk gadgets for verification of Schnorr signatures.

use dusk_jubjub::{GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use dusk_poseidon::sponge;

use dusk_plonk::prelude::*;

/// Verifies a single-key Schnorr signature within a Plonk circuit without
/// requiring the secret key as a witness.
///
/// The function performs Schnorr verification by calculating the challenge and
/// confirming the signature equation.
///
/// ### Parameters
///
/// - `composer`: A mutable reference to the Plonk [`Composer`]`.
/// - `u`: Witness for the random nonce used during signature generation.
/// - `r`: Witness Point representing the nonce point `r = u*G`.
/// - `pk`: Witness Point representing the public key `pk = sk*G`.
/// - `msg`: Witness for the message.
///
/// ### Returns
///
/// - `Result<(), Error>`: Returns an empty `Result` on successful verification
///   or an `Error` if the witness `u` is not a valid [`JubJubScalar`].
///
/// ### Errors
///
/// This function will return an `Error` if the witness `u` is not a valid
/// [`JubJubScalar`].
pub fn single_key_verify<C: Composer>(
    composer: &mut C,
    u: Witness,
    r: WitnessPoint,
    pk: WitnessPoint,
    msg: Witness,
) -> Result<(), Error> {
    let r_x = *r.x();
    let r_y = *r.y();

    let challenge = [r_x, r_y, msg];
    let challenge_hash = sponge::truncated::gadget(composer, &challenge);

    let s_a = composer.component_mul_generator(u, GENERATOR_EXTENDED)?;
    let s_b = composer.component_mul_point(challenge_hash, pk);
    let point = composer.component_add_point(s_a, s_b);

    composer.assert_equal_point(r, point);

    Ok(())
}

/// Verifies a double-key Schnorr proof within a Plonk circuit without requiring
/// the secret key as a witness.
///
/// This function is an extended version of `single_key_verify`, optimized for
/// double key pairs.
///
/// ### Parameters
///
/// - `composer`: A mutable reference to the Plonk [`Composer`].
/// - `u`: Witness for the random nonce used during signature generation.
/// - `r`: Witness Point representing the nonce points `r = u*G`
/// - `r_p`: Witness Point representing the nonce points `r_p = u*G_prime`.
/// - `pk`: Witness Point public key `pk = sk*G`
/// - `pk_p`: Witness Point public key `pk_p = sk*G_prime`
/// - `msg`: Witness for the message.
///
/// ### Returns
///
/// - `Result<(), Error>`: Returns an empty `Result` on successful verification
///   or an `Error` if the witness `u` is not a valid [`JubJubScalar`].
///
/// ### Errors
///
/// This function will return an `Error` if the witness `u` is not a valid
/// [`JubJubScalar`].
pub fn double_key_verify<C: Composer>(
    composer: &mut C,
    u: Witness,
    r: WitnessPoint,
    r_p: WitnessPoint,
    pk: WitnessPoint,
    pk_p: WitnessPoint,
    msg: Witness,
) -> Result<(), Error> {
    let r_x = *r.x();
    let r_y = *r.y();

    let r_p_x = *r_p.x();
    let r_p_y = *r_p.y();

    let challenge = [r_x, r_y, r_p_x, r_p_y, msg];
    let challenge_hash = sponge::truncated::gadget(composer, &challenge);

    let s_a = composer.component_mul_generator(u, GENERATOR_EXTENDED)?;
    let s_b = composer.component_mul_point(challenge_hash, pk);
    let point = composer.component_add_point(s_a, s_b);

    let s_p_a = composer.component_mul_generator(u, GENERATOR_NUMS_EXTENDED)?;
    let s_p_b = composer.component_mul_point(challenge_hash, pk_p);
    let point_p = composer.component_add_point(s_p_a, s_p_b);

    composer.assert_equal_point(r, point);
    composer.assert_equal_point(r_p, point_p);

    Ok(())
}
