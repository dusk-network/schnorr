// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::{double_key, gadgets, single_key};

use anyhow::Result;
use dusk_plonk::constraint_system::ecc::Point;
use dusk_plonk::prelude::*;
use rand::rngs::StdRng;

#[derive(Debug, Clone)]
pub struct SingleKeyCircuit {
    signature: single_key::Signature,
    sk: single_key::SecretKey,
    pk: single_key::PublicKey,
    message: BlsScalar,
    pub_inputs: Vec<PublicInput>,
}

impl SingleKeyCircuit {
    pub fn new(
        signature: single_key::Signature,
        sk: single_key::SecretKey,
        pk: single_key::PublicKey,
        message: BlsScalar,
    ) -> Self {
        Self {
            signature,
            sk,
            pk,
            message,
            pub_inputs: vec![],
        }
    }
}

impl Circuit<'_> for SingleKeyCircuit {
    #[allow(non_snake_case)]
    fn gadget(&mut self, composer: &mut StandardComposer) -> Result<()> {
        let R = Point::from_private_affine(composer, self.signature.R().into());
        let u = composer.add_input(self.signature.u().clone().into());
        let PK = Point::from_private_affine(composer, self.pk.as_ref().into());
        let message = composer.add_input(self.message);

        gadgets::single_key_verify(composer, R, u, PK, message);

        let s = composer.circuit_size();
        let pk = self.pk.as_ref().into();
        self.pub_inputs.push(PublicInput::AffinePoint(pk, s, s + 1));
        composer.assert_equal_public_point(PK, pk);

        Ok(())
    }

    fn get_pi_positions(&self) -> &Vec<PublicInput> {
        &self.pub_inputs
    }

    fn get_mut_pi_positions(&mut self) -> &mut Vec<PublicInput> {
        &mut self.pub_inputs
    }

    fn get_trim_size(&self) -> usize {
        1 << 13
    }

    fn set_trim_size(&mut self, _size: usize) {}
}

#[derive(Debug, Clone)]
pub struct DoubleKeyCircuit {
    signature: double_key::Signature,
    sk: double_key::SecretKey,
    pk: double_key::PublicKeyPair,
    message: BlsScalar,
    pub_inputs: Vec<PublicInput>,
}

impl DoubleKeyCircuit {
    pub fn new(
        signature: double_key::Signature,
        sk: double_key::SecretKey,
        pk: double_key::PublicKeyPair,
        message: BlsScalar,
    ) -> Self {
        Self {
            signature,
            sk,
            pk,
            message,
            pub_inputs: vec![],
        }
    }
}

impl Circuit<'_> for DoubleKeyCircuit {
    #[allow(non_snake_case)]
    fn gadget(&mut self, composer: &mut StandardComposer) -> Result<()> {
        let R = Point::from_private_affine(composer, self.signature.R().into());
        let R_prime = Point::from_private_affine(
            composer,
            self.signature.R_prime().into(),
        );
        let u = composer.add_input(self.signature.u().clone().into());
        let PK = Point::from_private_affine(composer, self.pk.PK().into());
        let PK_prime =
            Point::from_private_affine(composer, self.pk.PK_prime().into());
        let message = composer.add_input(self.message);

        gadgets::double_key_verify(
            composer, R, R_prime, u, PK, PK_prime, message,
        );

        let s = composer.circuit_size();
        let pk = self.pk.PK().into();
        self.pub_inputs.push(PublicInput::AffinePoint(pk, s, s + 1));
        composer.assert_equal_public_point(PK, pk);

        let s = composer.circuit_size();
        let pk_prime = self.pk.PK_prime().into();
        self.pub_inputs
            .push(PublicInput::AffinePoint(pk_prime, s, s + 1));
        composer.assert_equal_public_point(PK_prime, pk_prime);

        Ok(())
    }

    fn get_pi_positions(&self) -> &Vec<PublicInput> {
        &self.pub_inputs
    }

    fn get_mut_pi_positions(&mut self) -> &mut Vec<PublicInput> {
        &mut self.pub_inputs
    }

    fn get_trim_size(&self) -> usize {
        1 << 13
    }

    fn set_trim_size(&mut self, _size: usize) {}
}

pub fn gen_single(
    rng: &mut StdRng,
) -> (
    single_key::SecretKey,
    single_key::PublicKey,
    BlsScalar,
    single_key::Signature,
) {
    let sk = single_key::SecretKey::new(rng);
    let pk = single_key::PublicKey::from(&sk);
    let message = BlsScalar::random(rng);
    let signature = sk.sign(rng, message);

    (sk, pk, message, signature)
}

pub fn gen_double(
    rng: &mut StdRng,
) -> (
    double_key::SecretKey,
    double_key::PublicKeyPair,
    BlsScalar,
    double_key::Signature,
) {
    let sk = double_key::SecretKey::new(rng);
    let pk = double_key::PublicKeyPair::from(&sk);
    let message = BlsScalar::random(rng);
    let signature = sk.sign(rng, message);

    (sk, pk, message, signature)
}
