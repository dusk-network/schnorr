// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::gadgets;
use crate::{Proof, PublicKeyPair, Signature};
use anyhow::Result;
use dusk_pki::{PublicKey, SecretKey};
use dusk_plonk::constraint_system::ecc::Point;
use dusk_plonk::prelude::*;
use rand::rngs::StdRng;

#[derive(Debug, Clone)]
pub struct SingleKeyCircuit {
    signature: Signature,
    sk: SecretKey,
    pk: PublicKey,
    message: BlsScalar,
    pub_inputs: Vec<PublicInput>,
}

impl SingleKeyCircuit {
    pub fn new(
        signature: Signature,
        sk: SecretKey,
        pk: PublicKey,
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
    proof: Proof,
    sk: SecretKey,
    pkp: PublicKeyPair,
    message: BlsScalar,
    pub_inputs: Vec<PublicInput>,
}

impl DoubleKeyCircuit {
    pub fn new(
        proof: Proof,
        sk: SecretKey,
        pkp: PublicKeyPair,
        message: BlsScalar,
    ) -> Self {
        Self {
            proof,
            sk,
            pkp,
            message,
            pub_inputs: vec![],
        }
    }
}

impl Circuit<'_> for DoubleKeyCircuit {
    #[allow(non_snake_case)]
    fn gadget(&mut self, composer: &mut StandardComposer) -> Result<()> {
        let R = Point::from_private_affine(
            composer,
            self.proof.public().R().as_ref().into(),
        );
        let R_prime = Point::from_private_affine(
            composer,
            self.proof.public().R_prime().as_ref().into(),
        );
        let u = composer.add_input(self.proof.u().clone().into());
        let PK = Point::from_private_affine(
            composer,
            (self.pkp.0).0.as_ref().into(),
        );
        let PK_prime = Point::from_private_affine(
            composer,
            (self.pkp.0).1.as_ref().into(),
        );
        let message = composer.add_input(self.message);

        gadgets::double_key_verify(
            composer, R, R_prime, u, PK, PK_prime, message,
        );

        let s = composer.circuit_size();
        let pk = (self.pkp.0).0.as_ref().into();
        self.pub_inputs.push(PublicInput::AffinePoint(pk, s, s + 1));
        composer.assert_equal_public_point(PK, pk);

        let s = composer.circuit_size();
        let pk_prime = (self.pkp.0).1.as_ref().into();
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
) -> (SecretKey, PublicKey, BlsScalar, Signature) {
    let sk = SecretKey::random(rng);
    let pk = PublicKey::from(&sk);
    let message = BlsScalar::random(rng);
    let signature = Signature::new(&sk, rng, message);

    (sk, pk, message, signature)
}

pub fn gen_double(
    rng: &mut StdRng,
) -> (SecretKey, PublicKeyPair, BlsScalar, Proof) {
    let sk = SecretKey::random(rng);
    let pkp = PublicKeyPair::from(sk);

    let message = BlsScalar::random(rng);
    let proof = Proof::new(&sk, rng, message);

    (sk, pkp, message, proof)
}
