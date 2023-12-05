// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use dusk_plonk::error::Error as PlonkError;
use dusk_schnorr::{gadgets, DoubleSignature, SecretKey, Signature};
use rand::rngs::StdRng;
use rand::SeedableRng;

use dusk_plonk::prelude::*;

lazy_static::lazy_static! {
    pub static ref PP: PublicParameters = {
        let rng = &mut StdRng::seed_from_u64(2321u64);

        PublicParameters::setup(1 << 13, rng)
            .expect("Failed to generate PP")
    };
}

const LABEL: &[u8] = b"dusk-network";

//
// Test single_key_verify
//
#[derive(Debug, Default)]
struct SingleSigCircuit {
    signature: Signature,
    pk: JubJubExtended,
    message: BlsScalar,
}

impl SingleSigCircuit {
    pub fn valid_random(rng: &mut StdRng) -> Self {
        let sk = SecretKey::random(rng);
        let message = BlsScalar::uni_random(rng);
        let signature = sk.sign(rng, message);

        let pk = GENERATOR_EXTENDED * sk.as_ref();

        Self {
            signature,
            pk,
            message,
        }
    }

    pub fn invalid_random(rng: &mut StdRng) -> Self {
        let sk = SecretKey::random(rng);
        let message = BlsScalar::uni_random(rng);
        let signature = sk.sign(rng, message);

        let sk_wrong = SecretKey::random(rng);
        let pk = GENERATOR_EXTENDED * sk_wrong.as_ref();

        Self {
            signature,
            pk,
            message,
        }
    }
}

impl Circuit for SingleSigCircuit {
    fn circuit<C: Composer>(&self, composer: &mut C) -> Result<(), PlonkError> {
        let (u, r) = self.signature.append(composer);

        let pk = composer.append_point(self.pk);
        let msg = composer.append_witness(self.message);

        gadgets::single_key_verify(composer, u, r, pk, msg)?;

        Ok(())
    }
}

#[test]
fn single_key() {
    let mut rng = StdRng::seed_from_u64(0xfeeb);

    // Create prover and verifier circuit description
    let (prover, verifier) = Compiler::compile::<SingleSigCircuit>(&PP, LABEL)
        .expect("Circuit should compile successfully");

    //
    // Check valid circuit verifies
    let circuit = SingleSigCircuit::valid_random(&mut rng);

    let (proof, public_inputs) = prover
        .prove(&mut rng, &circuit)
        .expect("Proving the circuit should be successful");

    verifier
        .verify(&proof, &public_inputs)
        .expect("Verification should be successful");

    //
    // Check proof creation of invalid circuit not possible
    let circuit = SingleSigCircuit::invalid_random(&mut rng);

    prover
        .prove(&mut rng, &circuit)
        .expect_err("Proving invalid circuit shouldn't be possible");
}

//
// Test double_key_verify
//
#[derive(Debug, Default)]
struct DoubleSigCircuit {
    signature: DoubleSignature,
    pk: JubJubExtended,
    pk_p: JubJubExtended,
    message: BlsScalar,
}

impl DoubleSigCircuit {
    pub fn valid_random(rng: &mut StdRng) -> Self {
        let sk = SecretKey::random(rng);
        let message = BlsScalar::uni_random(rng);
        let signature = sk.sign_double(rng, message);

        let pk = GENERATOR_EXTENDED * sk.as_ref();
        let pk_p = GENERATOR_NUMS_EXTENDED * sk.as_ref();

        Self {
            signature,
            pk,
            pk_p,
            message,
        }
    }

    pub fn invalid_random(rng: &mut StdRng) -> Self {
        let sk = SecretKey::random(rng);
        let message = BlsScalar::uni_random(rng);
        let signature = sk.sign_double(rng, message);

        let sk_wrong = SecretKey::random(rng);
        let pk = GENERATOR_EXTENDED * sk_wrong.as_ref();
        let pk_p = GENERATOR_NUMS_EXTENDED * sk_wrong.as_ref();

        Self {
            signature,
            pk,
            pk_p,
            message,
        }
    }
}

impl Circuit for DoubleSigCircuit {
    fn circuit<C: Composer>(&self, composer: &mut C) -> Result<(), PlonkError> {
        let (u, r, r_p) = self.signature.append(composer);

        let pk = composer.append_point(self.pk);
        let pk_p = composer.append_point(self.pk_p);
        let msg = composer.append_witness(self.message);

        gadgets::double_key_verify(composer, u, r, r_p, pk, pk_p, msg)
            .expect("this is infallible");

        Ok(())
    }
}

#[test]
fn double_key() {
    let mut rng = StdRng::seed_from_u64(0xfeeb);

    // Create prover and verifier circuit description
    let (prover, verifier) = Compiler::compile::<DoubleSigCircuit>(&PP, LABEL)
        .expect("Circuit compilation should succeed");

    //
    // Check valid circuit verifies
    let circuit = DoubleSigCircuit::valid_random(&mut rng);

    let (proof, public_inputs) = prover
        .prove(&mut rng, &circuit)
        .expect("Proving the circuit should succeed");

    verifier
        .verify(&proof, &public_inputs)
        .expect("Verifying the proof should succeed");

    //
    // Check proof creation of invalid circuit not possible
    let circuit = DoubleSigCircuit::invalid_random(&mut rng);

    prover
        .prove(&mut rng, &circuit)
        .expect_err("Proving invalid circuit shouldn't be possible");
}
