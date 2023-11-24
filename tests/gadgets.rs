// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_plonk::error::Error as PlonkError;
use dusk_schnorr::{gadgets, PublicKey, SecretKey, Signature};
use ff::Field;
use rand::rngs::StdRng;
use rand::SeedableRng;

use dusk_plonk::prelude::*;

#[cfg(feature = "double")]
use dusk_schnorr::{PublicKeyDouble, SignatureDouble};

#[cfg(feature = "var_generator")]
use dusk_schnorr::{PublicKeyVarGen, SecretKeyVarGen, SignatureVarGen};

lazy_static::lazy_static! {
    pub static ref PP: PublicParameters = {
        let rng = &mut StdRng::seed_from_u64(2321u64);

        PublicParameters::setup(1 << 13, rng)
            .expect("Failed to generate PP")
    };
}

const LABEL: &[u8] = b"dusk-network";

//
// Test verify_signature
//
#[derive(Debug, Default)]
struct SignatureCircuit {
    signature: Signature,
    pk: PublicKey,
    message: BlsScalar,
}

impl SignatureCircuit {
    pub fn valid_random(rng: &mut StdRng) -> Self {
        let sk = SecretKey::random(rng);
        let message = BlsScalar::random(&mut *rng);
        let signature = sk.sign(rng, message);

        let pk = PublicKey::from(&sk);

        Self {
            signature,
            pk,
            message,
        }
    }

    pub fn invalid_random(rng: &mut StdRng) -> Self {
        let sk = SecretKey::random(rng);
        let message = BlsScalar::random(&mut *rng);
        let signature = sk.sign(rng, message);

        let sk_wrong = SecretKey::random(rng);
        let pk = PublicKey::from(&sk_wrong);

        Self {
            signature,
            pk,
            message,
        }
    }
}

impl Circuit for SignatureCircuit {
    fn circuit<C: Composer>(&self, composer: &mut C) -> Result<(), PlonkError> {
        let (u, r) = self.signature.append(composer);

        let pk = composer.append_point(self.pk.as_ref());
        let msg = composer.append_witness(self.message);

        gadgets::verify_signature(composer, u, r, pk, msg)?;

        Ok(())
    }
}

#[test]
fn verify_signature() {
    let mut rng = StdRng::seed_from_u64(0xfeeb);

    // Create prover and verifier circuit description
    let (prover, verifier) = Compiler::compile::<SignatureCircuit>(&PP, LABEL)
        .expect("Circuit should compile successfully");

    //
    // Check valid circuit verifies
    let circuit = SignatureCircuit::valid_random(&mut rng);

    let (proof, _) = prover
        .prove(&mut rng, &circuit)
        .expect("Proving the circuit should be successful");

    let pub_inputs = vec![];
    verifier
        .verify(&proof, &pub_inputs)
        .expect("Verification should be successful");

    //
    // Check proof creation of invalid circuit not possible
    let circuit = SignatureCircuit::invalid_random(&mut rng);

    prover
        .prove(&mut rng, &circuit)
        .expect_err("Proving invalid circuit shouldn't be possible");
}

//
// Test verify_signature_double
//
#[derive(Debug, Default)]
#[cfg(feature = "double")]
struct SignatureDoubleCircuit {
    signature: SignatureDouble,
    pk_double: PublicKeyDouble,
    message: BlsScalar,
}

#[cfg(feature = "double")]
impl SignatureDoubleCircuit {
    pub fn valid_random(rng: &mut StdRng) -> Self {
        let sk = SecretKey::random(rng);
        let message = BlsScalar::random(&mut *rng);
        let signature = sk.sign_double(rng, message);

        let pk_double = PublicKeyDouble::from(&sk);

        Self {
            signature,
            pk_double,
            message,
        }
    }

    pub fn invalid_random(rng: &mut StdRng) -> Self {
        let sk = SecretKey::random(rng);
        let message = BlsScalar::random(&mut *rng);
        let signature = sk.sign_double(rng, message);

        let sk_wrong = SecretKey::random(rng);
        let pk_double = PublicKeyDouble::from(&sk_wrong);

        Self {
            signature,
            pk_double,
            message,
        }
    }
}

#[cfg(feature = "double")]
impl Circuit for SignatureDoubleCircuit {
    fn circuit<C: Composer>(&self, composer: &mut C) -> Result<(), PlonkError> {
        let (u, r, r_p) = self.signature.append(composer);

        let pk = composer.append_point(self.pk_double.pk());
        let pk_p = composer.append_point(self.pk_double.pk_prime());
        let msg = composer.append_witness(self.message);

        gadgets::verify_signature_double(composer, u, r, r_p, pk, pk_p, msg)
            .expect("this is infallible");

        Ok(())
    }
}

#[test]
#[cfg(feature = "double")]
fn verify_signature_double() {
    let mut rng = StdRng::seed_from_u64(0xfeeb);

    // Create prover and verifier circuit description
    let (prover, verifier) =
        Compiler::compile::<SignatureDoubleCircuit>(&PP, LABEL)
            .expect("Circuit compilation should succeed");

    //
    // Check valid circuit verifies
    let circuit = SignatureDoubleCircuit::valid_random(&mut rng);

    let (proof, _) = prover
        .prove(&mut rng, &circuit)
        .expect("Proving the circuit should succeed");

    let pub_inputs = vec![];
    verifier
        .verify(&proof, &pub_inputs)
        .expect("Verifying the proof should succeed");

    //
    // Check proof creation of invalid circuit not possible
    let circuit = SignatureDoubleCircuit::invalid_random(&mut rng);

    prover
        .prove(&mut rng, &circuit)
        .expect_err("Proving invalid circuit shouldn't be possible");
}

//
// Test verify_signature_var_gen
//
#[derive(Debug, Default)]
#[cfg(feature = "var_generator")]
struct SignatureVarGenCircuit {
    signature: SignatureVarGen,
    pk_var_gen: PublicKeyVarGen,
    message: BlsScalar,
}

#[cfg(feature = "var_generator")]
impl SignatureVarGenCircuit {
    pub fn valid_random(rng: &mut StdRng) -> Self {
        let sk = SecretKeyVarGen::random(rng);
        let message = BlsScalar::random(&mut *rng);
        let signature = sk.sign(rng, message);

        let pk_var_gen = PublicKeyVarGen::from(&sk);

        Self {
            signature,
            pk_var_gen,
            message,
        }
    }

    pub fn invalid_random(rng: &mut StdRng) -> Self {
        let sk = SecretKeyVarGen::random(rng);
        let message = BlsScalar::random(&mut *rng);
        let signature = sk.sign(rng, message);

        let sk_wrong = SecretKeyVarGen::random(rng);
        let pk_var_gen = PublicKeyVarGen::from(&sk_wrong);

        Self {
            signature,
            pk_var_gen,
            message,
        }
    }
}

#[cfg(feature = "var_generator")]
impl Circuit for SignatureVarGenCircuit {
    fn circuit<C: Composer>(&self, composer: &mut C) -> Result<(), PlonkError> {
        let (u, r) = self.signature.append(composer);

        let pk_var_gen = composer.append_point(self.pk_var_gen.public_key());
        let generator = composer.append_point(self.pk_var_gen.generator());
        let msg = composer.append_witness(self.message);

        gadgets::verify_signature_var_gen(
            composer, u, r, pk_var_gen, generator, msg,
        )?;

        Ok(())
    }
}

#[test]
#[cfg(feature = "var_generator")]
fn verify_signature_var_gen() {
    let mut rng = StdRng::seed_from_u64(0xfeeb);

    // Create prover and verifier circuit description
    let (prover, verifier) =
        Compiler::compile::<SignatureVarGenCircuit>(&PP, LABEL)
            .expect("Circuit should compile successfully");

    //
    // Check valid circuit verifies
    let circuit = SignatureVarGenCircuit::valid_random(&mut rng);

    let (proof, _) = prover
        .prove(&mut rng, &circuit)
        .expect("Proving the circuit should be successful");

    let pub_inputs = vec![];
    verifier
        .verify(&proof, &pub_inputs)
        .expect("Verification should be successful");

    //
    // Check proof creation of invalid circuit not possible
    let circuit = SignatureVarGenCircuit::invalid_random(&mut rng);

    prover
        .prove(&mut rng, &circuit)
        .expect_err("Proving invalid circuit shouldn't be possible");
}
