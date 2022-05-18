// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use criterion::{criterion_group, criterion_main, Criterion};

use dusk_jubjub::{GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use dusk_pki::SecretKey;
use dusk_plonk::error::Error as PlonkError;
use dusk_schnorr::{gadgets, Proof, Signature};
use rand::rngs::StdRng;
use rand::SeedableRng;

use dusk_plonk::prelude::*;

const CAPACITY: usize = 13;

lazy_static::lazy_static! {
    pub static ref PP: PublicParameters = {
        let rng = &mut StdRng::seed_from_u64(2321u64);

        PublicParameters::setup(1 << CAPACITY, rng)
            .expect("Failed to generate PP")
    };
}

static mut CONSTRAINTS: usize = 0;
static LABEL: &[u8; 12] = b"dusk-network";

#[derive(Debug)]
struct TestSingleKey {
    signature: Signature,
    k: JubJubExtended,
    message: BlsScalar,
}

impl Default for TestSingleKey {
    fn default() -> Self {
        let rng = &mut StdRng::seed_from_u64(0xbeef);

        let sk = SecretKey::random(rng);
        let message = BlsScalar::random(rng);
        let signature = Signature::new(&sk, rng, message);

        let k = GENERATOR_EXTENDED * sk.as_ref();

        Self {
            signature,
            k,
            message,
        }
    }
}

impl TestSingleKey {
    pub fn new(
        signature: Signature,
        k: JubJubExtended,
        message: BlsScalar,
    ) -> Self {
        Self {
            signature,
            k,
            message,
        }
    }
}

impl Circuit for TestSingleKey {
    const CIRCUIT_ID: [u8; 32] = [0xff; 32];
    fn gadget(
        &mut self,
        composer: &mut TurboComposer,
    ) -> Result<(), PlonkError> {
        let (u, r) = self.signature.to_witness(composer);

        let k = composer.append_point(self.k);
        let m = composer.append_witness(self.message);

        gadgets::single_key_verify(composer, u, r, k, m);

        unsafe {
            CONSTRAINTS = composer.gates();
        }

        Ok(())
    }

    fn public_inputs(&self) -> Vec<PublicInputValue> {
        vec![]
    }

    fn padded_gates(&self) -> usize {
        1 << CAPACITY - 1
    }
}

struct TestDoubleKey {
    proof: Proof,
    k: JubJubExtended,
    k_p: JubJubExtended,
    message: BlsScalar,
}

impl Default for TestDoubleKey {
    fn default() -> Self {
        let rng = &mut StdRng::seed_from_u64(0xbeef);

        let sk = SecretKey::random(rng);
        let message = BlsScalar::random(rng);
        let proof = Proof::new(&sk, rng, message);

        let k = GENERATOR_EXTENDED * sk.as_ref();
        let k_p = GENERATOR_NUMS_EXTENDED * sk.as_ref();

        Self {
            proof,
            k,
            k_p,
            message,
        }
    }
}

impl TestDoubleKey {
    pub fn new(
        proof: Proof,
        k: JubJubExtended,
        k_p: JubJubExtended,
        message: BlsScalar,
    ) -> Self {
        Self {
            proof,
            k,
            k_p,
            message,
        }
    }
}

impl Circuit for TestDoubleKey {
    const CIRCUIT_ID: [u8; 32] = [0xff; 32];
    fn gadget(
        &mut self,
        composer: &mut TurboComposer,
    ) -> Result<(), PlonkError> {
        let (u, r, r_p) = self.proof.to_witness(composer);

        let k = composer.append_point(self.k);
        let k_p = composer.append_point(self.k_p);
        let m = composer.append_witness(self.message);

        gadgets::double_key_verify(composer, u, r, r_p, k, k_p, m);

        unsafe {
            CONSTRAINTS = composer.gates();
        }

        Ok(())
    }

    fn public_inputs(&self) -> Vec<PublicInputValue> {
        vec![]
    }

    fn padded_gates(&self) -> usize {
        1 << CAPACITY
    }
}

fn single_key_prover(input: &TestSingleKey, pk: &ProverKey) {
    TestSingleKey::new(input.signature, input.k, input.message)
        .prove(&PP, &pk, LABEL)
        .expect("Failed to prove");
}

fn double_key_prover(input: &TestDoubleKey, pk: &ProverKey) {
    TestDoubleKey::new(input.proof, input.k, input.k_p, input.message)
        .prove(&PP, &pk, LABEL)
        .expect("Failed to prove");
}

fn schnorr_benchmark(c: &mut Criterion) {
    //** SINGLE KEY BENCHMARK *****************************

    // We compile the circuit using the public
    // parameters PP
    let (pk, _vd) = TestSingleKey::default()
        .compile(&PP)
        .expect("Failed to compile circuit");

    // We compute a testing input for the circuit
    let input = TestSingleKey::default();

    // We benchmark the prover
    unsafe {
        let log = &format!("Single Key Prover ({} constraints)", CONSTRAINTS);
        c.bench_function(log, |b| b.iter(|| single_key_prover(&input, &pk)));
    }

    //** DOUBLE KEY BENCHMARK *****************************

    // We compile the circuit using the public
    // parameters PP
    let (pk, _vd) = TestDoubleKey::default()
        .compile(&PP)
        .expect("Failed to compile circuit");

    // We compute a testing input for the circuit
    let input = TestDoubleKey::default();

    // We benchmark the prover
    unsafe {
        let log = &format!("Double Key Prover ({} constraints)", CONSTRAINTS);
        c.bench_function(log, |b| b.iter(|| double_key_prover(&input, &pk)));
    }
}

criterion_group! {
    name = schnorr;
    config = Criterion::default().sample_size(10);
    targets = schnorr_benchmark
}
criterion_main!(schnorr);
