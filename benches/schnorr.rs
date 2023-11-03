// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use criterion::{criterion_group, criterion_main, Criterion};

use dusk_jubjub::{GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use dusk_plonk::error::Error as PlonkError;
use dusk_schnorr::{gadgets, DoubleSignature, NoteSecretKey, Signature};
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

fn bench_prover<C>(rng: &mut StdRng, prover: &Prover, circuit: &C)
where
    C: Circuit,
{
    prover
        .prove(rng, circuit)
        .expect("proof creation of valid circuit should succeed");
}

//** SINGLE KEY BENCHMARK *****************************
#[derive(Debug, Default)]
struct SingleSigCircuit {
    signature: Signature,
    pub_key: JubJubExtended,
    message: BlsScalar,
}

impl SingleSigCircuit {
    pub fn valid(rng: &mut StdRng) -> Self {
        let sk = NoteSecretKey::random(rng);
        let message = BlsScalar::uni_random(rng);
        let signature = sk.sign_single(rng, message);

        let pub_key = GENERATOR_EXTENDED * sk.as_ref();

        Self {
            signature,
            pub_key,
            message,
        }
    }
}

impl Circuit for SingleSigCircuit {
    fn circuit<C>(&self, composer: &mut C) -> Result<(), PlonkError>
    where
        C: Composer,
    {
        let (u, r) = self.signature.append(composer);

        let pub_key = composer.append_point(self.pub_key);
        let m = composer.append_witness(self.message);

        let _result = gadgets::single_key_verify(composer, u, r, pub_key, m);

        unsafe {
            CONSTRAINTS = composer.constraints();
        }

        Ok(())
    }
}

fn single_key_proof_creation(c: &mut Criterion) {
    let mut rng = &mut StdRng::seed_from_u64(0xbeef);

    // We compile the circuit using the public parameters PP
    let (prover, _verifier) = Compiler::compile::<SingleSigCircuit>(&PP, LABEL)
        .expect("circuit should compile");

    let circuit = SingleSigCircuit::valid(&mut rng);

    // We benchmark the prover
    unsafe {
        let log =
            &format!("Single Key proof creation ({} constraints)", CONSTRAINTS);
        c.bench_function(log, |b| {
            b.iter(|| bench_prover(&mut rng, &prover, &circuit))
        });
    }
}

//** DOUBLE KEY BENCHMARK *****************************
#[derive(Debug, Default)]
struct DoubleSigCircuit {
    signature: DoubleSignature,
    pk: JubJubExtended,
    pk_p: JubJubExtended,
    message: BlsScalar,
}

impl DoubleSigCircuit {
    pub fn valid(rng: &mut StdRng) -> Self {
        let sk = NoteSecretKey::random(rng);
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
}

impl Circuit for DoubleSigCircuit {
    fn circuit<C>(&self, composer: &mut C) -> Result<(), PlonkError>
    where
        C: Composer,
    {
        let (u, r, r_p) = self.signature.append(composer);

        let pk = composer.append_point(self.pk);
        let pk_p = composer.append_point(self.pk_p);
        let m = composer.append_witness(self.message);

        gadgets::double_key_verify(composer, u, r, r_p, pk, pk_p, m)
            .expect("this is infallible");

        unsafe {
            CONSTRAINTS = composer.constraints();
        }

        Ok(())
    }
}

fn double_key_proof_creation(c: &mut Criterion) {
    let mut rng = &mut StdRng::seed_from_u64(0xbeef);

    // We compile the circuit using the public parameters PP
    let (prover, _verifier) = Compiler::compile::<DoubleSigCircuit>(&PP, LABEL)
        .expect("circuit should compile");

    let circuit = DoubleSigCircuit::valid(&mut rng);

    // We benchmark the prover
    unsafe {
        let log =
            &format!("Double Key proof creation ({} constraints)", CONSTRAINTS);
        c.bench_function(log, |b| {
            b.iter(|| bench_prover(&mut rng, &prover, &circuit))
        });
    }
}

criterion_group! {
    name = schnorr;
    config = Criterion::default().sample_size(10);
    targets = single_key_proof_creation, double_key_proof_creation,
}
criterion_main!(schnorr);
