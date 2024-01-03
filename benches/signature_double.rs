// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use criterion::{criterion_group, criterion_main, Criterion};

use dusk_schnorr::{gadgets, PublicKeyDouble, SecretKey, SignatureDouble};
use ff::Field;
use rand::rngs::StdRng;
use rand::SeedableRng;

use dusk_plonk::prelude::Error as PlonkError;
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

#[derive(Debug, Default)]
struct SigDoubleCircuit {
    signature: SignatureDouble,
    pk: PublicKeyDouble,
    message: BlsScalar,
}

impl SigDoubleCircuit {
    pub fn valid(rng: &mut StdRng) -> Self {
        let sk = SecretKey::random(rng);
        let message = BlsScalar::random(&mut *rng);
        let signature = sk.sign_double(rng, message);

        let pk = PublicKeyDouble::from(&sk);

        Self {
            signature,
            pk,
            message,
        }
    }
}

impl Circuit for SigDoubleCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), PlonkError> {
        let (u, r, r_p) = self.signature.append(composer);

        let pk = composer.append_point(self.pk.pk());
        let pk_p = composer.append_point(self.pk.pk_prime());
        let m = composer.append_witness(self.message);

        gadgets::verify_signature_double(composer, u, r, r_p, pk, pk_p, m)
            .expect("this is infallible");

        unsafe {
            CONSTRAINTS = composer.constraints();
        }

        Ok(())
    }
}

fn proof_creation_signature_double(c: &mut Criterion) {
    let mut rng = &mut StdRng::seed_from_u64(0xbeef);

    // We compile the circuit using the public parameters PP
    let (prover, _verifier) = Compiler::compile::<SigDoubleCircuit>(&PP, LABEL)
        .expect("circuit should compile");

    let circuit = SigDoubleCircuit::valid(&mut rng);

    // We benchmark the prover
    unsafe {
        let log = &format!(
            "Signature double proof creation ({} constraints)",
            CONSTRAINTS
        );
        c.bench_function(log, |b| {
            b.iter(|| bench_prover(&mut rng, &prover, &circuit))
        });
    }
}

criterion_group! {
    name = schnorr;
    config = Criterion::default().sample_size(10);
    targets = proof_creation_signature_double,
}
criterion_main!(schnorr);
