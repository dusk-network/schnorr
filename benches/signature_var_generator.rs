// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use criterion::{criterion_group, criterion_main, Criterion};

use dusk_schnorr::{
    gadgets, PublicKeyVarGen, SecretKeyVarGen, SignatureVarGen,
};
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
struct SigVarGenCircuit {
    signature: SignatureVarGen,
    pk: PublicKeyVarGen,
    message: BlsScalar,
}

impl SigVarGenCircuit {
    pub fn valid(rng: &mut StdRng) -> Self {
        let sk = SecretKeyVarGen::random(rng);
        let message = BlsScalar::random(&mut *rng);
        let signature = sk.sign(rng, message);

        let pk = PublicKeyVarGen::from(&sk);

        Self {
            signature,
            pk,
            message,
        }
    }
}

impl Circuit for SigVarGenCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), PlonkError> {
        let (u, r) = self.signature.append(composer);

        let pk = composer.append_point(self.pk.public_key());
        let generator = composer.append_point(self.pk.generator());
        let m = composer.append_witness(self.message);

        let _result =
            gadgets::verify_signature_var_gen(composer, u, r, pk, generator, m);

        unsafe {
            CONSTRAINTS = composer.constraints();
        }

        Ok(())
    }
}

fn proof_creation_signature_var_generation(c: &mut Criterion) {
    let mut rng = &mut StdRng::seed_from_u64(0xbeef);

    // We compile the circuit using the public parameters PP
    let (prover, _verifier) = Compiler::compile::<SigVarGenCircuit>(&PP, LABEL)
        .expect("circuit should compile");

    let circuit = SigVarGenCircuit::valid(&mut rng);

    // We benchmark the prover
    unsafe {
        let log = &format!(
            "Signature variable generator proof creation {} constraints)",
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
    targets = proof_creation_signature_var_generation,
}
criterion_main!(schnorr);
