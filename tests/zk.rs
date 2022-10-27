// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use dusk_pki::SecretKey;
use dusk_plonk::error::Error as PlonkError;
use dusk_schnorr::{gadgets, Proof, Signature};
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

#[test]
fn single_key() {
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
        fn circuit<C: Composer>(
            &self,
            composer: &mut C,
        ) -> Result<(), PlonkError> {
            let (u, r) = self.signature.to_witness(composer);

            let k = composer.append_point(self.k);
            let m = composer.append_witness(self.message);

            gadgets::single_key_verify(composer, u, r, k, m)?;

            Ok(())
        }
    }

    let label = b"dusk-network";

    let rng = &mut StdRng::seed_from_u64(0xfeeb);

    let sk = SecretKey::random(rng);
    let message = BlsScalar::random(rng);
    let signature = Signature::new(&sk, rng, message);

    let k = GENERATOR_EXTENDED * sk.as_ref();
    let (prover, verifier) = Compiler::compile(&PP, label)
        .expect("Circuit should compile successfully");

    let circuit = TestSingleKey::new(signature, k, message);

    let (proof, public_inputs) = prover
        .prove(rng, &circuit)
        .expect("Proving the circuit should be successful");

    verifier
        .verify(&proof, &public_inputs)
        .expect("Verification should be successful");
}

#[test]
fn double_key() {
    #[derive(Debug)]
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
        fn circuit<C: Composer>(
            &self,
            composer: &mut C,
        ) -> Result<(), PlonkError> {
            let (u, r, r_p) = self.proof.to_witness(composer);

            let k = composer.append_point(self.k);
            let k_p = composer.append_point(self.k_p);
            let m = composer.append_witness(self.message);

            gadgets::double_key_verify(composer, u, r, r_p, k, k_p, m)?;

            Ok(())
        }
    }

    let label = b"dusk-network";

    let rng = &mut StdRng::seed_from_u64(0xfeeb);

    let sk = SecretKey::random(rng);
    let message = BlsScalar::random(rng);
    let proof = Proof::new(&sk, rng, message);

    let k = GENERATOR_EXTENDED * sk.as_ref();
    let k_p = GENERATOR_NUMS_EXTENDED * sk.as_ref();

    let (prover, verifier) = Compiler::compile(&PP, label)
        .expect("Circuit compilation should succeed");

    let circuit = TestDoubleKey::new(proof, k, k_p, message);

    let (proof, public_inputs) = prover
        .prove(rng, &circuit)
        .expect("Proving the circuit should succeed");

    verifier
        .verify(&proof, &public_inputs)
        .expect("Verifying the proof should succeed");
}
