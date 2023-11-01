// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use dusk_plonk::error::Error as PlonkError;
use dusk_schnorr::{gadgets, DoubleSignature, NoteSecretKey, Signature};
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
            let mut rng = StdRng::seed_from_u64(0xbeef);

            let sk = NoteSecretKey::random(&mut rng);
            let message = BlsScalar::uni_random(&mut rng);
            let signature = sk.sign_single(&mut rng, message);

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

    let mut rng = StdRng::seed_from_u64(0xfeeb);

    let sk = NoteSecretKey::random(&mut rng);
    let message = BlsScalar::uni_random(&mut rng);
    let signature = sk.sign_single(&mut rng, message);

    let k = GENERATOR_EXTENDED * sk.as_ref();
    let (prover, verifier) = Compiler::compile::<TestSingleKey>(&PP, label)
        .expect("Circuit should compile successfully");

    let circuit = TestSingleKey::new(signature, k, message);

    let (proof, public_inputs) = prover
        .prove(&mut rng, &circuit)
        .expect("Proving the circuit should be successful");

    verifier
        .verify(&proof, &public_inputs)
        .expect("Verification should be successful");
}

#[test]
fn double_key() {
    #[derive(Debug)]
    struct TestDoubleKey {
        signature: DoubleSignature,
        k: JubJubExtended,
        k_p: JubJubExtended,
        message: BlsScalar,
    }

    impl Default for TestDoubleKey {
        fn default() -> Self {
            let mut rng = StdRng::seed_from_u64(0xbeef);

            let sk = NoteSecretKey::random(&mut rng);
            let message = BlsScalar::uni_random(&mut rng);
            let signature = sk.sign_double(&mut rng, message);

            let k = GENERATOR_EXTENDED * sk.as_ref();
            let k_p = GENERATOR_NUMS_EXTENDED * sk.as_ref();

            Self {
                signature,
                k,
                k_p,
                message,
            }
        }
    }

    impl TestDoubleKey {
        pub fn new(
            signature: DoubleSignature,
            k: JubJubExtended,
            k_p: JubJubExtended,
            message: BlsScalar,
        ) -> Self {
            Self {
                signature,
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
            let (u, r, r_p) = self.signature.to_witness(composer);

            let k = composer.append_point(self.k);
            let k_p = composer.append_point(self.k_p);
            let m = composer.append_witness(self.message);

            gadgets::double_key_verify(composer, u, r, r_p, k, k_p, m)?;

            Ok(())
        }
    }

    let label = b"dusk-network";

    let mut rng = StdRng::seed_from_u64(0xfeeb);

    let sk = NoteSecretKey::random(&mut rng);
    let message = BlsScalar::uni_random(&mut rng);
    let signature = sk.sign_double(&mut rng, message);

    let k = GENERATOR_EXTENDED * sk.as_ref();
    let k_p = GENERATOR_NUMS_EXTENDED * sk.as_ref();

    let (prover, verifier) = Compiler::compile::<TestDoubleKey>(&PP, label)
        .expect("Circuit compilation should succeed");

    let circuit = TestDoubleKey::new(signature, k, k_p, message);

    let (proof, public_inputs) = prover
        .prove(&mut rng, &circuit)
        .expect("Proving the circuit should succeed");

    verifier
        .verify(&proof, &public_inputs)
        .expect("Verifying the proof should succeed");
}
