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
        const CIRCUIT_ID: [u8; 32] = [0xff; 32];

        fn gadget(
            &mut self,
            composer: &mut TurboComposer,
        ) -> Result<(), PlonkError> {
            let (u, r) = self.signature.to_witness(composer);

            let k = composer.append_point(self.k);
            let m = composer.append_witness(self.message);

            gadgets::single_key_verify(composer, u, r, k, m);

            Ok(())
        }

        fn public_inputs(&self) -> Vec<PublicInputValue> {
            vec![]
        }

        fn padded_gates(&self) -> usize {
            1 << 12
        }
    }

    let label = b"dusk-network";

    let rng = &mut StdRng::seed_from_u64(0xfeeb);

    let sk = SecretKey::random(rng);
    let message = BlsScalar::random(rng);
    let signature = Signature::new(&sk, rng, message);

    let k = GENERATOR_EXTENDED * sk.as_ref();

    let (pk, vd) = TestSingleKey::default()
        .compile(&PP)
        .expect("Failed to compile circuit");

    let proof = TestSingleKey::new(signature, k, message)
        .prove(&PP, &pk, label)
        .expect("Failed to prove");

    TestSingleKey::verify(&PP, &vd, &proof, &[], label)
        .expect("Failed to verify");
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

            Ok(())
        }

        fn public_inputs(&self) -> Vec<PublicInputValue> {
            vec![]
        }

        fn padded_gates(&self) -> usize {
            1 << 13
        }
    }

    let label = b"dusk-network";

    let rng = &mut StdRng::seed_from_u64(0xfeeb);

    let sk = SecretKey::random(rng);
    let message = BlsScalar::random(rng);
    let proof = Proof::new(&sk, rng, message);

    let k = GENERATOR_EXTENDED * sk.as_ref();
    let k_p = GENERATOR_NUMS_EXTENDED * sk.as_ref();

    let (pk, vd) = TestDoubleKey::default()
        .compile(&PP)
        .expect("Failed to compile circuit");

    let proof = TestDoubleKey::new(proof, k, k_p, message)
        .prove(&PP, &pk, label)
        .expect("Failed to prove");

    TestDoubleKey::verify(&PP, &vd, &proof, &[], label)
        .expect("Failed to verify");
}
