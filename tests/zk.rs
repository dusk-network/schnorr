// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![feature(once_cell)]

#[cfg(feature = "std")]
mod zk {
    use anyhow::Result;
    use dusk_jubjub::JubJubAffine;
    use dusk_pki::{PublicKey, SecretKey};
    use dusk_plonk::circuit;
    use dusk_plonk::constraint_system::ecc::Point;
    use dusk_plonk::prelude::Error as PlonkError;
    use dusk_plonk::prelude::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use schnorr::{gadgets, Proof, PublicKeyPair, Signature};
    use std::lazy::SyncLazy;

    #[test]
    fn single_key_verify() {
        let mut rng = StdRng::seed_from_u64(2321u64);

        let (sk, pk, message, signature) = gen_single(&mut rng);
        let mut proof_circuit =
            SingleKeyCircuit::new(signature, sk, pk, message);

        let proof = proof_circuit
            .gen_proof(&*PP, &*SINGLE_PK, SINGLE_LB)
            .unwrap();
        let pk: JubJubAffine = pk.as_ref().into();
        let pi: Vec<PublicInputValue> = vec![pk.into()];

        circuit::verify_proof(
            &*PP,
            &*SINGLE_VK,
            &proof,
            &pi,
            &*SINGLE_PI,
            SINGLE_LB,
        )
        .expect("Failed to verify proof");
    }

    #[test]
    fn single_key_verify_wrong_pk() {
        let mut rng = StdRng::seed_from_u64(2321u64);

        let (sk, pk, message, signature) = gen_single(&mut rng);
        let mut proof_circuit =
            SingleKeyCircuit::new(signature, sk, pk, message);

        let proof = proof_circuit
            .gen_proof(&*PP, &*SINGLE_PK, SINGLE_LB)
            .unwrap();

        let (_, pk, _, _) = gen_single(&mut rng);
        let pk: JubJubAffine = pk.as_ref().into();
        let pi: Vec<PublicInputValue> = vec![pk.into()];

        let result = circuit::verify_proof(
            &*PP,
            &*SINGLE_VK,
            &proof,
            &pi,
            &*SINGLE_PI,
            SINGLE_LB,
        );
        assert!(result.is_err());
    }

    #[test]
    fn double_key_verify() {
        let mut rng = StdRng::seed_from_u64(2321u64);

        let (sk, pk, message, signature) = gen_double(&mut rng);
        let mut proof_circuit =
            DoubleKeyCircuit::new(signature, sk, pk, message);

        let proof = proof_circuit
            .gen_proof(&*PP, &*DOUBLE_PK, DOUBLE_LB)
            .unwrap();

        let pk_prime: JubJubAffine = pk.R_prime().as_ref().into();
        let pk: JubJubAffine = pk.R().as_ref().into();

        let pi: Vec<PublicInputValue> = vec![pk.into(), pk_prime.into()];

        circuit::verify_proof(
            &*PP,
            &*DOUBLE_VK,
            &proof,
            &pi,
            &*DOUBLE_PI,
            DOUBLE_LB,
        )
        .expect("Failed to verify proof");
    }

    #[test]
    fn double_key_verify_wrong_pk() {
        let mut rng = StdRng::seed_from_u64(2321u64);

        let (sk, pk, message, signature) = gen_double(&mut rng);
        let mut proof_circuit =
            DoubleKeyCircuit::new(signature, sk, pk, message);

        let proof = proof_circuit
            .gen_proof(&*PP, &*DOUBLE_PK, DOUBLE_LB)
            .unwrap();

        let pk_prime: JubJubAffine = pk.R_prime().as_ref().into();
        let (_, pk, _, _) = gen_double(&mut rng);
        let pk: JubJubAffine = pk.R().as_ref().into();

        let pi: Vec<PublicInputValue> = vec![pk.into(), pk_prime.into()];

        let result = circuit::verify_proof(
            &*PP,
            &*DOUBLE_VK,
            &proof,
            &pi,
            &*DOUBLE_PI,
            DOUBLE_LB,
        );
        assert!(result.is_err());
    }

    #[test]
    fn double_key_verify_wrong_pk_prime() {
        let mut rng = StdRng::seed_from_u64(2321u64);

        let (sk, pk, message, signature) = gen_double(&mut rng);
        let mut proof_circuit =
            DoubleKeyCircuit::new(signature, sk, pk, message);

        let proof = proof_circuit
            .gen_proof(&*PP, &*DOUBLE_PK, DOUBLE_LB)
            .unwrap();

        let pk_p: JubJubAffine = pk.R().as_ref().into();
        let (_, pk, _, _) = gen_double(&mut rng);
        let pk_prime: JubJubAffine = pk.R_prime().as_ref().into();
        let pk = pk_p;

        let pi: Vec<PublicInputValue> = vec![pk.into(), pk_prime.into()];

        let result = circuit::verify_proof(
            &*PP,
            &*DOUBLE_VK,
            &proof,
            &pi,
            &*DOUBLE_PI,
            DOUBLE_LB,
        );
        assert!(result.is_err());
    }

    /// Static definitions

    pub static PP: SyncLazy<PublicParameters> = SyncLazy::new(|| {
        let mut rng = StdRng::seed_from_u64(2321u64);

        PublicParameters::setup(1 << 13, &mut rng)
            .expect("Failed to generate PP")
    });

    static SINGLE: SyncLazy<(
        ProverKey,
        VerifierKey,
        Vec<usize>,
        &'static [u8],
    )> = SyncLazy::new(|| {
        let mut rng = StdRng::seed_from_u64(2321u64);

        let (sk, pk, message, signature) = gen_single(&mut rng);
        let mut circuit = SingleKeyCircuit::new(signature, sk, pk, message);

        let (pk, vk, pi_pos) = circuit.compile(&*PP).unwrap();
        let label = b"single-key-label";

        (pk, vk, pi_pos, label)
    });

    static DOUBLE: SyncLazy<(
        ProverKey,
        VerifierKey,
        Vec<usize>,
        &'static [u8],
    )> = SyncLazy::new(|| {
        let mut rng = StdRng::seed_from_u64(2321u64);

        let (sk, pk, message, signature) = gen_double(&mut rng);
        let mut circuit = DoubleKeyCircuit::new(signature, sk, pk, message);

        let (pk, vk, pi_pos) = circuit.compile(&*PP).unwrap();
        let label = b"double-key-label";

        (pk, vk, pi_pos, label)
    });

    pub static SINGLE_PK: SyncLazy<ProverKey> =
        SyncLazy::new(|| SINGLE.0.clone());
    pub static SINGLE_VK: SyncLazy<VerifierKey> =
        SyncLazy::new(|| SINGLE.1.clone());
    pub static SINGLE_PI: SyncLazy<Vec<usize>> =
        SyncLazy::new(|| SINGLE.2.clone());
    pub static SINGLE_LB: &'static [u8] = b"double-key-label";

    pub static DOUBLE_PK: SyncLazy<ProverKey> =
        SyncLazy::new(|| DOUBLE.0.clone());
    pub static DOUBLE_VK: SyncLazy<VerifierKey> =
        SyncLazy::new(|| DOUBLE.1.clone());
    pub static DOUBLE_PI: SyncLazy<Vec<usize>> =
        SyncLazy::new(|| DOUBLE.2.clone());
    pub static DOUBLE_LB: &'static [u8] = b"double-key-label";

    #[derive(Debug, Clone)]
    pub struct SingleKeyCircuit {
        signature: Signature,
        sk: SecretKey,
        pk: PublicKey,
        message: BlsScalar,
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
            }
        }
    }

    impl Circuit for SingleKeyCircuit {
        const CIRCUIT_ID: [u8; 32] = [0xff; 32];

        #[allow(non_snake_case)]
        fn gadget(
            &mut self,
            composer: &mut StandardComposer,
        ) -> Result<(), PlonkError> {
            let R =
                Point::from_private_affine(composer, self.signature.R().into());
            let u = composer.add_input(self.signature.u().clone().into());
            let PK =
                Point::from_private_affine(composer, self.pk.as_ref().into());
            let message = composer.add_input(self.message);

            gadgets::single_key_verify(composer, R, u, PK, message);

            let pk = self.pk.as_ref().into();
            composer.assert_equal_public_point(PK, pk);

            Ok(())
        }

        fn padded_circuit_size(&self) -> usize {
            1 << 13
        }
    }

    #[derive(Debug, Clone)]
    pub struct DoubleKeyCircuit {
        proof: Proof,
        sk: SecretKey,
        pkp: PublicKeyPair,
        message: BlsScalar,
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
            }
        }
    }

    impl Circuit for DoubleKeyCircuit {
        const CIRCUIT_ID: [u8; 32] = [0xff; 32];

        #[allow(non_snake_case)]
        fn gadget(
            &mut self,
            composer: &mut StandardComposer,
        ) -> Result<(), PlonkError> {
            let R = Point::from_private_affine(
                composer,
                self.proof.keys().R().as_ref().into(),
            );
            let R_prime = Point::from_private_affine(
                composer,
                self.proof.keys().R_prime().as_ref().into(),
            );
            let u = composer.add_input(self.proof.u().clone().into());
            let PK = Point::from_private_affine(
                composer,
                self.pkp.R().as_ref().into(),
            );
            let PK_prime = Point::from_private_affine(
                composer,
                self.pkp.R_prime().as_ref().into(),
            );
            let message = composer.add_input(self.message);

            gadgets::double_key_verify(
                composer, R, R_prime, u, PK, PK_prime, message,
            );

            let pk = self.pkp.R().as_ref().into();
            composer.assert_equal_public_point(PK, pk);

            let pk_prime = self.pkp.R_prime().as_ref().into();
            composer.assert_equal_public_point(PK_prime, pk_prime);

            Ok(())
        }

        fn padded_circuit_size(&self) -> usize {
            1 << 13
        }
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
}