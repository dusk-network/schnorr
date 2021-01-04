// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_plonk::constraint_system::ecc::scalar_mul::fixed_base;
use dusk_plonk::constraint_system::ecc::scalar_mul::variable_base::variable_base_scalar_mul;
use dusk_plonk::constraint_system::ecc::Point;
use dusk_plonk::jubjub::{GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use dusk_plonk::prelude::*;
use poseidon252::sponge::sponge::sponge_hash_gadget;

/// Given `R`, assert the signature `u` is correct for `PK` over `message`.
///
/// `R` is expected to be generated from [`crate::single_key::SecretKey::sign`]
#[allow(non_snake_case)]
pub fn single_key_verify(
    composer: &mut StandardComposer,
    R: Point,
    u: Variable,
    PK: Point,
    message: Variable,
) {
    let h = sponge_hash_gadget(composer, &[message]);
    let c_hash = sponge_hash_gadget(composer, &[*R.x(), *R.y(), h]);

    let m = BlsScalar::pow_of_2(251).sub(&BlsScalar::one());
    let m = composer.add_witness_to_circuit_description(m);
    let c = composer.and_gate(c_hash, m, 250);

    let p1_l = fixed_base::scalar_mul(composer, u, GENERATOR_EXTENDED);
    let p1_r = variable_base_scalar_mul(composer, c, PK);
    let p1 = p1_l.point().add(composer, *p1_r.point());

    composer.assert_equal_point(p1, R);
}

/// Given `(R, R_prime)`, assert the signature `u` is correct for the pair `(PK,
/// PK_prime)` over `message`.
///
/// `(R, R_prime, u)` is expected to be generated from
/// [`crate::double_key::SecretKey::sign`]
#[allow(non_snake_case)]
pub fn double_key_verify(
    composer: &mut StandardComposer,
    R: Point,
    R_prime: Point,
    u: Variable,
    PK: Point,
    PK_prime: Point,
    message: Variable,
) {
    let h = sponge_hash_gadget(composer, &[message]);
    let c_hash = sponge_hash_gadget(
        composer,
        &[*R.x(), *R.y(), *R_prime.x(), *R_prime.y(), h],
    );

    let m = BlsScalar::pow_of_2(251).sub(&BlsScalar::one());
    let m = composer.add_witness_to_circuit_description(m);
    let c = composer.and_gate(c_hash, m, 250);

    let p1_l = fixed_base::scalar_mul(composer, u, GENERATOR_EXTENDED);
    let p1_r = variable_base_scalar_mul(composer, c, PK);
    let p1 = p1_l.point().add(composer, *p1_r.point());

    let p2_l = fixed_base::scalar_mul(composer, u, GENERATOR_NUMS_EXTENDED);
    let p2_r = variable_base_scalar_mul(composer, c, PK_prime);
    let p2 = p2_l.point().add(composer, *p2_r.point());

    composer.assert_equal_point(p1, R);
    composer.assert_equal_point(p2, R_prime);
}

#[cfg(test)]
mod tests {
    use dusk_plonk::prelude::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    mod helpers;

    use helpers::*;

    #[test]
    fn zk_single_key_verify() {
        let mut rng = StdRng::seed_from_u64(2321u64);

        let (sk, pk, message, signature) = gen_single(&mut rng);
        let mut circuit = SingleKeyCircuit::new(signature, sk, pk, message);
        let pp =
            PublicParameters::setup(circuit.get_trim_size(), &mut rng).unwrap();
        let (circuit_pk, circuit_vk) = circuit.compile(&pp).unwrap();
        let label = b"single-key-label";

        let (sk, pk, message, signature) = gen_single(&mut rng);
        let mut proof_circuit =
            SingleKeyCircuit::new(signature, sk, pk, message);
        let proof = proof_circuit.gen_proof(&pp, &circuit_pk, label).unwrap();
        let pi = proof_circuit.get_pi_positions().clone();

        circuit
            .verify_proof(&pp, &circuit_vk, label, &proof, pi.as_slice())
            .unwrap();
    }

    #[test]
    fn zk_single_key_verify_wrong_pk() {
        let mut rng = StdRng::seed_from_u64(2321u64);

        let (sk, pk, message, signature) = gen_single(&mut rng);
        let mut circuit = SingleKeyCircuit::new(signature, sk, pk, message);
        let pp =
            PublicParameters::setup(circuit.get_trim_size(), &mut rng).unwrap();
        let (circuit_pk, circuit_vk) = circuit.compile(&pp).unwrap();
        let label = b"single-key-label";

        let (sk, pk, message, signature) = gen_single(&mut rng);
        let mut proof_circuit =
            SingleKeyCircuit::new(signature, sk, pk, message);
        let proof = proof_circuit.gen_proof(&pp, &circuit_pk, label).unwrap();

        let mut pi = proof_circuit.get_pi_positions().clone();
        let (_, pk, _, _) = gen_single(&mut rng);
        match &mut pi[0] {
            PublicInput::AffinePoint(p, _, _) => *p = pk.as_ref().into(),
            _ => panic!("Unexpected PI!"),
        }

        assert!(circuit
            .verify_proof(&pp, &circuit_vk, label, &proof, pi.as_slice())
            .is_err());
    }

    #[test]
    fn zk_double_key_verify() {
        let mut rng = StdRng::seed_from_u64(2321u64);

        let (sk, pk, message, signature) = gen_double(&mut rng);
        let mut circuit = DoubleKeyCircuit::new(signature, sk, pk, message);
        let pp =
            PublicParameters::setup(circuit.get_trim_size(), &mut rng).unwrap();
        let (circuit_pk, circuit_vk) = circuit.compile(&pp).unwrap();
        let label = b"double-key-label";

        let (sk, pk, message, signature) = gen_double(&mut rng);
        let mut proof_circuit =
            DoubleKeyCircuit::new(signature, sk, pk, message);
        let proof = proof_circuit.gen_proof(&pp, &circuit_pk, label).unwrap();
        let pi = proof_circuit.get_pi_positions().clone();

        circuit
            .verify_proof(&pp, &circuit_vk, label, &proof, pi.as_slice())
            .unwrap();
    }

    #[test]
    fn zk_double_key_verify_wrong_pk() {
        let mut rng = StdRng::seed_from_u64(2321u64);

        let (sk, pk, message, signature) = gen_double(&mut rng);
        let mut circuit = DoubleKeyCircuit::new(signature, sk, pk, message);
        let pp =
            PublicParameters::setup(circuit.get_trim_size(), &mut rng).unwrap();
        let (circuit_pk, circuit_vk) = circuit.compile(&pp).unwrap();
        let label = b"double-key-label";

        let (sk, pk, message, signature) = gen_double(&mut rng);
        let mut proof_circuit =
            DoubleKeyCircuit::new(signature, sk, pk, message);
        let proof = proof_circuit.gen_proof(&pp, &circuit_pk, label).unwrap();

        let mut pi = proof_circuit.get_pi_positions().clone();
        let (_, pk, _, _) = gen_double(&mut rng);
        match &mut pi[0] {
            PublicInput::AffinePoint(p, _, _) => *p = pk.PK().into(),
            _ => panic!("Unexpected PI!"),
        }

        assert!(circuit
            .verify_proof(&pp, &circuit_vk, label, &proof, pi.as_slice())
            .is_err());
    }

    #[test]
    fn zk_double_key_verify_wrong_pk_prime() {
        let mut rng = StdRng::seed_from_u64(2321u64);

        let (sk, pk, message, signature) = gen_double(&mut rng);
        let mut circuit = DoubleKeyCircuit::new(signature, sk, pk, message);
        let pp =
            PublicParameters::setup(circuit.get_trim_size(), &mut rng).unwrap();
        let (circuit_pk, circuit_vk) = circuit.compile(&pp).unwrap();
        let label = b"double-key-label";

        let (sk, pk, message, signature) = gen_double(&mut rng);
        let mut proof_circuit =
            DoubleKeyCircuit::new(signature, sk, pk, message);
        let proof = proof_circuit.gen_proof(&pp, &circuit_pk, label).unwrap();

        let mut pi = proof_circuit.get_pi_positions().clone();
        let (_, pk, _, _) = gen_double(&mut rng);
        match &mut pi[1] {
            PublicInput::AffinePoint(p, _, _) => *p = pk.PK_prime().into(),
            _ => panic!("Unexpected PI!"),
        }

        assert!(circuit
            .verify_proof(&pp, &circuit_vk, label, &proof, pi.as_slice())
            .is_err());
    }
}
