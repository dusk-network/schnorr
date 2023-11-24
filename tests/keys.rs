// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{JubJubAffine, JubJubExtended, JubJubScalar};
use dusk_schnorr::{PublicKey, SecretKey};
use rand_core::OsRng;

#[cfg(feature = "double")]
use dusk_schnorr::PublicKeyDouble;

#[cfg(feature = "var_generator")]
use dusk_schnorr::{PublicKeyVarGen, SecretKeyVarGen};

#[test]
#[allow(clippy::eq_op)]
fn partial_eq_pk() {
    let sk1 = SecretKey::random(&mut OsRng);
    let sk2 = SecretKey::random(&mut OsRng);

    assert_ne!(sk1, sk2);

    let pk1 = PublicKey::from(&sk1);
    let pk2 = PublicKey::from(&sk2);

    assert_eq!(pk1, pk1);
    assert_ne!(pk1, pk2);

    // With all coordinates being different the points are the same ie.
    // equality holds using this technique.
    let s = (
        JubJubScalar::from(2u64),
        JubJubScalar::from(7u64),
        JubJubScalar::from(4u64),
        JubJubScalar::from(5u64),
        JubJubScalar::from(567758785u64),
    );

    let left: JubJubExtended = dusk_jubjub::GENERATOR_EXTENDED * s.0
        + dusk_jubjub::GENERATOR_EXTENDED * s.1;

    let right: JubJubExtended = dusk_jubjub::GENERATOR_EXTENDED * s.2
        + dusk_jubjub::GENERATOR_EXTENDED * s.3;

    let wrong: JubJubExtended = dusk_jubjub::GENERATOR_EXTENDED * s.2
        + dusk_jubjub::GENERATOR_EXTENDED * s.4;

    // Assert none of the extended points coordinates actually matches even
    // though the points in affine version are the same
    assert_ne!(left.get_u(), right.get_u());
    assert_ne!(left.get_v(), right.get_v());
    assert_ne!(left.get_z(), right.get_z());

    assert_eq!(JubJubAffine::from(right), JubJubAffine::from(left));

    assert_eq!(PublicKey::from(left), PublicKey::from(right));
    assert_ne!(PublicKey::from(left), PublicKey::from(wrong))
}

#[test]
#[cfg(feature = "double")]
fn partial_eq_pk_double() {
    let sk1 = SecretKey::random(&mut OsRng);
    let sk2 = SecretKey::random(&mut OsRng);

    assert_ne!(sk1, sk2);

    let pk1 = PublicKeyDouble::from(&sk1);
    let pk2 = PublicKeyDouble::from(&sk2);

    assert_eq!(pk1, pk1);
    assert_ne!(pk1, pk2);
}

#[test]
#[cfg(feature = "var_generator")]
fn partial_eq_pk_var_gen() {
    let sk1 = SecretKeyVarGen::random(&mut OsRng);
    let sk2 = SecretKeyVarGen::random(&mut OsRng);

    assert_ne!(sk1, sk2);

    let pk1 = PublicKeyVarGen::from(&sk1);
    let pk2 = PublicKeyVarGen::from(&sk2);

    assert_eq!(pk1, pk1);
    assert_ne!(pk1, pk2);

    // With all coordinates being different the points are the same ie.
    // equality holds using this technique.
    let s = (
        JubJubScalar::from(2u64),
        JubJubScalar::from(7u64),
        JubJubScalar::from(4u64),
        JubJubScalar::from(5u64),
    );

    let left: JubJubExtended = dusk_jubjub::GENERATOR_EXTENDED * s.0
        + dusk_jubjub::GENERATOR_EXTENDED * s.1;

    let right: JubJubExtended = dusk_jubjub::GENERATOR_EXTENDED * s.2
        + dusk_jubjub::GENERATOR_EXTENDED * s.3;

    // Assert none of the extended points coordinates actually matches even
    // though the points in affine version are the same
    assert_ne!(left.get_u(), right.get_u());
    assert_ne!(left.get_v(), right.get_v());
    assert_ne!(left.get_z(), right.get_z());
    assert_eq!(JubJubAffine::from(right), JubJubAffine::from(left));

    // construct two different generator points
    let var_gen = dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(42u64);
    let wrong_var_gen =
        dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(4242u64);
    assert_ne!(var_gen, wrong_var_gen);

    assert_eq!(
        PublicKeyVarGen::from_raw_unchecked(left, var_gen),
        PublicKeyVarGen::from_raw_unchecked(right, var_gen)
    );
    assert_ne!(
        PublicKeyVarGen::from_raw_unchecked(left, var_gen),
        PublicKeyVarGen::from_raw_unchecked(left, wrong_var_gen)
    )
}
