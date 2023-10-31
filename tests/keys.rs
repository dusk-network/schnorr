// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{JubJubAffine, JubJubExtended, JubJubScalar};
use dusk_schnorr::{NotePublicKey, NoteSecretKey};
use rand_core::OsRng;

#[test]
#[allow(clippy::eq_op)]
fn partial_eq_pk() {
    let sk1 = NoteSecretKey::random(&mut OsRng);
    let sk2 = NoteSecretKey::random(&mut OsRng);

    assert_ne!(sk1, sk2);

    let pk1 = NotePublicKey::from(&sk1);
    let pk2 = NotePublicKey::from(&sk2);

    assert_eq!(pk1, pk1);
    assert_ne!(pk1, pk2);

    // With all coordinates being different the points are the same ie.
    // equalty holds using this technique.
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

    // Assert none of the points coordinates actually matches
    assert_ne!(left.get_u(), right.get_u());
    assert_ne!(left.get_v(), right.get_v());
    assert_ne!(left.get_z(), right.get_z());

    assert_eq!(JubJubAffine::from(right), JubJubAffine::from(left));

    assert_eq!(NotePublicKey::from(left), NotePublicKey::from(right));
    assert_ne!(NotePublicKey::from(left), NotePublicKey::from(wrong))
}
