// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! # Public Key Module
//!
//! This module provides the public key components for the Schnorr signature
//! scheme, necessary for verifying signature validity. It includes single and
//! double public keys, as well as public keys for signing with a variable
//! generator. Public keys in this context are points on the JubJub
//! elliptic curve generated from the [`SecretKey`] and generator point, and
//! they provide the basis for signature verification.

use dusk_bls12_381::BlsScalar;
use dusk_bytes::{Error, Serializable};
use dusk_jubjub::{JubJubAffine, JubJubExtended, GENERATOR_EXTENDED};

use crate::{SecretKey, Signature};

#[cfg(feature = "double")]
use crate::SignatureDouble;
#[cfg(feature = "double")]
use dusk_bytes::DeserializableSlice;
#[cfg(feature = "double")]
use dusk_jubjub::GENERATOR_NUMS_EXTENDED;

#[cfg(feature = "var_generator")]
use crate::{SecretKeyVarGen, SignatureVarGen};

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

/// Structure representing a [`PublicKey`], consisting of a [`JubJubExtended`]
/// point on the JubJub curve. This public key allows for the verification of
/// signatures created with its corresponding secret key without revealing the
/// secret key itself.
///
/// ## Examples
///
/// Generate a [`PublicKey`] from a [`SecretKey`]:
/// ```
/// use dusk_schnorr::{SecretKey, PublicKey};
/// use dusk_bls12_381::BlsScalar;
/// use rand::rngs::StdRng;
/// use rand::SeedableRng;
///
/// let mut rng = StdRng::seed_from_u64(12345);
/// let sk = SecretKey::random(&mut rng);
/// let pk = PublicKey::from(&sk);
/// ```
#[derive(Default, Copy, Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct PublicKey(JubJubExtended);

impl From<&SecretKey> for PublicKey {
    fn from(sk: &SecretKey) -> Self {
        let pk = GENERATOR_EXTENDED * sk.0;

        PublicKey(pk)
    }
}

impl From<JubJubExtended> for PublicKey {
    fn from(p: JubJubExtended) -> PublicKey {
        PublicKey(p)
    }
}

impl From<&JubJubExtended> for PublicKey {
    fn from(p: &JubJubExtended) -> PublicKey {
        PublicKey(*p)
    }
}

impl AsRef<JubJubExtended> for PublicKey {
    fn as_ref(&self) -> &JubJubExtended {
        &self.0
    }
}

impl Serializable<32> for PublicKey {
    type Error = Error;

    fn to_bytes(&self) -> [u8; 32] {
        JubJubAffine::from(self.0).to_bytes()
    }

    fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        let pk: JubJubAffine = match JubJubAffine::from_bytes(*bytes).into() {
            Some(pk) => pk,
            None => return Err(Error::InvalidData),
        };
        Ok(Self(pk.into()))
    }
}

impl PublicKey {
    /// Verifies that the given Schnorr [`Signature`] is valid.
    ///
    /// This function computes a challenge hash `c` using the stored `R` point
    /// and the provided message, then performs the verification by checking
    /// that:
    /// ```text
    /// u * G + c * PK == R
    /// ```
    ///
    /// ## Parameters
    ///
    /// - `sig`: Reference to the [`Signature`] to be verified.
    /// - `message`: The message as [`BlsScalar`].
    ///
    /// ## Returns
    ///
    /// A boolean value indicating the validity of the Schnorr [`Signature`].
    pub fn verify(&self, sig: &Signature, message: BlsScalar) -> bool {
        // Compute challenge value, c = H(R||m);
        let c = crate::signatures::challenge_hash(sig.R(), message);

        // Compute verification steps
        // u * G + c * PK
        let point_1 = (GENERATOR_EXTENDED * sig.u()) + (self.as_ref() * c);

        point_1.eq(&sig.R())
    }

    /// Create a [`PublicKey`] from its internal parts.
    ///
    /// The public keys are generated from a bijective function that takes a
    /// secret keys domain. If keys are generated directly from curve
    /// points, there is no guarantee a secret key exists - in fact, the
    /// discrete logarithm property will guarantee the secret key cannot be
    /// extracted from this public key.
    ///
    /// If you opt to generate the keys manually, be sure you have its secret
    /// counterpart - otherwise this key will be of no use.
    pub const fn from_raw_unchecked(key: JubJubExtended) -> Self {
        Self(key)
    }
}

/// Structure representing a [`PublicKeyDouble`], consisting of two
/// [`JubJubExtended`] poinst on the JubJub curve.
///
/// The [`PublicKeyDouble`] struct contains two public keys: `(pk, pk')`,
/// which are generated from different bases.
/// Specifically: `pk = sk * G` with the standard generator point [`G`],
/// and `pk' = sk * G'` with generator point [`G'`].
///
/// This construct allows for a double-key mechanism to enable more advanced
/// uses then the single-key variant. For example, it is used in Phoenix for
/// proof delegation while preventing the leakage of secret keys.
///
/// # Feature
///
/// Only available with the "double" feature enabled.
///
/// ## Fields
///
/// - `(pk, pk')`: two [`PublicKey`], where `pk` is generated with [`G`] and
///   `pk'` with [`G'`]
///
/// Generate a [`PublicKeyDouble`] from a [`SecretKey`]:
/// ## Example
/// ```
/// use rand::rngs::StdRng;
/// use rand::SeedableRng;
/// use dusk_schnorr::{SecretKey, PublicKeyDouble};
///
/// let mut rng = StdRng::seed_from_u64(12345);
/// let sk = SecretKey::random(&mut rng);
/// let pk_double = PublicKeyDouble::from(&sk);
/// ```
///
/// [`G`]: `GENERATOR_EXTENDED`
/// [`G'`]: `GENERATOR_NUMS_EXTENDED`
#[derive(Default, Copy, Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
#[cfg(feature = "double")]
pub struct PublicKeyDouble(JubJubExtended, JubJubExtended);

#[cfg(feature = "double")]
impl PublicKeyDouble {
    /// Returns the `PublicKey` corresponding to the standard elliptic curve
    /// generator point `sk * G`.
    #[allow(non_snake_case)]
    pub fn pk(&self) -> &JubJubExtended {
        &self.0
    }

    /// Returns the `PublicKey` corresponding to the secondary elliptic
    /// curve generator point `sk * G'`.
    #[allow(non_snake_case)]
    pub fn pk_prime(&self) -> &JubJubExtended {
        &self.1
    }

    /// Verifies that the given Schnorr [`SignatureDouble`] is valid.
    ///
    /// It computes the challenge scalar and verifies the equality of points,
    /// thereby ensuring the [`SignatureDouble`] is valid.
    ///
    /// # Parameters
    ///
    /// * `sig_double`: Reference to the [`SignatureDouble`] to be verified.
    /// - `message`: The message as [`BlsScalar`].
    ///
    /// # Returns
    ///
    /// A boolean value indicating the validity of the Schnorr
    /// [`SignatureDouble`].
    #[allow(non_snake_case)]
    pub fn verify(
        &self,
        sig_double: &SignatureDouble,
        message: BlsScalar,
    ) -> bool {
        // Compute challenge value, c = H(R||R_prime||m);
        let c = crate::signatures::challenge_hash_double(
            sig_double.R(),
            sig_double.R_prime(),
            message,
        );

        // Compute verification steps
        // u * G + c * PK
        let point_1 = (GENERATOR_EXTENDED * sig_double.u()) + (self.pk() * c);
        // u * G' + c * PK'
        let point_2 =
            (GENERATOR_NUMS_EXTENDED * sig_double.u()) + (self.pk_prime() * c);

        // Verify point equations
        // point_1 = R && point_2 = R_prime
        point_1.eq(sig_double.R()) && point_2.eq(sig_double.R_prime())
    }

    /// Create a [`PublicKeyDouble`] from its internal parts
    ///
    /// The public keys are generated from a bijective function that takes a
    /// secret keys domain. If keys are generated directly from curve
    /// points, there is no guarantee a secret key exists - in fact, the
    /// discrete logarithm property will guarantee the secret key cannot be
    /// extracted from this public key.
    ///
    /// If you opt to generate the keys manually, be sure you have its secret
    /// counterpart - otherwise this key will be of no use.
    pub const fn from_raw_unchecked(
        pk: JubJubExtended,
        pk_prime: JubJubExtended,
    ) -> Self {
        Self(pk, pk_prime)
    }
}

#[cfg(feature = "double")]
impl From<&SecretKey> for PublicKeyDouble {
    fn from(sk: &SecretKey) -> Self {
        let pk = GENERATOR_EXTENDED * sk.as_ref();
        let pk_prime = GENERATOR_NUMS_EXTENDED * sk.as_ref();

        PublicKeyDouble(pk, pk_prime)
    }
}

#[cfg(feature = "double")]
impl From<SecretKey> for PublicKeyDouble {
    fn from(sk: SecretKey) -> Self {
        (&sk).into()
    }
}

#[cfg(feature = "double")]
impl Serializable<64> for PublicKeyDouble {
    type Error = Error;

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        let pk: JubJubAffine = self.pk().into();
        let pk_prime: JubJubAffine = self.pk_prime().into();
        buf[..32].copy_from_slice(&pk.to_bytes()[..]);
        buf[32..].copy_from_slice(&pk_prime.to_bytes()[..]);
        buf
    }

    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let pk = JubJubAffine::from_slice(&bytes[..32])?;
        let pk_prime = JubJubAffine::from_slice(&bytes[32..])?;
        Ok(PublicKeyDouble(pk.into(), pk_prime.into()))
    }
}

/// Structure representing a [`PublicKeyVarGen`], consisting of a public key
/// [`JubJubExtended`] point and a variable generator [`JubJubExtended`] point
/// on the JubJub curve. This public key allows for the verification of
/// signatures created with its corresponding variable generator secret key
/// without revealing the secret key itself.
///
/// # Feature
///
/// Only available with the "var_generator" feature enabled.
///
/// ## Examples
///
/// Generate a [`PublicKeyVarGen`] from a [`SecretKeyVarGen`]:
/// ```
/// use dusk_schnorr::{SecretKeyVarGen, PublicKeyVarGen};
/// use dusk_bls12_381::BlsScalar;
/// use rand::rngs::StdRng;
/// use rand::SeedableRng;
///
/// let mut rng = StdRng::seed_from_u64(12345);
/// let sk = SecretKeyVarGen::random(&mut rng);
/// let pk = PublicKeyVarGen::from(&sk);
/// ```
#[derive(Default, Copy, Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
#[cfg(feature = "var_generator")]
pub struct PublicKeyVarGen {
    pk: JubJubExtended,
    generator: JubJubExtended,
}

#[cfg(feature = "var_generator")]
impl From<&SecretKeyVarGen> for PublicKeyVarGen {
    fn from(sk: &SecretKeyVarGen) -> Self {
        let generator = sk.generator().clone();
        let pk = generator * sk.secret_key();

        PublicKeyVarGen { pk, generator }
    }
}

#[cfg(feature = "var_generator")]
impl Serializable<64> for PublicKeyVarGen {
    type Error = Error;

    fn to_bytes(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        let pk: JubJubAffine = self.pk.into();
        let pk_bytes = pk.to_bytes();
        let gen: JubJubAffine = self.generator.into();
        let gen_bytes = gen.to_bytes();
        buf[..32].copy_from_slice(&pk_bytes);
        buf[32..].copy_from_slice(&gen_bytes);
        buf
    }

    fn from_bytes(bytes: &[u8; 64]) -> Result<Self, Error> {
        let mut pk_bytes = [0u8; 32];
        let mut gen_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&bytes[..32]);
        gen_bytes.copy_from_slice(&bytes[32..]);
        let pk: JubJubExtended =
            <JubJubAffine as Serializable<32>>::from_bytes(&pk_bytes)?.into();
        let generator: JubJubExtended =
            <JubJubAffine as Serializable<32>>::from_bytes(&gen_bytes)?.into();
        Ok(Self { pk, generator })
    }
}

#[cfg(feature = "var_generator")]
impl PublicKeyVarGen {
    /// Returns a reference to the [`JubJubExtended`] public key.
    pub fn public_key(&self) -> &JubJubExtended {
        &self.pk
    }

    /// Returns a reference to the [`JubJubExtended`] generator.
    pub fn generator(&self) -> &JubJubExtended {
        &self.generator
    }

    /// Verifies that the given Schnorr [`SignatureVarGen`] is valid.
    ///
    /// This function computes a challenge hash using the stored `R` point and
    /// the provided message, then performs the verification by checking the
    /// equality of `u * G + c * PK` and `R`.
    ///
    /// ## Parameters
    ///
    /// - `sig_var_gen`: Reference to the [`SignatureVarGen`] to be verified.
    /// - `message`: The message in [`BlsScalar`] format.
    ///
    /// ## Returns
    ///
    /// A boolean value indicating the validity of the Schnorr
    /// [`SignatureVarGen`].
    pub fn verify(
        &self,
        sig_var_gen: &SignatureVarGen,
        message: BlsScalar,
    ) -> bool {
        // Compute challenge value, c = H(R||H(m));
        let c = crate::signatures::challenge_hash(sig_var_gen.R(), message);

        // Compute verification steps
        // u * G + c * PK
        let point_1 =
            (*self.generator() * sig_var_gen.u()) + (self.public_key() * c);

        point_1.eq(&sig_var_gen.R())
    }

    /// Create a [`PublicKeyVarGen`] from its internal parts
    ///
    /// The public keys are generated from a bijective function that takes a
    /// secret keys domain. If keys are generated directly from curve
    /// points, there is no guarantee a secret key exists - in fact, the
    /// discrete logarithm property will guarantee the secret key cannot be
    /// extracted from this public key.
    ///
    /// If you opt to generate the keys manually, be sure you have its secret
    /// counterpart - otherwise this key will be of no use.
    pub const fn from_raw_unchecked(
        pk: JubJubExtended,
        generator: JubJubExtended,
    ) -> Self {
        Self { pk, generator }
    }
}
