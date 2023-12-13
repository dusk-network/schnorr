// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! # Secret Key Module
//!
//! This module provides the `SecretKey` and `SecretKeyVarGen`, essential for
//! signing messages, proving ownership. It facilitates the generation of
//! Schnorr signatures, supporting both single and double signature schemes, as
//! well as signatures with variable generators.

use dusk_bls12_381::BlsScalar;
use dusk_bytes::{Error, Serializable};
use dusk_jubjub::{JubJubScalar, GENERATOR_EXTENDED};
use ff::Field;
use rand_core::{CryptoRng, RngCore};

use crate::Signature;

#[cfg(feature = "var_generator")]
use crate::SignatureVarGen;
#[cfg(feature = "var_generator")]
use dusk_jubjub::{JubJubAffine, JubJubExtended};

#[cfg(feature = "double")]
use crate::SignatureDouble;
#[cfg(feature = "double")]
use dusk_jubjub::GENERATOR_NUMS_EXTENDED;

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

/// Structure representing a [`SecretKey`], represented as a private scalar
/// in the JubJub scalar field.
///
/// ## Examples
///
/// Generate a random `SecretKey`:
/// ```
/// use dusk_schnorr::SecretKey;
/// use rand::rngs::StdRng;
/// use rand::SeedableRng;
///
/// let mut rng = StdRng::seed_from_u64(12345);
/// let sk = SecretKey::random(&mut rng);
/// ```
#[allow(non_snake_case)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct SecretKey(pub(crate) JubJubScalar);

impl From<JubJubScalar> for SecretKey {
    fn from(s: JubJubScalar) -> SecretKey {
        SecretKey(s)
    }
}

impl From<&JubJubScalar> for SecretKey {
    fn from(s: &JubJubScalar) -> SecretKey {
        SecretKey(*s)
    }
}

impl AsRef<JubJubScalar> for SecretKey {
    fn as_ref(&self) -> &JubJubScalar {
        &self.0
    }
}

impl SecretKey {
    /// This will create a random [`SecretKey`] from a scalar
    /// of the Field JubJubScalar.
    pub fn random<T>(rand: &mut T) -> SecretKey
    where
        T: RngCore + CryptoRng,
    {
        let fr = JubJubScalar::random(rand);

        SecretKey(fr)
    }
}

impl Serializable<32> for SecretKey {
    type Error = Error;

    fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        let sk = match JubJubScalar::from_bytes(bytes).into() {
            Some(sk) => sk,
            None => return Err(Error::InvalidData),
        };
        Ok(Self(sk))
    }
}

impl SecretKey {
    /// Signs a chosen message with a given secret key using the dusk variant
    /// of the Schnorr signature scheme.
    ///
    /// This function performs the following cryptographic operations:
    /// - Generates a random nonce `r`.
    /// - Computes `R = r * G`.
    /// - Computes the challenge `c = H(R || m)`.
    /// - Computes the signature `u = r - c * sk`.
    ///
    /// ## Parameters
    ///
    /// - `rng`: Reference to the random number generator.
    /// - `message`: The message in [`BlsScalar`] to be signed.
    ///
    /// ## Returns
    ///
    /// Returns a new [`Signature`] containing the `u` scalar and `R` point.
    ///
    /// ## Example
    ///
    /// Sign a message with a [`SecretKey`] and verify with the respective
    /// [`PublicKey`]:
    /// ```
    /// use dusk_schnorr::{SecretKey, PublicKey};
    /// use dusk_jubjub::JubJubScalar;
    /// use dusk_bls12_381::BlsScalar;
    /// use rand::rngs::StdRng;
    /// use rand::SeedableRng;
    /// use ff::Field;
    ///
    /// let mut rng = StdRng::seed_from_u64(12345);
    ///
    /// let message = BlsScalar::random(&mut rng);
    ///
    /// let sk = SecretKey::random(&mut rng);
    /// let pk = PublicKey::from(&sk);
    ///
    /// let signature = sk.sign(&mut rng, message);
    ///
    /// assert!(pk.verify(&signature, message));
    /// ```
    ///
    /// [`PublicKey`]: [`crate::PublicKey`]
    #[allow(non_snake_case)]
    pub fn sign<R>(&self, rng: &mut R, msg: BlsScalar) -> Signature
    where
        R: RngCore + CryptoRng,
    {
        // Create random scalar value for scheme, r
        let r = JubJubScalar::random(rng);

        // Derive a points from r, to sign with the message
        // R = r * G
        let R = GENERATOR_EXTENDED * r;

        // Compute challenge value, c = H(R||m);
        let c = crate::signatures::challenge_hash(&R, msg);

        // Compute scalar signature, U = r - c * sk,
        let u = r - (c * self.as_ref());

        Signature::new(u, R)
    }

    /// Constructs a new `Signature` instance by signing a given message with
    /// a `SecretKey`.
    ///
    /// Utilizes a secure random number generator to create a unique random
    /// scalar, and subsequently computes public key points `(R, R')` and a
    /// scalar signature `u`.
    ///
    /// # Feature
    ///
    /// Only available with the "double" feature enabled.
    ///
    /// # Parameters
    ///
    /// * `rng`: Cryptographically secure random number generator.
    /// * `message`: Message as a `BlsScalar`.
    ///
    /// # Returns
    ///
    /// A new [`SignatureDouble`] instance.
    ///
    /// ## Example
    ///
    /// Double sign a message with a [`SecretKey`] and verify with the
    /// respective [`PublicKeyDouble`]:
    /// ```
    /// use dusk_schnorr::{SecretKey, PublicKeyDouble};
    /// use dusk_jubjub::JubJubScalar;
    /// use dusk_bls12_381::BlsScalar;
    /// use rand::rngs::StdRng;
    /// use rand::SeedableRng;
    /// use ff::Field;
    ///
    /// let mut rng = StdRng::seed_from_u64(12345);
    ///
    /// let message = BlsScalar::random(&mut rng);
    ///
    /// let sk = SecretKey::random(&mut rng);
    /// let pk = PublicKeyDouble::from(&sk);
    ///
    /// let signature = sk.sign_double(&mut rng, message);
    ///
    /// assert!(pk.verify(&signature, message));
    /// ```
    ///
    /// [`PublicKeyDouble`]: [`crate::PublicKeyDouble`]
    #[allow(non_snake_case)]
    #[cfg(feature = "double")]
    pub fn sign_double<R>(
        &self,
        rng: &mut R,
        message: BlsScalar,
    ) -> SignatureDouble
    where
        R: RngCore + CryptoRng,
    {
        // Create random scalar value for scheme, r
        let r = JubJubScalar::random(rng);

        // Derive two points from r, to sign with the message
        // R = r * G
        // R_prime = r * G'
        let R = GENERATOR_EXTENDED * r;
        let R_prime = GENERATOR_NUMS_EXTENDED * r;
        // Compute challenge value, c = H(R||R_prime||m);
        let c = crate::signatures::challenge_hash_double(&R, &R_prime, message);

        // Compute scalar signature, u = r - c * sk,
        let u = r - (c * self.as_ref());

        SignatureDouble::new(u, R, R_prime)
    }

    /// Create a [`SecretKeyVarGen`], a `SecretKey` with a generator
    /// other than [`GENERATOR_EXTENDED`].
    ///
    /// # Feature
    ///
    /// Only available with the "var_generator" feature enabled.
    ///
    /// # Parameters
    ///
    /// * `generator`: A `JubJubExtended` point that will replace
    /// `GENERATOR_EXTENDED` in the signature algorithm
    ///
    /// # Returns
    ///
    /// A new [`SecretKeyVarGen`] instance.
    #[cfg(feature = "var_generator")]
    pub fn with_variable_generator(
        self,
        generator: JubJubExtended,
    ) -> SecretKeyVarGen {
        SecretKeyVarGen::new(self.0, generator)
    }
}

/// Structure representing a [`SecretKeyVarGen`], represented as a private
/// scalar in the JubJub scalar field, with a variable generator,
/// represented as a point on the JubJub curve.
///
/// # Feature
///
/// Only available with the "var_generator" feature enabled.
///
/// ## Examples
///
/// Generate a random `SecretKey`:
/// Generating a random `SecretKeyVarGen` with a variable generator
/// ```
/// use dusk_schnorr::{SecretKey, SecretKeyVarGen};
/// use rand::rngs::StdRng;
/// use rand::SeedableRng;
/// use dusk_jubjub::{JubJubScalar, GENERATOR_EXTENDED};
/// use ff::Field;
///
/// let mut rng = StdRng::seed_from_u64(12345);
///
/// // generate a variable generator secret key from an existing standard
/// // SecretKey:
/// let sk = SecretKey::random(&mut rng);
/// let generator = GENERATOR_EXTENDED * JubJubScalar::random(&mut rng);
/// let sk_var_gen: SecretKeyVarGen = sk.with_variable_generator(generator);
///
/// // generate a variable generator secret key from the raw values:
/// let sk_var_gen = SecretKeyVarGen::new(JubJubScalar::from(42u64), generator);
///
/// // generate a variable generator secret key at random:
/// let sk_var_gen = SecretKeyVarGen::random(&mut rng);
/// ```
#[allow(non_snake_case)]
#[derive(Clone, Copy, PartialEq, Debug, Default)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
#[cfg(feature = "var_generator")]
pub struct SecretKeyVarGen {
    sk: JubJubScalar,
    generator: JubJubExtended,
}

#[cfg(feature = "var_generator")]
impl Serializable<64> for SecretKeyVarGen {
    type Error = Error;

    fn to_bytes(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        let sk_bytes = self.sk.to_bytes();
        let gen: JubJubAffine = self.generator.into();
        let gen_bytes = gen.to_bytes();
        buf[..32].copy_from_slice(&sk_bytes);
        buf[32..].copy_from_slice(&gen_bytes);
        buf
    }

    fn from_bytes(bytes: &[u8; 64]) -> Result<Self, Error> {
        let mut sk_bytes = [0u8; 32];
        let mut gen_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(&bytes[..32]);
        gen_bytes.copy_from_slice(&bytes[32..]);
        let sk = <JubJubScalar as Serializable<32>>::from_bytes(&sk_bytes)?;
        let generator: JubJubExtended =
            <JubJubAffine as Serializable<32>>::from_bytes(&gen_bytes)?.into();
        Ok(Self { sk, generator })
    }
}

#[cfg(feature = "var_generator")]
impl SecretKeyVarGen {
    /// Create a new [`SecretKeyVarGen`] with a given secret key and a
    /// generator point.
    ///
    /// ## Parameters
    ///
    /// - `sk`: The secret key as `JubJubScalar`.
    /// - `generator`: The generator point as `JubJubExtended`.
    ///
    /// ## Returns
    ///
    /// - A new [`SecretKeyVarGen`] instance for signing with a variable
    ///   generator.
    pub fn new(sk: JubJubScalar, generator: JubJubExtended) -> Self {
        Self { sk, generator }
    }

    /// Create a random [`SecretKeyVarGen`] from a scalar.
    /// of the Field JubJubScalar.
    ///
    /// ## Parameters
    ///
    /// - `rng`: Reference to a random number generator.
    ///
    /// ## Returns
    ///
    /// - A new [`SecretKeyVarGen`] instance for signing with a variable
    ///   generator.
    pub fn random<T>(rand: &mut T) -> SecretKeyVarGen
    where
        T: RngCore + CryptoRng,
    {
        let sk = JubJubScalar::random(&mut *rand);
        let scalar = JubJubScalar::random(&mut *rand);
        let generator = GENERATOR_EXTENDED * scalar;

        SecretKeyVarGen { sk, generator }
    }

    /// Returns a reference to the [`JubJubScalar`] secret key.
    pub(crate) fn secret_key(&self) -> &JubJubScalar {
        &self.sk
    }

    /// Returns a reference to the [`JubJubExtended`] generator.
    pub(crate) fn generator(&self) -> &JubJubExtended {
        &self.generator
    }

    /// Signs a chosen message with a given secret key using the dusk
    /// variant of the Schnorr signature scheme.
    ///
    /// This function performs the following cryptographic operations:
    /// - Generates a random nonce `r`.
    /// - Computes `R = r * G`.
    /// - Computes the challenge `c = H(R || m)`.
    /// - Computes the signature `u = r - c * sk`.
    ///
    /// ## Parameters
    ///
    /// - `rng`: Reference to the random number generator.
    /// - `message`: The message in [`BlsScalar`] to be signed.
    ///
    /// ## Returns
    ///
    /// Returns a new [`SignatureVarGen`] containing the `u` scalar and `R`
    /// point.
    ///
    /// ## Example
    ///
    /// Sign a message with a [`SecretKeyVarGen`] and verify with the respective
    /// [`PublicKeyVarGen`]:
    /// ```
    /// use dusk_schnorr::{SecretKeyVarGen, PublicKeyVarGen};
    /// use dusk_jubjub::JubJubScalar;
    /// use dusk_bls12_381::BlsScalar;
    /// use rand::rngs::StdRng;
    /// use rand::SeedableRng;
    /// use ff::Field;
    ///
    /// let mut rng = StdRng::seed_from_u64(12345);
    ///
    /// let message = BlsScalar::random(&mut rng);
    ///
    /// let sk = SecretKeyVarGen::random(&mut rng);
    /// let pk = PublicKeyVarGen::from(&sk);
    ///
    /// let signature = sk.sign(&mut rng, message);
    ///
    /// assert!(pk.verify(&signature, message));
    /// ```
    ///
    /// [`PublicKeyVarGen`]: [`crate::PublicKeyVarGen`]
    #[allow(non_snake_case)]
    pub fn sign<R>(&self, rng: &mut R, msg: BlsScalar) -> SignatureVarGen
    where
        R: RngCore + CryptoRng,
    {
        // Create random scalar value for scheme, r
        let r = JubJubScalar::random(rng);

        // Derive a points from r, to sign with the message
        // R = r * G
        let R = self.generator() * r;

        // Compute challenge value, c = H(R||H(m));
        let c = crate::signatures::challenge_hash(&R, msg);

        // Compute scalar signature, U = r - c * sk,
        let u = r - (c * self.secret_key());

        SignatureVarGen::new(u, R)
    }
}
