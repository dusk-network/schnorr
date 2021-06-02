# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Add `default-features=false` to `rand_core` [#52](https://github.com/dusk-network/schnorr/issues/52)

### Changed
- Update `canonical` from `0.5` to `0.6` [#41](https://github.com/dusk-network/schnorr/issues/41)
- Update `dusk-plonk` from `0.6` to `0.8` [#41](https://github.com/dusk-network/schnorr/issues/41)
- Update `dusk-poseidon` from `0.18` to `0.21.0-rc` [#41](https://github.com/dusk-network/schnorr/issues/41)
- Update `dusk-pki` from `0.6` to `0.7` [#41](https://github.com/dusk-network/schnorr/issues/41)
- Change crate name from `schnorr` to `dusk-schnorr` [#41](https://github.com/dusk-network/schnorr/issues/41)
### Removed
- Remove `dusk-bls12_381` and import it from `dusk-plonk` [#41](https://github.com/dusk-network/schnorr/issues/41)
- Remove `dusk-jubjub` and import it from `dusk-plonk` [#41](https://github.com/dusk-network/schnorr/issues/41)
- Remove one hashing level for `message` in signature processing [#55](https://github.com/dusk-network/schnorr/issues/55)

### Removed
- Remove `dusk-jubjub` from dependencies [#50](https://github.com/dusk-network/schnorr/issues/50)
- Remove `dusk-bls12_381` from dependencies [#50](https://github.com/dusk-network/schnorr/issues/50)
- Remove `anyhow` from dependencies [#50](https://github.com/dusk-network/schnorr/issues/50)
- Change default crate featureset to be `alloc`. [#50](https://github.com/dusk-network/schnorr/issues/50)
  

## [0.6.0] - 2021-04-06

### Changed

- Update `dusk-plonk` from `0.6` to `0.7` #37
- Update `dusk-poseidon` from `0.19` to `0.20` #37

## [0.5.2] - 2021-02-15

### Changed

- Update `dusk-pki` to pull from crates.io

## [0.5.1] - 2021-02-11

### Changed

- Update `dusk-pki` `v0.6.0`

## [0.5.0] - 2021-02-11

### Changed

- Update `poseidon252` to `dusk-poseidon` `v0.18`

## [0.4.1] - 2021-02-09

### Changed

- Bump `dusk-pki` to `v0.5.3`

## [0.4.0] - 2021-01-29

### Added

- `PublicKeyPair` attributes R and R_prime exposed as methods
- `Proof::keys` added to fetch `PublicKeyPair`

### Changed

- JubJubScalars renamed from `U` to `u`, as in notation standards
- Bump `poseidon252` to `v0.17.0`
- Bump `dusk-pki` to `v0.5.1`

## [0.3.0] - 2021-01-28

### Added

- Add `dusk_bytes::Serializable` trait to structure
- Add dusk_pki's `SecretKey` and `PublicKey`

### Removed

- Remove manual implementation of `to_bytes` and `from_bytes`
- Remove `SecretKey`, `PublicKey` from `schnorr`
- Remove `Error` schnorr enum

### Changed

- `single_key::SecretKey.sign` method is now `Signature::new`
- `double_key::SecretKey.sign` method is now `Proof::new`
- Change return value of single's key `verify` from `Result` to `bool`
- Change return value of double's key `verify` from `Result` to `bool`
- Update CHANGELOG to ISO 8601
- Bump `poseidon252` to `v0.16.0`
- Bump `dusk-bls12_381` to `v0.6`
- Bump `dusk-jubjub` to `v0.8`
- Bump `dusk-plonk` to `v0.5`
- Bump `canonical` to `v0.5`
- Bump `canonical_derive` to `v0.5`

## [0.2.1] - 2021-01-08

### Fixes

- Fix byte truncation for BLS -> JubJub conversion
