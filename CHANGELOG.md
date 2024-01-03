# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Update `dusk-plonk` -> 0.19
- Update `dusk-poseidon` -> 0.33

## [0.17.0] - 2023-12-13

### Changed

- Move `verify` method to the public key structs [#81]
- Rename `PublicKeyPair` to `PublicKeyDouble` [#110]
- Rename `sign-single` to `sign` [#110]
- Restructure code internally [#110]
- Rename `DoubleSignature` to `SignatureDouble` [#107]
- Rename gadgets [#107]:
  - `single_key_verify` -> `verify_signature`
  - `double_key_verify` -> `verify_signature_double`
- Replace `HexDebug` trait by `Debug` for `SecretKey` and `PublicKey` [#107]
- Derive `PartialEq` trait instead of implementing it manually [#107]
- Derive `PartialEq` for `PublicKeyDouble` [#107]
- Update `dusk-bls12_381` -> 0.13
- Update `dusk-jubjub` -> 0.14
- Update `dusk-plonk` -> 0.18
- Update `dusk-poseidon` -> 0.32

### Added

- Add `from_raw_unchecked` to `PublicKeyDouble` [#81]
- Add latex documentation of the signature scheme to the README [#110]
- Add `SecretKeyVarGen`, `PublicKeyVarGen` and `SignatureVarGen` [#107]
- Add "double" feature for `SignatureDouble` [#107]
- Add "var_generator" feature for `SignatureVarGen` [#107]
- Add gadget `verify_signature_var_gen` [#107]
- Add `ff` dependency

## [0.16.0] - 2023-11-22

### Added

- Update README with keys structure [#104]
- Add documentation to the new key structs [#105]

### Changed

- Change the NotePublicKey tuple struct to directly be a tuple with two fields [#111]
- Change double and single signature creation to be a method on `NoteSecretKey` [#81]
- Rename internal `key_variants` module to `signatures` [#96]
- Rename the signatures method `to_witness` to `append` [#99]
- Update benchmarks to latest version of plonk [#94]
- Update test structure [#94]
- Move `PublicKeyPair` from `DoubleSignature` to `public_keys` [#95]
- Rename keys: `NoteSecretKey` -> `SecretKey`, `NotePublicKey` -> `PublicKey` [#108]

### Removed

- Hide `(Double)Signature::new()` from the public API [#81]

## [0.15.0] - 2023-11-1

### Added

- Move `SecretKey` & `PublicKey` from dusk_pki and renamed them to `NoteSecretKey` & `NotePublicKey` [#80]
- Add lib and module level documentation [#49]

### Changed

- Rename `double_key::Proof` struct to `double_key::Signature` [#89]
- Deprecate `Proof` public struct [#89]
- Re-export `double_key::Proof` as `DoubleSignature` [#89]

## [0.14.0] - 2023-10-12

### Changed

- Update `dusk-bls12_381` from `0.11` to `0.12`
- Update `dusk-jubjub` from `0.12` to `0.13`
- Update `dusk-pki` from `0.12` to `0.13`
- Update `dusk-poseidon` from `0.30` to `0.31`
- Update `dusk-plonk` from `0.14` to `0.16`

### Added

- Add `ff` dev-dependency

### Removed

- Remove `canonical` and `canonical_derive` dependencies
- Remove `canon` feature

## [0.13.0] - 2023-06-28

### Changed

- Update `dusk-pki` from `0.11` to `0.12`
- Update `dusk-poseidon` from `0.28` to `0.30`
- Update `dusk-plonk` from `0.13` to `0.14`
- Update `rust-toolchain` from `nightly-2022-08-08` to `nightly-2023-05-22`

## [0.12.1] - 2022-12-19

### Added

- Derive `Default` for `Signature` and `Proof`

## [0.12.0] - 2022-10-27

### Changed

- Update `dusk-plonk` from `0.12` to `0.13`
- Update `dusk-poseidon` from `0.26` to `0.28`

## [0.11.1] - 2022-10-19

### Added

- Add support for `rkyv-impl` under `no_std`

## [0.11.0] - 2022-08-17

### Added

- Add `CheckBytes` impl for `rkyv`ed structs
- Add `rkyv` implementations behind feature [#69]

### Changed

- Update dusk-poseidon from `0.23.0-rc` to `0.26`
- Update dusk-pki from `0.9.0-rc` to `0.11`
- Update dusk-plonk from `0.9` to `0.12`
- Update dusk-bls12_381 from `0.8` to `0.11`
- Update dusk-jubjub from `0.10` to `0.12`
- Update canonical from `0.6` to `0.7`
- Update canonical_derive from `0.6` to `0.7`

## Fixed

- Fix KeyPair serialization

## [0.8.0-rc]

### Changed

- Update `dusk-poseidon` from `0.21` to `0.22.0-rc` [#59]
- Update `dusk-pki` from `0.7` to `0.8.0-rc` [#59]

## [0.7.0] - 2021-06-02

### Added

- Add `default-features=false` to `rand_core` [#52]

### Changed

- Update `canonical` from `0.5` to `0.6` [#41]
- Update `dusk-plonk` from `0.6` to `0.8` [#41]
- Update `dusk-poseidon` from `0.18` to `0.21.0-rc` [#41]
- Update `dusk-pki` from `0.6` to `0.7` [#41]
- Change crate name from `schnorr` to `dusk-schnorr` [#41]
- Change default crate featureset to be `alloc`. [#50]

### Removed

- Remove one hashing level for `message` in signature processing [#55]
- Remove `anyhow` from dependencies [#50]

## [0.6.0] - 2021-04-06

### Changed

- Update `dusk-plonk` from `0.6` to `0.7` [#37]
- Update `dusk-poseidon` from `0.19` to `0.20` [#37]

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

<!-- ISSUES -->
[#111]: https://github.com/dusk-network/schnorr/issues/111
[#110]: https://github.com/dusk-network/schnorr/issues/110
[#108]: https://github.com/dusk-network/schnorr/issues/108
[#105]: https://github.com/dusk-network/schnorr/issues/105
[#104]: https://github.com/dusk-network/schnorr/issues/104
[#99]: https://github.com/dusk-network/schnorr/issues/99
[#96]: https://github.com/dusk-network/schnorr/issues/96
[#95]: https://github.com/dusk-network/schnorr/issues/95
[#94]: https://github.com/dusk-network/schnorr/issues/94
[#89]: https://github.com/dusk-network/schnorr/issues/89
[#81]: https://github.com/dusk-network/schnorr/issues/81
[#80]: https://github.com/dusk-network/schnorr/issues/80
[#69]: https://github.com/dusk-network/schnorr/issues/69
[#59]: https://github.com/dusk-network/schnorr/issues/59
[#55]: https://github.com/dusk-network/schnorr/issues/55
[#52]: https://github.com/dusk-network/schnorr/issues/52
[#50]: https://github.com/dusk-network/schnorr/issues/50
[#49]: https://github.com/dusk-network/schnorr/issues/49
[#41]: https://github.com/dusk-network/schnorr/issues/41
[#37]: https://github.com/dusk-network/schnorr/issues/37

<!-- VERSIONS -->
[Unreleased]: https://github.com/dusk-network/schnorr/compare/v0.17.0...HEAD
[0.17.0]: https://github.com/dusk-network/schnorr/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/dusk-network/schnorr/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/dusk-network/schnorr/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/dusk-network/schnorr/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/dusk-network/schnorr/compare/v0.12.1...v0.13.0
[0.12.1]: https://github.com/dusk-network/schnorr/compare/v0.12.0...v0.12.1
[0.12.0]: https://github.com/dusk-network/schnorr/compare/v0.11.1...v0.12.0
[0.11.1]: https://github.com/dusk-network/schnorr/compare/v0.11.0...v0.11.1
[0.11.0]: https://github.com/dusk-network/schnorr/compare/v0.7.0...v0.11.0
[0.7.0]: https://github.com/dusk-network/schnorr/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/dusk-network/schnorr/compare/v0.5.2...v0.6.0
[0.5.2]: https://github.com/dusk-network/schnorr/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/dusk-network/schnorr/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/dusk-network/schnorr/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/dusk-network/schnorr/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/dusk-network/schnorr/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/dusk-network/schnorr/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/dusk-network/schnorr/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/dusk-network/schnorr/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/dusk-network/schnorr/releases/tag/v0.1.0
