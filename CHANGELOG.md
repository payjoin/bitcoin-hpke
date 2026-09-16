# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.20.0] - 2026-09-08

Version numbers no longer track upstream `hpke`. Upstream 0.14.0 moved to `hybrid-array`,
`aead` 0.6, and edition 2024, which this fork does not follow, so matching version numbers
would imply a correspondence that no longer exists.

### Additions

* Zeroize DH outputs, key-derivation IKM and DeriveKeyPair candidate bytes, ported from
  upstream rust-hpke
  [#92](https://github.com/rozbb/rust-hpke/pull/92); the secp256k1 DH result and private key
  now erase themselves on drop

### Changes

* SHA-256/384/512 are now backed by rust-bitcoin's [`bitcoin_hashes`](https://crates.io/crates/bitcoin_hashes) instead of [`sha2`](https://crates.io/crates/sha2)
* ChaCha20-Poly1305 is now backed by rust-bitcoin's [`chacha20-poly1305`](https://crates.io/crates/chacha20-poly1305) instead of [`chacha20poly1305`](https://crates.io/crates/chacha20poly1305)
* Dropped the `sha2` and `chacha20poly1305` dependencies
* Bumped MSRV from 1.63.0 to 1.85, matching [rust-payjoin](https://github.com/payjoin/rust-payjoin)

### Notes

* Wire compatibility is unchanged: the RFC 9180 known-answer tests pass unmodified.
* Both new dependencies are CC0-1.0 licensed; the crates they replace were MIT/Apache-2.0.
* `chacha20-poly1305` does not zeroize per-operation key copies. Its key types are `Copy`
  by design, following the rust-bitcoin position in
  [rust-secp256k1#553](https://github.com/rust-bitcoin/rust-secp256k1/issues/553).
  Its 0.2.1 floor is the first release with a constant-time Poly1305 tag comparison.


## [0.13.0] - 2024-09-04

### Additions

* Support [secp256k1-based DHKEM](https://www.ietf.org/archive/id/draft-wahby-cfrg-hpke-kem-secp256k1-01.html) with libsecp256k1 C bindings via rust-bitcoin's [`secp256k1`](https://crates.io/crates/secp256k1) crate. Enable it using the `secp` feature.

### Changes

* Removed `k256`, `x25519`, `p256`, `p384`, and `p521` features
* Removed AesGcm AEAD schemes since bitcoin uses only ChaCha20Poly1305


## [0.12.0] - 2024-07-03

### Additions

* Added `Serializable::write_exact` so serialization requires less stack space
* Added support for the P-521 curve

### Changes

* Constrained `Aead::AeadImpl` to be `Send + Sync`
* Bumped `subtle` dependency and removed `byteorder` dependency

### Removals

* Removed all impls of `serde::{Serialize, Deserailize}` from crate. See [wiki](https://github.com/rozbb/rust-hpke/wiki/Migrating-away-from-the-serde_impls-feature) for migration instructions.

## [0.11.0] - 2023-10-11

### Removals

* Removed the redundant re-export of the first encapsulated key type as `kem::EncappedKey`

### Changes

* Updated `x25519-dalek` to 2.0
* Updated `subtle` to 2.5

## [0.10.0] - 2022-10-01

### Additions
* Added `alloc` feature and feature-gated the `open()` and `seal()` methods behind it

### Changes
* Bumped MSRV from 1.56.1 (`59eed8a2a` 2021-11-01) to 1.57.0 (`f1edd0429` 2021-11-29)
* Updated dependencies and weakened `zeroize` dependency from `>=1.3` to just `^1`
* Improved documentation for the AEAD `export()` method and the KDF `labeled_expand()` method

## [0.9.0] - 2022-05-04

### Additions
* Refactored some internals so end users can theoretically define their own KEMs. See PR [#27](https://github.com/rozbb/rust-hpke/pull/27).

### Changes
* Bumped MSRV from 1.51.0 (`2fd73fabe` 2021-03-23) to 1.56.1 (`59eed8a2a` 2021-11-01)
* Updated dependencies
