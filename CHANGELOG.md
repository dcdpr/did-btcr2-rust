# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Versioning

This crate is pre-1.0 and tracks the in-progress did:btcr2 method spec.
During pre-1.0 the version is held; changes accumulate under **Unreleased**.
Semver discipline begins at the 1.0 cut, once the did:btcr2 spec stabilizes.

## [Unreleased]

### Added

### Changed

- On-wire DID prefix flipped from `did:btc1:` to `did:btcr2:` (no back-compat;
  the parser rejects the old `did:btc1:` prefix).

### Deprecated

### Removed

### Fixed

### Security
