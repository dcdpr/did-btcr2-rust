# Vendored crates

## bech32-rust

- Source: ssh://git@gl1.dcdpr.com/dcd/bech32-rust.git (private), commit
  27d256c98f8085a99f51479e04b6b5da8ad929bb (2025-08-02), copied 2026-09-30. The crate's
  `repository` field names github.com/dcdpr/bech32-rust, where it has not been published yet.
- Files: Cargo.toml, src/, tests/, README.md, LICENSE-MIT, LICENSE-APACHE, .rustfmt.toml,
  byte-identical to that commit. Not copied: .gitignore, .gitlab-ci.yml, Cargo.lock, deny.toml.
- Licence: MIT OR Apache-2.0.
- The copy is a path dependency of the root crate and excluded from the workspace, so our fmt,
  clippy, doc and test runs do not touch it. Do not edit it here.
- Remove this directory when bech32-rust is published on crates.io, and depend on the published
  crate instead.
