//! Safe secret-key input for the `update` / `deactivate` subcommands.
//!
//! A secret key MUST NOT enter via argv — argv is visible in shell history and
//! `ps`, so a raw `--key <hex>` flag would leak the key.
//! Keys are read from one of three sources, in precedence order:
//!
//! 1. `--key-file <path>` (a file holding raw 32-byte lowercase hex),
//! 2. `--key-stdin` (the same hex on stdin),
//! 3. the `DIDBTC1_KEY` environment variable.
//!
//! The beacon key mirrors this trio (`--beacon-key-file` / `--beacon-key-stdin`
//! / `DIDBTC1_BEACON_KEY`); it defaults to the update key when no
//! beacon-key source is supplied (the same pubkey backs `#initialKey` and all
//! three default singleton beacons).
//!
//! The on-disk / stdin format is raw 32-byte lowercase hex, matching the
//! `--patch` file convention.

use std::io::Read;
use std::path::PathBuf;

use secp256k1::SecretKey;

use crate::CliRunError;

/// A typed key-loading failure. Lifted into [`CliRunError`] via `#[from]`.
#[derive(Debug, onlyerror::Error)]
pub enum KeyError {
    /// No key source was supplied (no file, no stdin, no env var).
    #[error("no secret key supplied: use --key-file, --key-stdin, or set {0}")]
    MissingSource(&'static str),

    /// The supplied value was not valid hex.
    #[error("secret key is not valid hex")]
    BadHex(#[from] hex::FromHexError),

    /// The decoded key was not exactly 32 bytes.
    #[error("secret key must be 32 bytes ({0} bytes supplied)")]
    WrongLength(usize),

    /// The 32 bytes did not form a valid secp256k1 secret key.
    #[error("invalid secp256k1 secret key")]
    InvalidKey(#[from] secp256k1::Error),

    /// An I/O error reading the key file or stdin.
    #[error("I/O error reading the secret key: {0}")]
    Io(#[from] std::io::Error),
}

/// Where a single secret key is read from, and the env var that backs it.
///
/// `file` > `stdin` > `env_var` in precedence. Exactly one of the three is
/// consulted (the first present); `stdin` reads the process stdin to end.
#[derive(Debug)]
pub struct KeySource {
    /// `--key-file <path>` (highest precedence).
    pub file: Option<PathBuf>,
    /// `--key-stdin` (read the key from stdin).
    pub stdin: bool,
    /// The environment variable consulted last (e.g. `DIDBTC1_KEY`).
    pub env_var: &'static str,
}

impl KeySource {
    /// Load the secret key, applying precedence file > stdin > env.
    ///
    /// Reads the chosen source, trims surrounding whitespace/newline, decodes
    /// raw 32-byte lowercase hex, and parses a [`SecretKey`]. Every failure mode
    /// is a typed [`KeyError`] — never a panic, never a default key.
    pub fn load(self) -> Result<SecretKey, KeyError> {
        let raw = if let Some(path) = self.file {
            std::fs::read_to_string(path)?
        } else if self.stdin {
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            buf
        } else if let Ok(val) = std::env::var(self.env_var) {
            val
        } else {
            return Err(KeyError::MissingSource(self.env_var));
        };
        parse_secret_hex(raw.trim())
    }

    /// True if this source reads from stdin (the `--key-stdin` path). Used to
    /// detect the stdin double-consume hazard before any read occurs.
    pub fn reads_stdin(&self) -> bool {
        // A file or env var, if present, takes precedence over stdin, so stdin
        // is only actually consumed when neither is set.
        self.stdin && self.file.is_none()
    }
}

/// Decode raw 32-byte lowercase hex into a [`SecretKey`].
///
/// Pure (no I/O, no env) so it is unit-testable directly. The input is assumed
/// already trimmed.
pub fn parse_secret_hex(hex_str: &str) -> Result<SecretKey, KeyError> {
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != 32 {
        return Err(KeyError::WrongLength(bytes.len()));
    }
    Ok(SecretKey::from_slice(&bytes)?)
}

/// Guard the stdin double-consume hazard.
///
/// `--key-stdin` (or `--beacon-key-stdin`) reads the secret from stdin; the
/// interactive `y/N` broadcast confirm ALSO reads stdin. Those two readers
/// cannot coexist. This returns [`CliRunError::StdinConflict`] IFF a stdin key
/// is combined with an interactive prompt (`!yes && !dry_run`); otherwise the
/// combination is safe (a `--dry-run` never prompts; `--yes` skips the prompt,
/// so stdin is consumed exactly once for the key).
///
/// A pure boolean function — tested directly with the full truth table.
pub fn guard_stdin_confirm(
    key_from_stdin: bool,
    yes: bool,
    dry_run: bool,
) -> Result<(), CliRunError> {
    if key_from_stdin && !yes && !dry_run {
        return Err(CliRunError::StdinConflict);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid 32-byte lowercase-hex secret key (all 0x07 bytes).
    const VALID_HEX: &str = "0707070707070707070707070707070707070707070707070707070707070707";

    /// Pure precedence resolver mirroring [`KeySource::load`]'s source choice,
    /// taking explicit `Option` inputs so the precedence rule is tested without
    /// touching the real filesystem / stdin / process env (avoids env-race).
    fn resolve_source(
        file: Option<&str>,
        stdin: Option<&str>,
        env: Option<&str>,
    ) -> Result<SecretKey, KeyError> {
        let raw = if let Some(f) = file {
            f.to_string()
        } else if let Some(s) = stdin {
            s.to_string()
        } else if let Some(e) = env {
            e.to_string()
        } else {
            return Err(KeyError::MissingSource("DIDBTC1_KEY"));
        };
        parse_secret_hex(raw.trim())
    }

    #[test]
    fn keyload_precedence_file_over_stdin_over_env() {
        let file_key = VALID_HEX;
        let stdin_key = "0808080808080808080808080808080808080808080808080808080808080808";
        let env_key = "0909090909090909090909090909090909090909090909090909090909090909";

        // All three present → file wins.
        let chosen = resolve_source(Some(file_key), Some(stdin_key), Some(env_key))
            .expect("file source decodes");
        assert_eq!(chosen, parse_secret_hex(file_key).unwrap());

        // Only stdin + env → stdin wins.
        let chosen =
            resolve_source(None, Some(stdin_key), Some(env_key)).expect("stdin source decodes");
        assert_eq!(chosen, parse_secret_hex(stdin_key).unwrap());

        // Only env → env is used.
        let chosen = resolve_source(None, None, Some(env_key)).expect("env source decodes");
        assert_eq!(chosen, parse_secret_hex(env_key).unwrap());
    }

    #[test]
    fn keyload_errors_when_none() {
        let err = resolve_source(None, None, None).expect_err("no source is an error");
        assert!(matches!(err, KeyError::MissingSource(_)));
    }

    #[test]
    fn keyload_rejects_argv() {
        // Contract: there is no inline-key argv path. KeySource carries only a
        // file path, a stdin flag, and an env var name — no raw-hex field — so
        // the parser cannot accept a key on the command line. The grep-level
        // acceptance check enforces the absence of a `--key`/`--beacon-key` arm.
        let src = KeySource {
            file: None,
            stdin: false,
            env_var: "DIDBTC1_KEY",
        };
        // No constructor takes a raw hex string; loading with nothing set errors.
        assert!(matches!(src.load(), Err(KeyError::MissingSource(_))));
    }

    #[test]
    fn keyload_parses_hex() {
        let sk = parse_secret_hex(VALID_HEX).expect("32-byte lowercase hex decodes");
        // Round-trips back to the same bytes.
        assert_eq!(hex::encode(sk.secret_bytes()), VALID_HEX);

        // Wrong length is a typed error.
        assert!(matches!(
            parse_secret_hex("0707"),
            Err(KeyError::WrongLength(2))
        ));
        // Non-hex is a typed error.
        assert!(matches!(parse_secret_hex("zzzz"), Err(KeyError::BadHex(_))));
    }

    #[test]
    fn stdin_confirm_conflict_is_typed_error() {
        // key-from-stdin + interactive prompt (no --yes, not --dry-run) → conflict.
        assert!(matches!(
            guard_stdin_confirm(true, false, false),
            Err(CliRunError::StdinConflict)
        ));
        // --yes skips the prompt → stdin consumed once for the key → allowed.
        assert!(guard_stdin_confirm(true, true, false).is_ok());
        // --dry-run never prompts → allowed.
        assert!(guard_stdin_confirm(true, false, true).is_ok());
        // key not from stdin → no conflict regardless.
        assert!(guard_stdin_confirm(false, false, false).is_ok());
    }
}
