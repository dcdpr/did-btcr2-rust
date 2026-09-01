//! Secret material this tool holds in memory, and the one rule that governs it:
//! a buffer that held a secret is overwritten before it is dropped.
//!
//! Two secrets pass through this crate — the key that mints the DIDs and the
//! node's RPC credential — and they get the same treatment. Reading either with
//! `read_to_string` puts it into an owned heap buffer that is freed unscrubbed,
//! leaving that copy behind for whatever allocates the page next. That is the
//! leak the minting key's fixed-size decode already avoids, and this module is
//! where the avoidance lives so the second secret cannot drift from the first.
//!
//! Nothing here uses `unsafe`; the crate forbids it.

use std::path::Path;

/// Overwrite a buffer that held secret material, before it is dropped.
///
/// The `black_box` is what makes the write survive: a store to memory that is
/// never read again is dead and the optimizer may remove it, which would leave
/// the scrub in the source and not in the binary. No `unsafe` and no extra
/// dependency — a volatile write or the `zeroize` crate would do the same job.
pub fn scrub(bytes: &mut [u8]) {
    bytes.fill(0);
    std::hint::black_box(bytes);
}

/// A secret held as owned bytes, scrubbed when it is dropped.
///
/// BYTES rather than a `String`: a `String`'s buffer cannot be overwritten
/// without `unsafe`, which this crate forbids, so a secret kept as one is a
/// secret that cannot be scrubbed at all. The contents are validated as UTF-8
/// and trimmed once, at construction, which is what lets [`Secret::expose`] be
/// infallible and every caller see the same value.
///
/// `Debug` is implemented by hand and renders `<redacted>`, so a secret cannot
/// reach a log or an error through a `{:?}` on something that happens to hold
/// one. There is deliberately no `Display`, no `Clone` and no `Serialize`: the
/// value comes out through `expose` at the point of use and nowhere else.
pub struct Secret(Vec<u8>);

impl Secret {
    /// Read a secret out of a file, trimmed of surrounding whitespace.
    ///
    /// Reads bytes and scrubs them. `std::fs::read_to_string` would put the
    /// whole file — credential included — into a `String` that is dropped
    /// intact, which is the leak this type exists to close.
    pub fn from_file(path: &Path) -> Result<Self, std::io::Error> {
        let mut raw = std::fs::read(path)?;
        let secret = std::str::from_utf8(&raw)
            .map(|text| Self(text.trim().as_bytes().to_vec()))
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "the file is not UTF-8 text",
                )
            });
        scrub(&mut raw);
        secret
    }

    /// Adopt a secret that is already exposed — an argv value, which sits in
    /// world-readable `/proc/<pid>/cmdline` for the life of the process and in
    /// shell history besides.
    ///
    /// Scrubbing from here on is still worth doing and this type still does it,
    /// but nothing undoes that exposure. It is why the file form is the
    /// documented one.
    pub fn from_exposed(value: &str) -> Self {
        Self(value.trim().as_bytes().to_vec())
    }

    /// Whether the secret carries nothing.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The secret as text, at the point of use.
    pub fn expose(&self) -> &str {
        std::str::from_utf8(&self.0).expect("the bytes were validated as UTF-8 at construction")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        scrub(&mut self.0);
    }
}

// Implemented BY HAND, not derived: a derived one would print the bytes, putting
// the secret into any `{:?}` and into any error or log line that wraps a value
// holding one.
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A credential that is non-repetitive, so a substring scan for it is a real
    /// check rather than one that matches any run of zeros.
    const CREDENTIAL: &str = "rpcuser:s3cr3t-node-password";

    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "chain-capture-secret-{}-{tag}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("scratch directory is creatable");
        dir
    }

    #[test]
    fn scrub_overwrites_the_buffer_it_is_given() {
        // The property both loaders depend on: after `scrub`, the buffer that
        // held the secret holds nothing. Whether the allocation is later reused
        // is the allocator's business; leaving the secret in it is not.
        //
        // Both shapes the callers pass: a heap buffer a file was read into, and
        // the fixed-size array the minting key is decoded onto.
        let mut buffer = b"rpcuser:s3cr3t-node-password".to_vec();
        scrub(&mut buffer);
        assert!(
            buffer.iter().all(|b| *b == 0),
            "every byte is overwritten, not just the length reset: {buffer:?}"
        );

        let mut decoded = [7u8; 32];
        scrub(&mut decoded);
        assert_eq!(decoded, [0u8; 32]);
    }

    #[test]
    fn a_secret_read_from_a_file_is_trimmed_and_never_rendered() {
        let dir = scratch_dir("from-file");
        let path = dir.join("rpc.auth");
        std::fs::write(&path, format!("  {CREDENTIAL}\n\n")).expect("the file is writable");

        let secret = Secret::from_file(&path).expect("the credential file reads");
        assert_eq!(
            secret.expose(),
            CREDENTIAL,
            "surrounding whitespace is not part of the credential"
        );
        assert!(!secret.is_empty());
        assert_eq!(
            format!("{secret:?}"),
            "<redacted>",
            "a Debug render must not carry the secret"
        );

        std::fs::remove_dir_all(&dir).expect("scratch directory is removable");
    }

    #[test]
    fn a_file_that_is_not_text_is_refused_by_reason_and_not_by_encoding() {
        let dir = scratch_dir("not-text");
        let path = dir.join("binary.auth");
        std::fs::write(&path, [0xff, 0xfe, 0x00, 0x01]).expect("the file is writable");

        let error = Secret::from_file(&path).expect_err("a non-text file is not a credential");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            !error.to_string().contains("0xff") && !error.to_string().contains("255"),
            "the refusal names the reason, never the bytes: {error}"
        );

        std::fs::remove_dir_all(&dir).expect("scratch directory is removable");
    }

    #[test]
    fn an_empty_or_whitespace_only_file_yields_an_empty_secret() {
        // Empty is reported to the caller rather than accepted here, because
        // what an empty credential MEANS is the caller's decision: the node
        // needs one, the endpoint rule does not.
        let dir = scratch_dir("empty");
        let path = dir.join("empty.auth");
        std::fs::write(&path, "   \n").expect("the file is writable");

        assert!(
            Secret::from_file(&path)
                .expect("whitespace still reads")
                .is_empty()
        );

        std::fs::remove_dir_all(&dir).expect("scratch directory is removable");
    }

    #[test]
    fn an_argv_secret_is_trimmed_the_same_way() {
        let secret = Secret::from_exposed("  rpcuser:s3cr3t-node-password  ");
        assert_eq!(secret.expose(), CREDENTIAL);
        assert_eq!(format!("{secret:?}"), "<redacted>");
    }
}
