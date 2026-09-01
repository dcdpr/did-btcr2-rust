//! secp256k1 key types and BIP340 Multikey encoding used by did:btcr2
//! identifiers and Data Integrity proofs.

use base58::ToBase58;
use onlyerror::Error;
pub use secp256k1::PublicKey;
use secp256k1::SecretKey as Secp256k1SecretKey;
use secp256k1::{Secp256k1, constants::PUBLIC_KEY_SIZE};

/// Multikey prefix specified by [Data Integrity BIP340 Cryptosuites]
///
/// [Data Integrity BIP340 Cryptosuites]: https://dcdpr.github.io/data-integrity-schnorr-secp256k1/#multikey
const MULTIKEY_PREFIX: [u8; 2] = [0xe7, 0x01];

/// Errors arising while constructing keys from bytes or decoding BIP340
/// Multikey strings.
#[derive(Error, Debug)]
pub enum Error {
    /// Failed to create public key from bytes
    InvalidBytesForPublicKey(#[source] secp256k1::Error),

    /// Failed to create secret key from bytes
    InvalidBytesForSecretKey(#[source] secp256k1::Error),

    /// Multikey must start with 'z' (base58-btc)
    MultibasePrefix,

    /// Failed to decode base58
    MultikeyBase58,

    /// Invalid Multikey prefix or length for a secp256k1 compressed public key
    MultikeyPrefix,
}

/// Extension trait adding BIP340 Multikey encode/decode to [`PublicKey`].
pub trait PublicKeyExt {
    /// Create a `PublicKey` from a BIP-340 Multikey.
    fn from_multikey(multikey: &str) -> Result<Self, Error>
    where
        Self: Sized;

    /// Encode a `PublicKey` into a BIP-340 Multikey.
    fn to_multikey(&self) -> String;
}

impl PublicKeyExt for PublicKey {
    fn from_multikey(multikey: &str) -> Result<Self, Error> {
        // Ensure multikey starts with 'z' (base58-btc)
        if !multikey.starts_with('z') {
            return Err(Error::MultibasePrefix);
        }

        // Remove 'z' prefix and decode base58
        let data =
            base58::FromBase58::from_base58(&multikey[1..]).map_err(|_| Error::MultikeyBase58)?;

        // Cryptosuite §2.1.1: bip340-jcs multikeys MUST be the 2-byte prefix +
        // a 33-byte COMPRESSED secp256k1 key. Any other encoding (e.g. a
        // 65-byte uncompressed key) MUST NOT be allowed, so enforce the exact
        // total length before handing bytes to from_slice.
        if data.len() != 2 + PUBLIC_KEY_SIZE {
            return Err(Error::MultikeyPrefix);
        }

        // Check prefix
        if data[0..2] != MULTIKEY_PREFIX {
            return Err(Error::MultikeyPrefix);
        }

        // Extract key data (after the 2-byte prefix)
        Self::from_slice(&data[2..]).map_err(Error::InvalidBytesForPublicKey)
    }

    fn to_multikey(&self) -> String {
        const PREFIX_LEN: usize = MULTIKEY_PREFIX.len();

        // Serialize to bytes
        let key_bytes = self.serialize();

        // Prepend Multikey prefix for secp256k1 compressed public key
        let mut data = [0; PREFIX_LEN + PUBLIC_KEY_SIZE];

        data[..PREFIX_LEN].copy_from_slice(&MULTIKEY_PREFIX);
        data[PREFIX_LEN..].copy_from_slice(&key_bytes);

        // Encode with base58-btc
        let encoded = data.to_base58();

        // Prepend 'z' for base58-btc
        format!("z{encoded}")
    }
}

/// A secp256k1 secret key that zeroizes its bytes on drop.
///
/// Wraps [`secp256k1::SecretKey`]; the inner key is exposed only at the final
/// point of use (the sign boundary) via the crate-private `as_inner`. The owned
/// bytes are scrubbed to `[1u8; 32]` when the value drops, so a used-and-dropped
/// secret key does not linger in process memory.
pub struct SecretKey(Secp256k1SecretKey);

// Do NOT derive `Copy`/`Debug`: `Drop` forbids `Copy`, and a derived `Debug`
// would print the raw secret bytes. `Debug` is redacted manually below.
//
// `Clone` is deliberately NOT implemented: the inner secp `SecretKey` is `Copy`,
// so a clone would duplicate the 32 secret bytes, and an ambient `.clone()`
// (easy to add, easy to hit implicitly through a `#[derive(Clone)]` on a
// containing struct) would silently fan out in-memory copies of the secret and
// widen the window before all are scrubbed. If a duplication is ever genuinely
// required, add an explicit, named method (e.g. `duplicate_secret`) so each
// secret copy is visible at the call site rather than an ambient capability.
impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(..)")
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        // secp256k1 0.27 overwrites the inner 32 bytes with `[1u8; 32]` in place
        // (all-zero is an invalid key, so it scrubs to all-ones).
        self.0.non_secure_erase();
    }
}

// The fixed-size-newtype convention (~/.claude/CLAUDE.md) prescribes an
// infallible `From<[u8; 32]>`. `SecretKey` deviates deliberately: a
// length-correct 32 bytes can still be an invalid secp scalar (all-zero or
// >= curve order), a *value* invariant that length cannot express. An
// infallible `From` would have to panic on such bytes, so both constructors are
// fallible `TryFrom` — every path stays panic-free on untrusted input.
impl TryFrom<Vec<u8>> for SecretKey {
    type Error = Error;
    fn try_from(v: Vec<u8>) -> Result<Self, Error> {
        Secp256k1SecretKey::from_slice(&v)
            .map(SecretKey)
            .map_err(Error::InvalidBytesForSecretKey)
    }
}

impl TryFrom<[u8; 32]> for SecretKey {
    type Error = Error;
    fn try_from(arr: [u8; 32]) -> Result<Self, Error> {
        Secp256k1SecretKey::from_slice(&arr)
            .map(SecretKey)
            .map_err(Error::InvalidBytesForSecretKey)
    }
}

impl SecretKey {
    /// Generate a new random secret key.
    pub fn generate() -> Self {
        SecretKey(Secp256k1SecretKey::new(&mut rand::rngs::OsRng))
    }

    /// Borrow the inner secp256k1 key. Call only at the final point of use
    /// (the sign boundary); do not store the returned reference.
    pub(crate) fn as_inner(&self) -> &Secp256k1SecretKey {
        &self.0
    }
}

/// Represents a key pair (public and secret key)
///
/// Not `Clone`: `secret_key` is a non-`Clone` [`SecretKey`], so cloning a
/// `KeyPair` cannot silently duplicate the secret material it holds.
#[derive(Debug)]
pub struct KeyPair {
    /// The public key
    pub public_key: PublicKey,
    // `secret_key` is private and reached only via `secret_key(&self)`; its
    // `Debug` is redacted by `SecretKey`'s manual `Debug` impl, so
    // `KeyPair: Debug` prints no secret bytes.
    secret_key: SecretKey,
}

impl KeyPair {
    /// Create a new key pair from a secret key
    pub fn from_secret_key(secret_key: SecretKey) -> Self {
        let secp = Secp256k1::new();
        let public_key = secret_key.as_inner().public_key(&secp);
        Self {
            public_key,
            secret_key,
        }
    }

    /// Generate a new random key pair
    pub fn generate() -> Self {
        Self::from_secret_key(SecretKey::generate())
    }

    /// Borrow this pair's secret key.
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_secure_erase_zeroizes_inner() {
        // Evidence (a): the scrub primitive that SecretKey::drop calls
        // actually zeroizes. Sound in-place mutation — no freed-memory read.
        let mut inner =
            Secp256k1SecretKey::from_slice(&[7u8; 32]).expect("[7u8;32] is a valid secp scalar");
        inner.non_secure_erase();
        assert_eq!(inner.secret_bytes(), [1u8; 32]); // secp overwrites with all-ones
    }

    #[test]
    fn test_drop_scrubs_secret_key() {
        // Evidence (b): running SecretKey::drop scrubs the owned bytes to
        // [1u8;32]. ManuallyDrop keeps the storage VALID after drop_in_place, so the
        // post-drop read is on live memory — NOT a freed-memory / stale-pointer read.
        use core::mem::ManuallyDrop;
        let mut key = ManuallyDrop::new(
            SecretKey::try_from([7u8; 32]).expect("[7u8;32] is a valid secp scalar"),
        );
        // SAFETY: `key` is a live ManuallyDrop; drop_in_place runs SecretKey::drop
        // (invoking non_secure_erase) but leaves the storage owned by ManuallyDrop,
        // so reading it immediately afterward is defined behavior. We never touch
        // `key` again after this read, so no double-drop occurs.
        unsafe {
            core::ptr::drop_in_place(&mut *key as *mut SecretKey);
        }
        assert_eq!(key.as_inner().secret_bytes(), [1u8; 32]);
    }

    #[test]
    fn test_try_from_vec_rejects_wrong_length() {
        let err = SecretKey::try_from(vec![0u8; 31]).expect_err("31 bytes is not a valid key");
        assert!(matches!(err, Error::InvalidBytesForSecretKey(_)));
    }

    #[test]
    fn test_try_from_vec_rejects_invalid_scalar() {
        // All-zero is a length-correct but invalid secp scalar.
        let err = SecretKey::try_from(vec![0u8; 32]).expect_err("all-zero is an invalid scalar");
        assert!(matches!(err, Error::InvalidBytesForSecretKey(_)));
    }

    #[test]
    fn test_try_from_array_roundtrips() {
        let key = SecretKey::try_from([1u8; 32]).expect("[1u8;32] is a valid secp scalar");
        let expected =
            Secp256k1SecretKey::from_slice(&[1u8; 32]).expect("[1u8;32] is a valid secp scalar");
        assert_eq!(*key.as_inner(), expected);
    }

    #[test]
    fn test_from_secret_key_public_key_consistency() {
        let sk = SecretKey::try_from([7u8; 32]).expect("[7u8;32] is a valid secp scalar");
        let sk_copy = SecretKey::try_from([7u8; 32]).expect("[7u8;32] is a valid secp scalar");
        let kp = KeyPair::from_secret_key(sk);
        let expected = sk_copy.as_inner().public_key(&Secp256k1::new());
        assert_eq!(kp.public_key, expected);
    }

    #[test]
    fn test_generate_distinctness() {
        let a = SecretKey::generate();
        let b = SecretKey::generate();
        assert_ne!(a.as_inner(), b.as_inner());
    }

    // `PublicKey::from_multikey` parses attacker-controlled
    // `publicKeyMultibase` out of resolved DID documents. Every validation rule
    // in from_multikey (key.rs:47-64) gets a focused negative test asserting the
    // CONCRETE typed variant the code returns, plus a to/from round-trip. The
    // runtime variant assertions here are the gate — not the greps.

    #[test]
    fn test_from_multikey_rejects_missing_z_prefix() {
        // Rule: `!multikey.starts_with('z')` -> Error::MultibasePrefix (key.rs:49-51).
        let err = PublicKey::from_multikey("xabc").expect_err("non-'z' prefix must be rejected");
        match err {
            Error::MultibasePrefix => {}
            other => panic!("expected MultibasePrefix, got {other:?}"),
        }
    }

    #[test]
    fn test_from_multikey_rejects_non_base58_payload() {
        // Rule: base58 decode failure -> Error::MultikeyBase58 (key.rs:54-55).
        // base58 alphabet excludes 0, O, I, l — a payload of only those chars
        // cannot decode.
        let err =
            PublicKey::from_multikey("z0OIl").expect_err("non-base58 payload must be rejected");
        match err {
            Error::MultikeyBase58 => {}
            other => panic!("expected MultikeyBase58, got {other:?}"),
        }
    }

    #[test]
    fn test_from_multikey_rejects_short_decoded() {
        // Rule: decoded len < 2 -> Error::MultikeyPrefix (key.rs:58-60).
        // 'z' + base58 of a 1-byte payload decodes to len 1.
        let multikey = format!("z{}", [0x00u8].to_base58());
        let err =
            PublicKey::from_multikey(&multikey).expect_err("decoded length < 2 must be rejected");
        match err {
            Error::MultikeyPrefix => {}
            other => panic!("expected MultikeyPrefix, got {other:?}"),
        }
    }

    #[test]
    fn test_from_multikey_rejects_wrong_prefix() {
        // Rule: first two bytes != MULTIKEY_PREFIX ([0xe7,0x01]) -> Error::MultikeyPrefix
        // (key.rs:58-60). Length is valid (>= 2), only the prefix is wrong.
        let mut bytes = vec![0x00u8, 0x00u8];
        bytes.extend_from_slice(&[0x02u8; 33]);
        let multikey = format!("z{}", bytes.to_base58());
        let err = PublicKey::from_multikey(&multikey)
            .expect_err("wrong 2-byte multikey prefix must be rejected");
        match err {
            Error::MultikeyPrefix => {}
            other => panic!("expected MultikeyPrefix, got {other:?}"),
        }
    }

    #[test]
    fn test_from_multikey_rejects_non_curve_point() {
        // Rule: valid prefix + 33 bytes that are not a curve point ->
        // Error::InvalidBytesForPublicKey (key.rs:63). 0x02 || [0xff;32] is a
        // compressed-form x-coordinate with no valid y (>= field prime).
        let mut bytes = MULTIKEY_PREFIX.to_vec();
        bytes.push(0x02);
        bytes.extend_from_slice(&[0xffu8; 32]);
        let multikey = format!("z{}", bytes.to_base58());
        let err = PublicKey::from_multikey(&multikey)
            .expect_err("non-curve-point key bytes must be rejected");
        match err {
            Error::InvalidBytesForPublicKey(_) => {}
            other => panic!("expected InvalidBytesForPublicKey, got {other:?}"),
        }
    }

    #[test]
    fn test_from_multikey_rejects_uncompressed_key() {
        // Cryptosuite §2.1.1: a multikey carrying a 65-byte UNCOMPRESSED
        // secp256k1 key (prefix + 65 bytes = len 67) MUST be rejected. Without
        // the exact-length gate, from_slice would happily accept it.
        let sk = SecretKey::try_from([9u8; 32]).expect("[9u8;32] is a valid secp scalar");
        let pk = sk.as_inner().public_key(&Secp256k1::new());
        let mut bytes = MULTIKEY_PREFIX.to_vec();
        bytes.extend_from_slice(&pk.serialize_uncompressed()); // 65 bytes
        assert_eq!(bytes.len(), 2 + 65);
        let multikey = format!("z{}", bytes.to_base58());
        let err = PublicKey::from_multikey(&multikey)
            .expect_err("a 65-byte uncompressed key multikey must be rejected");
        match err {
            Error::MultikeyPrefix => {}
            other => panic!("expected MultikeyPrefix (length gate), got {other:?}"),
        }
    }

    #[test]
    fn test_from_multikey_round_trip() {
        // A real public key survives to_multikey -> from_multikey unchanged.
        let sk = SecretKey::try_from([7u8; 32]).expect("[7u8;32] is a valid secp scalar");
        let pk = sk.as_inner().public_key(&Secp256k1::new());
        let decoded =
            PublicKey::from_multikey(&pk.to_multikey()).expect("round-trip multikey must decode");
        assert_eq!(decoded, pk);
    }
}
