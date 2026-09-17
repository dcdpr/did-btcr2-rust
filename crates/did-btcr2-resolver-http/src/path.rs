//! Request-target path handling: strict percent-decoding and the one route.
//!
//! The decoder is hand-rolled rather than borrowed from `urlencoding` because
//! that crate's `decode` passes a malformed escape (`%ZZ`, or a trailing `%2`)
//! through literally; the binding must answer 400 for those, so a malformed
//! escape has to be an error here, not a silently kept byte.

use std::fmt;

/// Why a percent-encoded path segment could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// A `%` with fewer than two following characters.
    Truncated,
    /// A `%` followed by a non-hexadecimal character.
    NotHex,
    /// The decoded bytes are not valid UTF-8.
    Utf8,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "truncated percent-escape",
            Self::NotHex => "non-hexadecimal percent-escape",
            Self::Utf8 => "decoded bytes are not valid UTF-8",
        })
    }
}

impl std::error::Error for DecodeError {}

/// Decode `%HH` escapes exactly once. `+` is literal (this is a path segment,
/// not a form body); no case normalisation of anything; a malformed escape
/// is an error, not passed through.
pub fn percent_decode(s: &str) -> Result<String, DecodeError> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hi = *bytes.get(i + 1).ok_or(DecodeError::Truncated)?;
            let lo = *bytes.get(i + 2).ok_or(DecodeError::Truncated)?;
            let hex = |c: u8| (c as char).to_digit(16).ok_or(DecodeError::NotHex);
            out.push(((hex(hi)? as u8) << 4) | hex(lo)? as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| DecodeError::Utf8)
}

/// The resolver path prefix of the DID Resolution HTTP binding.
pub const RESOLVE_PREFIX: &str = "/1.0/identifiers/";

/// Where a request-target path lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route<'a> {
    /// The resolver endpoint; `encoded_did` is the raw, undecoded segment
    /// after the prefix (possibly empty).
    Resolve {
        /// The raw path segment after the prefix, still percent-encoded.
        encoded_did: &'a str,
    },
    /// Any other path.
    NotFound,
}

/// Match the path against the one route the binding serves. The prefix
/// itself without a trailing slash is not the resolver endpoint.
pub fn route(path: &str) -> Route<'_> {
    match path.strip_prefix(RESOLVE_PREFIX) {
        Some(rest) => Route::Resolve { encoded_did: rest },
        None => Route::NotFound,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decode_rows() {
        let rows: &[(&str, Result<&str, DecodeError>)] = &[
            ("did%3Abtcr2%3Ak1abc", Ok("did:btcr2:k1abc")),
            ("did:btcr2:k1abc", Ok("did:btcr2:k1abc")),
            ("%253A", Ok("%3A")),
            ("a+b", Ok("a+b")),
            ("%3a", Ok(":")),
            ("did%3Abtcr2%3AK1", Ok("did:btcr2:K1")),
            ("%3G", Err(DecodeError::NotHex)),
            ("abc%2", Err(DecodeError::Truncated)),
            ("abc%", Err(DecodeError::Truncated)),
            ("%FF", Err(DecodeError::Utf8)),
        ];
        for (input, expected) in rows {
            let got = percent_decode(input);
            assert_eq!(got.as_deref(), expected.as_deref(), "{input}");
        }
    }

    #[test]
    fn decode_error_displays_a_reason() {
        assert_eq!(
            DecodeError::Truncated.to_string(),
            "truncated percent-escape"
        );
        assert_eq!(
            DecodeError::NotHex.to_string(),
            "non-hexadecimal percent-escape"
        );
        assert_eq!(
            DecodeError::Utf8.to_string(),
            "decoded bytes are not valid UTF-8"
        );
    }

    #[test]
    fn route_rows() {
        let rows: &[(&str, Route<'_>)] = &[
            (
                "/1.0/identifiers/did:btcr2:k1abc",
                Route::Resolve {
                    encoded_did: "did:btcr2:k1abc",
                },
            ),
            ("/1.0/identifiers/", Route::Resolve { encoded_did: "" }),
            ("/1.0/identifiers", Route::NotFound),
            ("/", Route::NotFound),
            ("", Route::NotFound),
            (
                "/1.0/identifiers/did:x/extra",
                Route::Resolve {
                    encoded_did: "did:x/extra",
                },
            ),
            ("/2.0/identifiers/did:x", Route::NotFound),
        ];
        for (input, expected) in rows {
            assert_eq!(route(input), *expected, "{input}");
        }
    }
}
