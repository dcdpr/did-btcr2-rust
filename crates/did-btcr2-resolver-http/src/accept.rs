//! `Accept` header negotiation.
//!
//! The header is read as an RFC 9110 §12.5.1 list of media ranges with `q`
//! weights; every other parameter is ignored. Supported: the full resolution
//! result (`application/did-resolution`) and the bare document in
//! `application/did`, `application/did+json` or `application/did+ld+json`.
//! `*/*` and `application/*` both select the full result, as does an absent
//! or empty header.
//!
//! Each supported type is weighted by the most specific range that matches
//! it (RFC 9110 §12.5.1: an exact name over `application/*` over `*/*`), so
//! `application/did-resolution;q=0, */*` excludes the full result and still
//! admits every bare type through the wildcard. A type whose weight is 0, or
//! that no range matches, is not acceptable. Among the acceptable types the
//! highest weight wins; at equal weight the one matched by a more specific
//! range wins, and after that the supported preference order (the full
//! result first, then the bare types in the order above).
//!
//! The chosen [`Mode`] maps to two strings: `opts_accept`, the media type
//! handed to the core as `resolutionOptions.accept` (the document's own type,
//! `application/did` inside a full result), and `content_type`, the response
//! header (`application/did-resolution` for a full result, the negotiated type
//! for a bare document).

/// What the negotiated response body is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The full resolution result (`didResolutionMetadata`, `didDocument`,
    /// `didDocumentMetadata`).
    Full,
    /// The bare DID document, in the named representation.
    Bare(&'static str),
}

/// Media type of the full resolution result.
pub const FULL: &str = "application/did-resolution";

/// Bare-document representations, in preference order for q-value ties.
pub const BARE: [&str; 3] = [
    "application/did",
    "application/did+json",
    "application/did+ld+json",
];

/// How specifically a media range names a supported type: an exact name over
/// `application/*` over `*/*` (RFC 9110 §12.5.1). Higher is more specific.
const SPECIFICITY_STAR_STAR: u8 = 0;
const SPECIFICITY_APPLICATION_STAR: u8 = 1;
const SPECIFICITY_EXACT: u8 = 2;

impl Mode {
    /// The `resolutionOptions.accept` value handed to the core — the media type
    /// of the document it produces. A full result wraps an `application/did`
    /// document.
    pub fn opts_accept(self) -> &'static str {
        match self {
            Mode::Full => BARE[0],
            Mode::Bare(t) => t,
        }
    }

    /// The response `Content-Type` for a successful (non-410) response.
    pub fn content_type(self) -> &'static str {
        match self {
            Mode::Full => FULL,
            Mode::Bare(t) => t,
        }
    }
}

/// Pick the response mode from an `Accept` header value (already joined
/// with `,` if the client sent several). Absent or empty -> full result.
/// Each supported type takes the weight of the most specific range that
/// matches it; a type with no match or weight 0 is out. Highest weight wins,
/// then the more specific match, then the preference order
/// `application/did-resolution`, `application/did`, `application/did+json`,
/// `application/did+ld+json`. `Err` carries the supported media types for
/// the 406 body.
pub fn negotiate(accept: Option<&str>) -> Result<Mode, Vec<&'static str>> {
    let Some(header) = accept.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(Mode::Full);
    };
    let ranges: Vec<(String, f32)> = header.split(',').filter_map(parse_range).collect();
    let supported = std::iter::once((FULL, Mode::Full)).chain(BARE.map(|b| (b, Mode::Bare(b))));
    // (q, specificity of the range that set it, mode) of the best type so far.
    let mut best: Option<(f32, u8, Mode)> = None;
    for (media_type, mode) in supported {
        let Some((specificity, q)) = weight_of(media_type, &ranges) else {
            continue;
        };
        if q <= 0.0 {
            continue;
        }
        if best
            .as_ref()
            .is_none_or(|(bq, bs, _)| q > *bq || (q == *bq && specificity > *bs))
        {
            best = Some((q, specificity, mode));
        }
    }
    best.map(|(_, _, m)| m)
        .ok_or_else(|| std::iter::once(FULL).chain(BARE).collect())
}

/// One `Accept` list member as (lower-cased media range, weight). An
/// unparsable weight counts as the RFC's default of 1. `nan` does parse as
/// an f32; a member carrying it is dropped outright, since every comparison
/// against NaN is false and it could neither win nor be displaced.
fn parse_range(item: &str) -> Option<(String, f32)> {
    let mut parts = item.split(';');
    let media_range = parts.next().unwrap_or("").trim().to_ascii_lowercase();
    let q = parts
        .filter_map(|p| p.trim().strip_prefix("q="))
        .next()
        .and_then(|v| v.parse::<f32>().ok())
        .unwrap_or(1.0);
    (!q.is_nan()).then_some((media_range, q))
}

/// RFC 9110 §12.5.1: the weight of `media_type` is that of the most specific
/// range matching it — its exact name, else `application/*`, else `*/*`.
/// Returns the (specificity, weight) pair, or `None` when no range matches.
/// Among equally specific ranges the first one listed sets the weight.
fn weight_of(media_type: &str, ranges: &[(String, f32)]) -> Option<(u8, f32)> {
    let mut best: Option<(u8, f32)> = None;
    for (range, q) in ranges {
        let specificity = match range.as_str() {
            "*/*" => SPECIFICITY_STAR_STAR,
            "application/*" => SPECIFICITY_APPLICATION_STAR,
            r if r == media_type => SPECIFICITY_EXACT,
            _ => continue,
        };
        if best.is_none_or(|(s, _)| specificity > s) {
            best = Some((specificity, *q));
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    const OFFERED: [&str; 4] = [
        "application/did-resolution",
        "application/did",
        "application/did+json",
        "application/did+ld+json",
    ];

    type Row = (Option<&'static str>, Result<Mode, Vec<&'static str>>);

    #[test]
    fn negotiate_rows() {
        let rows: &[Row] = &[
            (None, Ok(Mode::Full)),
            (Some(""), Ok(Mode::Full)),
            (Some("   "), Ok(Mode::Full)),
            (Some("*/*"), Ok(Mode::Full)),
            (Some("application/*"), Ok(Mode::Full)),
            (Some("application/did-resolution"), Ok(Mode::Full)),
            (
                Some("application/did+json"),
                Ok(Mode::Bare("application/did+json")),
            ),
            (
                Some("application/did+ld+json"),
                Ok(Mode::Bare("application/did+ld+json")),
            ),
            (Some("application/did"), Ok(Mode::Bare("application/did"))),
            (
                Some("Application/DID+JSON"),
                Ok(Mode::Bare("application/did+json")),
            ),
            (
                Some("application/x-unsupported-did-representation-99999"),
                Err(OFFERED.to_vec()),
            ),
            (Some("text/html"), Err(OFFERED.to_vec())),
            (
                Some("application/did-resolution;q=0.5, application/did+json"),
                Ok(Mode::Bare("application/did+json")),
            ),
            (Some("application/did+json;q=0"), Err(OFFERED.to_vec())),
            (Some("text/html, */*;q=0.1"), Ok(Mode::Full)),
            (
                Some("application/did+json;q=0.8, application/did+ld+json;q=0.8"),
                Ok(Mode::Bare("application/did+json")),
            ),
            (
                Some("application/did-resolution, application/did+json"),
                Ok(Mode::Full),
            ),
            (
                Some("application/*, application/did+json"),
                Ok(Mode::Bare("application/did+json")),
            ),
            (
                Some("*/*, application/did+ld+json"),
                Ok(Mode::Bare("application/did+ld+json")),
            ),
            (Some("*/*, application/*"), Ok(Mode::Full)),
            (
                Some("application/*;q=1, application/did+json;q=0.5"),
                Ok(Mode::Full),
            ),
            (
                Some("application/did+json;charset=utf-8"),
                Ok(Mode::Bare("application/did+json")),
            ),
            (
                Some("application/did+json;q=nan, application/did"),
                Ok(Mode::Bare("application/did")),
            ),
            (
                Some("application/did+json;q=garbage"),
                Ok(Mode::Bare("application/did+json")),
            ),
            (
                Some(" application/did+ld+json ; q=0.9 , */* ; q=0.1 "),
                Ok(Mode::Bare("application/did+ld+json")),
            ),
            // An explicit `q=0` on a named type excludes it even when a
            // wildcard would otherwise cover it: the most specific range wins.
            (
                Some("application/did-resolution;q=0, */*"),
                Ok(Mode::Bare("application/did")),
            ),
            (
                Some("application/did-resolution;q=0, application/*"),
                Ok(Mode::Bare("application/did")),
            ),
            (
                Some("*/*, application/did-resolution;q=0"),
                Ok(Mode::Bare("application/did")),
            ),
            (
                Some("application/*;q=0, application/did+json"),
                Ok(Mode::Bare("application/did+json")),
            ),
            (Some("application/*;q=0, */*"), Err(OFFERED.to_vec())),
            (
                Some("application/did-resolution;q=-1, */*"),
                Ok(Mode::Bare("application/did")),
            ),
        ];
        for (input, expected) in rows {
            assert_eq!(&negotiate(*input), expected, "{input:?}");
        }
    }

    #[test]
    fn mode_maps_to_opts_accept_and_content_type() {
        assert_eq!(Mode::Full.opts_accept(), "application/did");
        assert_eq!(Mode::Full.content_type(), "application/did-resolution");
        for bare in BARE {
            assert_eq!(Mode::Bare(bare).opts_accept(), bare);
            assert_eq!(Mode::Bare(bare).content_type(), bare);
        }
    }
}
