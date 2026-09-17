//! `Accept` header negotiation.
//!
//! The header is read as an RFC 9110 §12.5.1 list of media ranges with `q`
//! weights; every other parameter is ignored. Supported: the full resolution
//! result (`application/did-resolution`) and the bare document in
//! `application/did`, `application/did+json` or `application/did+ld+json`.
//! `*/*` and `application/*` both select the full result, as does an absent
//! or empty header.
//!
//! The highest weight wins. At equal weight the more specific range wins — a
//! named type over `application/*` over `*/*` — and among equally specific
//! named types the supported preference order decides (the full result first,
//! then the bare types in the order above).
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

/// Preference rank of the two wildcard ranges: below every named type
/// (RFC 9110 §12.5.1 — the more specific reference wins at equal weight).
const RANK_APPLICATION_STAR: usize = 4;
const RANK_STAR_STAR: usize = 5;

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
/// Highest q wins; at equal q the lower rank wins, and rank is
/// `application/did-resolution` 0, the bare types 1..=3, `application/*` 4,
/// `*/*` 5. `Err` carries the supported media types for the 406 body.
pub fn negotiate(accept: Option<&str>) -> Result<Mode, Vec<&'static str>> {
    let Some(header) = accept.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(Mode::Full);
    };
    // (q, preference rank, mode) of the best acceptable entry so far.
    let mut best: Option<(f32, usize, Mode)> = None;
    for item in header.split(',') {
        let mut parts = item.split(';');
        let media_type = parts.next().unwrap_or("").trim().to_ascii_lowercase();
        // An unparsable weight counts as the RFC's default of 1. `nan` does
        // parse as an f32; it is excluded outright so it can never be
        // recorded as `best` (which a later entry could then never displace,
        // since every comparison against NaN is false).
        let q = parts
            .filter_map(|p| p.trim().strip_prefix("q="))
            .next()
            .and_then(|v| v.parse::<f32>().ok())
            .unwrap_or(1.0);
        if q.is_nan() || q <= 0.0 {
            continue;
        }
        let candidate = match media_type.as_str() {
            "*/*" => Some((RANK_STAR_STAR, Mode::Full)),
            "application/*" => Some((RANK_APPLICATION_STAR, Mode::Full)),
            m if m == FULL => Some((0, Mode::Full)),
            m => BARE
                .iter()
                .position(|b| *b == m)
                .map(|i| (i + 1, Mode::Bare(BARE[i]))),
        };
        if let Some((rank, mode)) = candidate
            && best
                .as_ref()
                .is_none_or(|(bq, br, _)| q > *bq || (q == *bq && rank < *br))
        {
            best = Some((q, rank, mode));
        }
    }
    best.map(|(_, _, m)| m)
        .ok_or_else(|| std::iter::once(FULL).chain(BARE).collect())
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
