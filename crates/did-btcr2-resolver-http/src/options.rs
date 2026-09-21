//! Query string or `POST` body -> resolution options.
//!
//! Three names are accepted, the three scalar options the core models:
//! `versionId` (a positive integer), `versionTime` (an RFC 3339 timestamp,
//! normalised to UTC) and `minConf` (a positive integer). Two further
//! registered DID Resolution options are recognised but not implemented.
//! `noCache` (DID Resolution §13.2) takes `true` or `false`: `false` is the
//! spec's default — caching allowed — and is accepted as a no-op; `true` asks
//! to bypass the response cache this resolver keeps, which it declines with
//! `FEATURE_NOT_SUPPORTED`, the answer the spec requires of a resolver that
//! denies resolution without caching; any other value is malformed, so
//! `INVALID_OPTIONS`. Declining is not a control — the cache is a latency and
//! upstream-quota optimisation, and an empty-body `POST` reaches the backend
//! every time — it is simply an option the binding does not implement.
//! `expandRelativeUrls` is not implemented for any value and is
//! `FEATURE_NOT_SUPPORTED` outright.
//!
//! Every other name is rejected, not ignored: a silently dropped `versionld`
//! (or an `accept`, which the HTTP binding carries in the header only) would
//! resolve the wrong version and report success. A duplicated name is rejected
//! for the same reason — there is no "last one wins" to get wrong. A detail
//! that names the offending member shows at most 64 characters of it, so an
//! error body never grows with the request; no detail echoes a value.
//!
//! `versionId` and `versionTime` together are rejected here as well as in the
//! core's `Resolver::new`, with the same detail text. The core check comes
//! after the client has fetched the chain tip, so leaving the pair to it
//! would cost a wasted backend round-trip and, with the backend down, turn a
//! deterministic 400 `INVALID_OPTIONS` into a 500.
//!
//! The body form ([`parse_body_options`]) takes the same names as members of
//! one JSON object — `versionId` and `minConf` as a JSON number or a string
//! of decimal digits, `versionTime` as a string, `noCache` as a boolean —
//! plus `sidecar`, the did:btcr2 method option carrying spec-form sidecar
//! data. A body that is not a JSON object, or a `sidecar` that is not sidecar
//! data, is `INVALID_OPTIONS`. The unknown-name rule reaches into `sidecar`
//! too: its members are `genesisDocument`, `updates`, `casUpdates` and
//! `smtProofs`, and any other is rejected — the core's deserialiser would
//! ignore it, and a mis-keyed `update` would resolve without the updates.
//!
//! A member given more than once is rejected as in the query form. The body
//! is read member by member through a `Deserialize` over serde's `MapAccess`,
//! which streams every key as written, because `serde_json::Value` collapses
//! a repeat to its last occurrence before the binding could see it. The check
//! stops at the top level: `sidecar` is taken as a `Value`, so a member
//! repeated inside it takes the last occurrence. That is deliberate. The
//! sidecar is evidence the resolver verifies against the chain — update
//! hashes against beacon signals, the genesis document against the
//! identifier, CAS and SMT entries against their hashes and roots — so a
//! collapsed duplicate there fails verification or changes nothing, while a
//! repeated option is an instruction with two readings and no backstop.

use std::collections::HashSet;
use std::fmt;
use std::num::{NonZeroU32, NonZeroU64};

use did_btcr2::document::{ResolutionOptions, SidecarData};
use did_btcr2::error::{Btcr2Error, ProblemDetails};
use serde::de::{self, Deserialize, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

use crate::path::percent_decode;
use crate::problem::Problem;

/// Why the query string or body was rejected: the caller turns it into a
/// problem body.
#[derive(Debug)]
pub enum OptionsError {
    /// `INVALID_OPTIONS` — a malformed value, an unknown or duplicated name,
    /// or `accept` as a query parameter.
    Invalid(Btcr2Error),
    /// `FEATURE_NOT_SUPPORTED` — a registered option this resolver does not
    /// implement.
    Unsupported(Problem),
}

impl OptionsError {
    /// The RFC 9457 object for this failure.
    pub fn details(&self) -> Value {
        match self {
            Self::Invalid(e) => e.details(),
            Self::Unsupported(p) => p.details(),
        }
        .expect("both variants carry problem details")
    }
}

fn invalid(detail: String) -> OptionsError {
    OptionsError::Invalid(Btcr2Error::InvalidOptions(detail))
}

/// The most characters of a client-supplied name a rejection detail echoes.
const SHOWN_NAME_CHARS: usize = 64;

/// A client-supplied name as a detail shows it: at most [`SHOWN_NAME_CHARS`]
/// characters, `…` appended when cut. A detail names the offending member so
/// the client can find it, but a body at the limit can carry a member name a
/// mebibyte long and the query form's names are bounded only by the request
/// line; without the cut the error body would grow with the request.
fn shown(name: &str) -> String {
    let mut shown: String = name.chars().take(SHOWN_NAME_CHARS).collect();
    if name.chars().nth(SHOWN_NAME_CHARS).is_some() {
        shown.push('…');
    }
    shown
}

/// The members of spec-form sidecar data, by their wire names — the exact set
/// the core's `SidecarData` deserialiser reads (`did_btcr2::document`, the
/// private `SidecarDataWire`). The core ignores any other member; the binding
/// rejects it.
const SIDECAR_MEMBERS: [&str; 4] = ["genesisDocument", "updates", "casUpdates", "smtProofs"];

/// Parse the query string into the core's typed options. Accepted:
/// `versionId` (a string of decimal digits, no sign, no point; positive),
/// `versionTime` (RFC 3339, normalised to UTC), `minConf` (a string of
/// decimal digits, no sign, no point; positive) — `versionId` and
/// `versionTime` not together — and `noCache=false`, the default, which sets
/// nothing. `noCache=true` and `expandRelativeUrls` are declined as
/// unsupported features; a `noCache` value other than `true`/`false` is
/// invalid, as is any other name, including `accept` (header-only in the
/// HTTP binding). The integer grammar is the body form's `digits_to_u64`,
/// so `+2`, `-1`, `1.0` and ` 1` are rejected in both forms alike.
pub fn parse_options(query: Option<&str>) -> Result<ResolutionOptions, OptionsError> {
    let Some(query) = query.filter(|s| !s.is_empty()) else {
        return Ok(ResolutionOptions::default());
    };
    let mut seen = HashSet::new();
    let mut opts = ResolutionOptions::default();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode(raw_key).map_err(|_| {
            invalid(format!(
                "parameter `{}` is not valid percent-encoding",
                shown(raw_key)
            ))
        })?;
        let value = percent_decode(raw_value).map_err(|_| {
            invalid(format!(
                "the value of parameter `{}` is not valid percent-encoding",
                shown(&key)
            ))
        })?;
        if !seen.insert(key.clone()) {
            return Err(invalid(format!(
                "parameter `{}` is given more than once",
                shown(&key)
            )));
        }
        match key.as_str() {
            "versionId" => {
                opts.version_id = Some(
                    digits_to_u64(&value)
                        .and_then(NonZeroU64::new)
                        .ok_or_else(|| {
                            invalid(format!(
                                "versionId must be a positive integer, got `{value}`"
                            ))
                        })?,
                );
            }
            "versionTime" => {
                opts.version_time = Some(
                    chrono::DateTime::parse_from_rfc3339(&value)
                        .map(|t| t.with_timezone(&chrono::Utc))
                        .map_err(|_| {
                            invalid(format!(
                                "versionTime must be an RFC 3339 timestamp, got `{value}`"
                            ))
                        })?,
                );
            }
            "minConf" => {
                opts.min_conf = Some(
                    digits_to_u64(&value)
                        .and_then(|n| u32::try_from(n).ok())
                        .and_then(NonZeroU32::new)
                        .ok_or_else(|| {
                            invalid(format!("minConf must be a positive integer, got `{value}`"))
                        })?,
                );
            }
            "noCache" => match value.as_str() {
                // The spec's default: caching is allowed. Nothing to set.
                "false" => {}
                "true" => {
                    return Err(OptionsError::Unsupported(Problem::FeatureNotSupported(
                        "bypassing the response cache (noCache=true) is not supported by this resolver"
                            .to_string(),
                    )));
                }
                other => {
                    return Err(invalid(format!(
                        "noCache must be `true` or `false`, got `{other}`"
                    )));
                }
            },
            "expandRelativeUrls" => {
                return Err(OptionsError::Unsupported(Problem::FeatureNotSupported(
                    format!("resolution option `{key}` is not supported by this resolver"),
                )));
            }
            "accept" => {
                return Err(invalid(
                    "`accept` is supplied in the Accept header, not as a query parameter"
                        .to_string(),
                ));
            }
            _ => {
                return Err(invalid(format!(
                    "unknown resolution option `{}`",
                    shown(&key)
                )));
            }
        }
    }
    if opts.version_id.is_some() && opts.version_time.is_some() {
        // Word for word the core's `Resolver::new` detail, which stays as the
        // backstop for callers that bypass this binding.
        return Err(invalid(
            "versionId and versionTime are mutually exclusive; supply at most one".to_string(),
        ));
    }
    Ok(opts)
}

/// A request body as serde_json read it, before duplicates collapse: the
/// members of an object in document order, every occurrence kept; or not an
/// object at all.
enum Body {
    Object(Vec<(String, Value)>),
    Other,
}

impl<'de> Deserialize<'de> for Body {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BodyVisitor;

        impl<'de> Visitor<'de> for BodyVisitor {
            type Value = Body;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a JSON value")
            }

            fn visit_bool<E: de::Error>(self, _: bool) -> Result<Body, E> {
                Ok(Body::Other)
            }

            fn visit_i64<E: de::Error>(self, _: i64) -> Result<Body, E> {
                Ok(Body::Other)
            }

            fn visit_u64<E: de::Error>(self, _: u64) -> Result<Body, E> {
                Ok(Body::Other)
            }

            fn visit_f64<E: de::Error>(self, _: f64) -> Result<Body, E> {
                Ok(Body::Other)
            }

            fn visit_str<E: de::Error>(self, _: &str) -> Result<Body, E> {
                Ok(Body::Other)
            }

            fn visit_unit<E: de::Error>(self) -> Result<Body, E> {
                Ok(Body::Other)
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Body, A::Error> {
                // Drain it: serde_json expects the closing bracket after the
                // visitor returns, and a truncated array must still surface
                // as the syntax error it is.
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(Body::Other)
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Body, A::Error> {
                let mut members = Vec::new();
                while let Some(key) = map.next_key::<String>()? {
                    members.push((key, map.next_value::<Value>()?));
                }
                Ok(Body::Object(members))
            }
        }

        deserializer.deserialize_any(BodyVisitor)
    }
}

/// What a `POST` body yielded: the options, and what the log line reports
/// about the sidecar it carried.
#[derive(Debug)]
pub struct BodyOptions {
    /// The typed options, `sidecar_data` set when the body carried `sidecar`.
    pub opts: ResolutionOptions,
    /// `Some(n)` when the body carried a `sidecar` member: the length of its
    /// `updates` array, `0` when that key is absent or empty. `None` when the
    /// body carried no `sidecar`.
    pub sidecar_updates: Option<usize>,
}

/// Parse a `POST` body — the DID Resolution §12.1 form: every option except
/// `accept` as a member of one JSON object — into the core's options. The same
/// names and rejections as [`parse_options`], plus the method option `sidecar`,
/// whose value is spec-form sidecar data. `versionId` and `minConf` are taken
/// as a JSON number or as a string of decimal digits (the query form and the
/// spec's example body are string-valued; a client that mirrors either must
/// not be turned away); `versionTime` is a string, `noCache` a boolean.
///
/// An empty or all-whitespace body is `{}`: every option unset. A member
/// given more than once is rejected, as in the query form; the members are
/// read in document order and checked before any is interpreted, so the
/// detail names the duplicate whatever else the body carries. Inside
/// `sidecar` a repeated member takes the last occurrence (see the module
/// doc).
pub fn parse_body_options(body: &[u8]) -> Result<BodyOptions, OptionsError> {
    let mut opts = ResolutionOptions::default();
    let mut sidecar_updates = None;
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(BodyOptions {
            opts,
            sidecar_updates,
        });
    }
    let members = match serde_json::from_slice::<Body>(body) {
        Ok(Body::Object(members)) => members,
        Ok(Body::Other) => {
            return Err(invalid(
                "the request body must be a JSON object of resolution options".to_string(),
            ));
        }
        Err(e) => return Err(invalid(format!("the request body is not valid JSON: {e}"))),
    };
    // Before any member is interpreted, so the detail names the duplicate
    // whatever else the body carries. Linear: a body at the limit can hold
    // ~10^5 members, so no pairwise scan.
    let mut seen = HashSet::new();
    if let Some((key, _)) = members.iter().find(|(key, _)| !seen.insert(key.as_str())) {
        return Err(invalid(format!(
            "member `{}` is given more than once",
            shown(key)
        )));
    }
    for (key, value) in members {
        match key.as_str() {
            "versionId" => {
                opts.version_id = Some(
                    positive_integer(&value)
                        .and_then(NonZeroU64::new)
                        .ok_or_else(|| {
                            invalid(
                                "versionId must be a positive integer, as a JSON number or a string of decimal digits"
                                    .to_string(),
                            )
                        })?,
                );
            }
            "versionTime" => {
                opts.version_time = Some(
                    value
                        .as_str()
                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                        .map(|t| t.with_timezone(&chrono::Utc))
                        .ok_or_else(|| {
                            invalid(
                                "versionTime must be an RFC 3339 timestamp JSON string".to_string(),
                            )
                        })?,
                );
            }
            "minConf" => {
                opts.min_conf = Some(
                    positive_integer(&value)
                        .and_then(|n| u32::try_from(n).ok())
                        .and_then(NonZeroU32::new)
                        .ok_or_else(|| {
                            invalid(
                                "minConf must be a positive integer, as a JSON number or a string of decimal digits"
                                    .to_string(),
                            )
                        })?,
                );
            }
            "noCache" => match value {
                // The spec's default: caching is allowed. Nothing to set.
                Value::Bool(false) => {}
                Value::Bool(true) => {
                    return Err(OptionsError::Unsupported(Problem::FeatureNotSupported(
                        "bypassing the response cache (noCache=true) is not supported by this resolver"
                            .to_string(),
                    )));
                }
                _ => {
                    return Err(invalid(
                        "noCache must be the JSON boolean `true` or `false`".to_string(),
                    ));
                }
            },
            "expandRelativeUrls" => {
                return Err(OptionsError::Unsupported(Problem::FeatureNotSupported(
                    format!("resolution option `{key}` is not supported by this resolver"),
                )));
            }
            "accept" => {
                return Err(invalid(
                    "`accept` is supplied in the Accept header, not in the request body"
                        .to_string(),
                ));
            }
            "sidecar" => {
                // The core's wire type tolerates unknown members (every one
                // is optional, none is denied), so the binding applies the
                // module's rule itself: a mis-keyed `update` or `Updates`
                // would otherwise parse as an empty sidecar and the anchored
                // DID would fail on the chain, not on the typo.
                if let Some(unknown) = value
                    .as_object()
                    .and_then(|o| o.keys().find(|k| !SIDECAR_MEMBERS.contains(&k.as_str())))
                {
                    return Err(invalid(format!(
                        "unknown sidecar member `{}`",
                        shown(unknown)
                    )));
                }
                // The count is taken from the raw JSON: the core's `updates`
                // is not public, and its deserialiser fails the whole parse
                // on any bad element, so on success the raw length is the
                // typed length.
                let n = value
                    .get("updates")
                    .and_then(Value::as_array)
                    .map(Vec::len)
                    .unwrap_or(0);
                // The serde error is dropped, not interpolated: for a type
                // mismatch it renders the offending value, which would echo
                // arbitrary client text (up to the body limit) into the
                // detail. The body form names a rejected member but never
                // echoes a rejected value.
                let sidecar = SidecarData::from_json_value(value)
                    .map_err(|_| invalid("sidecar does not parse as sidecar data".to_string()))?;
                opts.sidecar_data = Some(sidecar);
                sidecar_updates = Some(n);
            }
            _ => {
                return Err(invalid(format!(
                    "unknown resolution option `{}`",
                    shown(&key)
                )));
            }
        }
    }
    if opts.version_id.is_some() && opts.version_time.is_some() {
        return Err(invalid(
            "versionId and versionTime are mutually exclusive; supply at most one".to_string(),
        ));
    }
    Ok(BodyOptions {
        opts,
        sidecar_updates,
    })
}

/// A string of ASCII decimal digits as a number: `None` for the empty string,
/// a sign, a point, whitespace, or a value past `u64::MAX`.
fn digits_to_u64(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// `versionId` / `minConf` value forms: a JSON number, or a JSON string of decimal digits.
fn positive_integer(value: &Value) -> Option<u64> {
    match value {
        Value::Number(_) => value.as_u64(),
        Value::String(s) => digits_to_u64(s),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    const INVALID_OPTIONS: &str = "https://www.w3.org/ns/did#INVALID_OPTIONS";
    const FEATURE_NOT_SUPPORTED: &str = "https://www.w3.org/ns/did#FEATURE_NOT_SUPPORTED";

    fn assert_all_unset(opts: &ResolutionOptions) {
        assert!(opts.accept.is_none());
        assert!(opts.version_id.is_none());
        assert!(opts.version_time.is_none());
        assert!(opts.min_conf.is_none());
        assert!(opts.sidecar_data.is_none());
        assert!(opts.chain_tip_height.is_none());
        assert!(opts.esplora_url.is_none());
        assert!(!opts.expand_relative_urls);
    }

    /// The failure's RFC 9457 `type` and the substring its `detail` must name.
    fn assert_rejected(query: &str, type_uri: &str, names: &str) {
        let err = parse_options(Some(query))
            .err()
            .unwrap_or_else(|| panic!("`{query}` must be rejected"));
        let details = err.details();
        assert_eq!(details["type"], type_uri, "{query}");
        let detail = details["detail"].as_str().expect("detail is a string");
        assert!(
            detail.contains(names),
            "{query}: detail `{detail}` lacks `{names}`"
        );
        assert!(
            details["title"].as_str().is_some_and(|t| !t.is_empty()),
            "{query}"
        );
    }

    /// The twin of `assert_rejected` over the body form.
    fn assert_body_rejected(body: &str, type_uri: &str, names: &str) {
        let err = parse_body_options(body.as_bytes())
            .err()
            .unwrap_or_else(|| panic!("`{body}` must be rejected"));
        let details = err.details();
        assert_eq!(details["type"], type_uri, "{body}");
        let detail = details["detail"].as_str().expect("detail is a string");
        assert!(
            detail.contains(names),
            "{body}: detail `{detail}` lacks `{names}`"
        );
        assert!(
            details["title"].as_str().is_some_and(|t| !t.is_empty()),
            "{body}"
        );
    }

    #[test]
    fn parse_options_rows() {
        assert_all_unset(&parse_options(None).expect("no query"));
        assert_all_unset(&parse_options(Some("")).expect("empty query"));

        let opts = parse_options(Some("versionId=3")).expect("versionId");
        assert_eq!(opts.version_id.map(NonZeroU64::get), Some(3));
        assert!(opts.version_time.is_none());
        assert!(opts.min_conf.is_none());

        let opts = parse_options(Some("minConf=1")).expect("minConf");
        assert_eq!(opts.min_conf.map(NonZeroU32::get), Some(1));
        assert!(opts.version_id.is_none());

        // The full u32 range, and leading zeros are digits — as the body
        // form already asserts.
        let opts = parse_options(Some("minConf=4294967295")).expect("u32::MAX");
        assert_eq!(opts.min_conf.map(NonZeroU32::get), Some(u32::MAX));
        let opts = parse_options(Some("versionId=007")).expect("leading zeros");
        assert_eq!(opts.version_id.map(NonZeroU64::get), Some(7));

        let opts = parse_options(Some("versionTime=2026-01-02T03:04:05Z")).expect("versionTime");
        assert_eq!(
            opts.version_time,
            Some(Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap())
        );

        // The pair is rejected here, in either order, before the resolver
        // runs — with the detail the core's `Resolver::new` uses, so a caller
        // sees one message whichever check fires.
        for query in [
            "versionId=1&versionTime=2026-01-02T03:04:05Z",
            "versionTime=2026-01-02T03:04:05Z&versionId=1",
            "versionId=1&minConf=1&versionTime=2026-01-02T03:04:05Z",
        ] {
            assert_rejected(query, INVALID_OPTIONS, "versionId");
            assert_rejected(query, INVALID_OPTIONS, "versionTime");
            let err = parse_options(Some(query)).expect_err("rejected");
            assert_eq!(
                err.details()["detail"],
                "versionId and versionTime are mutually exclusive; supply at most one",
                "{query}"
            );
        }

        let opts = parse_options(Some("&versionId=2&")).expect("empty pairs are skipped");
        assert_eq!(opts.version_id.map(NonZeroU64::get), Some(2));

        // INVALID_OPTIONS, each naming the offending parameter.
        for (query, names) in [
            ("versionId=abc", "versionId"),
            ("versionId=0", "versionId"),
            ("versionId=-1", "versionId"),
            ("versionId=", "versionId"),
            ("versionId", "versionId"),
            ("minConf=0", "minConf"),
            ("minConf=six", "minConf"),
            // A sign is not a digit: the query form and the body form reject
            // the same strings.
            ("versionId=+1", "versionId"),
            ("versionId=%2B1", "versionId"),
            ("minConf=+1", "minConf"),
            ("versionId=18446744073709551616", "versionId"),
            ("minConf=4294967296", "minConf"),
            ("versionId= 1", "versionId"),
            ("versionTime=yesterday", "versionTime"),
            ("versionTime=2026-01-02", "versionTime"),
            ("foo=1", "foo"),
            ("accept=application/did", "accept"),
            ("versionId=1&versionId=2", "versionId"),
            ("versionId=%zz", "versionId"),
            ("ver%zz=1", "ver%zz"),
            ("VersionId=1", "VersionId"),
            ("versionId=1&versionTime=2026-01-02T03:04:05Z", "versionId"),
        ] {
            assert_rejected(query, INVALID_OPTIONS, names);
        }

        // FEATURE_NOT_SUPPORTED for the registered-but-unimplemented pair:
        // `noCache` only when it asks for the bypass; `expandRelativeUrls`
        // for any value.
        for (query, names) in [
            ("noCache=true", "noCache"),
            ("expandRelativeUrls=true", "expandRelativeUrls"),
            ("expandRelativeUrls=false", "expandRelativeUrls"),
            ("expandRelativeUrls", "expandRelativeUrls"),
        ] {
            assert_rejected(query, FEATURE_NOT_SUPPORTED, names);
        }

        // A parameter name is echoed, but cut, as in the body form: the
        // unknown arm and the two percent-encoding failures. (The duplicate
        // arm can only name a known parameter here: pairs are interpreted in
        // order, so an unknown name is rejected at its first occurrence.)
        let long = "x".repeat(4096);
        let cut = format!("{}…", "x".repeat(64));
        for (query, expected) in [
            (
                format!("{long}=1"),
                format!("unknown resolution option `{cut}`"),
            ),
            (
                format!("{long}%zz=1"),
                format!("parameter `{cut}` is not valid percent-encoding"),
            ),
            (
                format!("{long}=%zz"),
                format!("the value of parameter `{cut}` is not valid percent-encoding"),
            ),
        ] {
            let err = parse_options(Some(&query)).expect_err("rejected");
            let details = err.details();
            assert_eq!(details["detail"], expected, "{query:.80}");
            let body = serde_json::to_vec(&details).expect("serialises");
            assert!(
                body.len() < 256 && body.len() < query.len() / 10,
                "the error body ({} bytes) does not grow with the query ({} bytes)",
                body.len(),
                query.len()
            );
        }
    }

    #[test]
    fn shown_cuts_at_sixty_four_characters() {
        assert_eq!(shown(""), "");
        assert_eq!(shown("versionId"), "versionId");
        let exact = "a".repeat(64);
        assert_eq!(shown(&exact), exact);
        assert_eq!(shown(&"a".repeat(65)), format!("{exact}…"));
        assert_eq!(shown(&"a".repeat(1 << 20)), format!("{exact}…"));
        // Characters, not bytes: a two-byte character counts once and is never
        // split.
        let accented = "é".repeat(64);
        assert_eq!(shown(&accented), accented);
        assert_eq!(shown(&"é".repeat(65)), format!("{accented}…"));
    }

    /// `noCache` has three answers: `false` (the spec default) is accepted
    /// and sets nothing, `true` is the unsupported bypass, anything else is a
    /// malformed value — `INVALID_OPTIONS`, as for `versionId=abc`.
    #[test]
    fn no_cache_false_is_accepted_true_is_unsupported_and_anything_else_is_invalid() {
        assert_all_unset(&parse_options(Some("noCache=false")).expect("the default is accepted"));
        let opts = parse_options(Some("versionId=3&noCache=false&minConf=2"))
            .expect("noCache=false beside real options");
        assert_eq!(opts.version_id.map(NonZeroU64::get), Some(3));
        assert_eq!(opts.min_conf.map(NonZeroU32::get), Some(2));

        assert_rejected("noCache=true", FEATURE_NOT_SUPPORTED, "noCache");
        assert_rejected("versionId=3&noCache=true", FEATURE_NOT_SUPPORTED, "noCache");

        for query in [
            "noCache=1",
            "noCache=0",
            "noCache=",
            "noCache",
            "noCache=True",
            "noCache=FALSE",
            "noCache=yes",
            "noCache=false&noCache=false",
        ] {
            assert_rejected(query, INVALID_OPTIONS, "noCache");
        }
        // Duplicates are rejected as duplicates, not on the value.
        assert_rejected(
            "noCache=false&noCache=false",
            INVALID_OPTIONS,
            "more than once",
        );
    }

    #[test]
    fn offset_timestamps_normalise_to_utc() {
        let opts = parse_options(Some("versionTime=2026-01-02T03:04:05%2B02:00"))
            .expect("an RFC 3339 offset is accepted");
        assert_eq!(
            opts.version_time,
            Some(Utc.with_ymd_and_hms(2026, 1, 2, 1, 4, 5).unwrap())
        );
        let opts = parse_options(Some("versionTime=2026-01-02T03:04:05-05:00"))
            .expect("a negative offset needs no escaping");
        assert_eq!(
            opts.version_time,
            Some(Utc.with_ymd_and_hms(2026, 1, 2, 8, 4, 5).unwrap())
        );
    }

    #[test]
    fn options_error_variants_carry_their_problem() {
        let invalid = parse_options(Some("foo=1")).expect_err("rejected");
        assert!(matches!(invalid, OptionsError::Invalid(_)), "{invalid:?}");
        let unsupported = parse_options(Some("noCache=true")).expect_err("rejected");
        assert!(
            matches!(unsupported, OptionsError::Unsupported(_)),
            "{unsupported:?}"
        );
        // A malformed `noCache` value is a malformed option, not a feature.
        let malformed = parse_options(Some("noCache=1")).expect_err("rejected");
        assert!(
            matches!(malformed, OptionsError::Invalid(_)),
            "{malformed:?}"
        );
    }

    fn body(body: &str) -> BodyOptions {
        parse_body_options(body.as_bytes()).unwrap_or_else(|e| panic!("`{body}`: {e:?}"))
    }

    #[test]
    fn parse_body_options_rows() {
        for empty in ["", "   \n", "{}"] {
            let parsed = body(empty);
            assert_all_unset(&parsed.opts);
            assert_eq!(parsed.sidecar_updates, None, "{empty:?}");
        }

        // Accepted: a JSON number or a string of decimal digits.
        assert_eq!(
            body(r#"{"versionId": 3}"#)
                .opts
                .version_id
                .map(NonZeroU64::get),
            Some(3)
        );
        assert_eq!(
            body(r#"{"versionId": "2"}"#)
                .opts
                .version_id
                .map(NonZeroU64::get),
            Some(2)
        );
        assert_eq!(
            body(r#"{"versionId": "007"}"#)
                .opts
                .version_id
                .map(NonZeroU64::get),
            Some(7),
            "leading zeros are digits"
        );
        assert_eq!(
            body(r#"{"minConf": 2}"#).opts.min_conf.map(NonZeroU32::get),
            Some(2)
        );
        assert_eq!(
            body(r#"{"minConf": "6"}"#)
                .opts
                .min_conf
                .map(NonZeroU32::get),
            Some(6)
        );
        assert_eq!(
            body(r#"{"versionTime": "2026-01-02T03:04:05+02:00"}"#)
                .opts
                .version_time,
            Some(Utc.with_ymd_and_hms(2026, 1, 2, 1, 4, 5).unwrap())
        );
        let parsed = body(r#"{"noCache": false, "versionId": 1}"#);
        assert_eq!(parsed.opts.version_id.map(NonZeroU64::get), Some(1));
        assert_eq!(parsed.sidecar_updates, None);

        // A sidecar with no updates is a sidecar: `Some(0)`, not `None`.
        for empty_sidecar in [r#"{"sidecar": {}}"#, r#"{"sidecar": {"updates": []}}"#] {
            let parsed = body(empty_sidecar);
            assert!(parsed.opts.sidecar_data.is_some(), "{empty_sidecar}");
            assert_eq!(parsed.sidecar_updates, Some(0), "{empty_sidecar}");
        }
        // The duplicate check stops at the top level: a member repeated
        // inside `sidecar` takes the last occurrence (see the module doc).
        let nested = r#"{"sidecar": {"updates": [], "updates": []}}"#;
        let parsed = body(nested);
        assert!(parsed.opts.sidecar_data.is_some(), "{nested}");
        assert_eq!(parsed.sidecar_updates, Some(0), "{nested}");

        // A real sidecar: the update count is read from the fixture, never
        // hardcoded, so a re-capture of the file does not break the test.
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../fixtures/chain/minted/clean-rotating-beacons.json"
        ))
        .expect("the minted fixture is JSON");
        let updates = fixture["sidecar"]["updates"]
            .as_array()
            .expect("the fixture's sidecar has updates")
            .len();
        assert!(updates >= 3, "the clean scenario carries several updates");
        let wrapped =
            serde_json::to_vec(&json!({"sidecar": fixture["sidecar"]})).expect("serialises");
        let parsed = parse_body_options(&wrapped).expect("the fixture's sidecar parses");
        assert!(parsed.opts.sidecar_data.is_some());
        assert_eq!(parsed.sidecar_updates, Some(updates));
        assert_all_unset(&ResolutionOptions {
            sidecar_data: None,
            ..parsed.opts
        });

        // INVALID_OPTIONS, each naming the offending member (or the shape).
        for (body, names) in [
            ("[]", "JSON object"),
            ("\"x\"", "JSON object"),
            ("42", "JSON object"),
            ("null", "JSON object"),
            ("{", "valid JSON"),
            ("[1, 2", "valid JSON"),
            // A repeated member is rejected as a duplicate, before the value
            // is looked at.
            ("{\"versionId\": 1, \"versionId\": 2}", "versionId"),
            ("{\"versionId\": 1, \"versionId\": 2}", "more than once"),
            (
                "{\"versionId\": \"abc\", \"versionId\": 1}",
                "more than once",
            ),
            ("{\"sidecar\": {}, \"sidecar\": {}}", "sidecar"),
            ("{\"sidecar\": {}, \"sidecar\": {}}", "more than once"),
            ("{\"foo\": 1, \"foo\": 2}", "more than once"),
            ("{\"versionId\": 0}", "versionId"),
            ("{\"versionId\": -1}", "versionId"),
            ("{\"versionId\": 1.5}", "versionId"),
            ("{\"versionId\": \"0\"}", "versionId"),
            ("{\"versionId\": \"-1\"}", "versionId"),
            ("{\"versionId\": \"1.5\"}", "versionId"),
            ("{\"versionId\": \"abc\"}", "versionId"),
            ("{\"versionId\": \"\"}", "versionId"),
            ("{\"versionId\": \" 2\"}", "versionId"),
            ("{\"versionId\": \"+2\"}", "versionId"),
            ("{\"versionId\": \"99999999999999999999\"}", "versionId"),
            ("{\"versionId\": true}", "versionId"),
            ("{\"versionId\": null}", "versionId"),
            ("{\"minConf\": 0}", "minConf"),
            ("{\"minConf\": \"0\"}", "minConf"),
            ("{\"minConf\": \"x\"}", "minConf"),
            ("{\"minConf\": 4294967296}", "minConf"),
            ("{\"minConf\": \"4294967296\"}", "minConf"),
            ("{\"versionTime\": \"yesterday\"}", "versionTime"),
            ("{\"versionTime\": 5}", "versionTime"),
            ("{\"noCache\": \"true\"}", "noCache"),
            ("{\"noCache\": 1}", "noCache"),
            ("{\"accept\": \"application/did\"}", "accept"),
            ("{\"foo\": 1}", "foo"),
            ("{\"VersionId\": 1}", "VersionId"),
            ("{\"sidecar\": 7}", "sidecar"),
            ("{\"sidecar\": \"x\"}", "sidecar"),
            (
                "{\"sidecar\": {\"updates\": [{\"not\": \"an update\"}]}}",
                "sidecar",
            ),
            ("{\"sidecar\": {\"updates\": 3}}", "sidecar"),
            // A mis-keyed sidecar member is rejected by name, not parsed as
            // an empty sidecar.
            ("{\"sidecar\": {\"update\": []}}", "update"),
            ("{\"sidecar\": {\"Updates\": []}}", "Updates"),
            ("{\"sidecar\": {\"updates\": [], \"extra\": 1}}", "extra"),
            (
                "{\"versionId\": 1, \"versionTime\": \"2026-01-02T03:04:05Z\"}",
                "versionId",
            ),
        ] {
            assert_body_rejected(body, INVALID_OPTIONS, names);
        }

        // Every wire member the core reads is accepted by name — the reject
        // list above is the complement of exactly this set.
        let parsed = body(
            r#"{"sidecar": {"genesisDocument": null, "updates": [], "casUpdates": null, "smtProofs": null}}"#,
        );
        assert!(parsed.opts.sidecar_data.is_some());
        assert_eq!(parsed.sidecar_updates, Some(0));

        // The pair's detail is the core's, byte for byte.
        let err = parse_body_options(br#"{"versionId": 1, "versionTime": "2026-01-02T03:04:05Z"}"#)
            .expect_err("rejected");
        assert_eq!(
            err.details()["detail"],
            "versionId and versionTime are mutually exclusive; supply at most one"
        );
        // The value is not echoed: the body form's detail names the member,
        // never the client's value — for a scalar, and for a sidecar whose
        // serde error would render the offending value.
        let err = parse_body_options(br#"{"versionId": "abc"}"#).expect_err("rejected");
        assert_eq!(
            err.details()["detail"],
            "versionId must be a positive integer, as a JSON number or a string of decimal digits"
        );
        let marker = "MARKER-".repeat(64);
        let err =
            parse_body_options(format!(r#"{{"sidecar": {{"updates": "{marker}"}}}}"#).as_bytes())
                .expect_err("rejected");
        assert_eq!(
            err.details()["detail"],
            "sidecar does not parse as sidecar data"
        );
        // A member name is echoed, but cut: the detail of a body whose only
        // content is a long name is a fraction of the body, in every arm that
        // names a member — unknown option, unknown sidecar member, duplicate.
        let long = "x".repeat(200_000);
        let cut = format!("{}…", "x".repeat(64));
        for (payload, expected) in [
            (
                format!(r#"{{"{long}": 1}}"#),
                format!("unknown resolution option `{cut}`"),
            ),
            (
                format!(r#"{{"sidecar": {{"{long}": 1}}}}"#),
                format!("unknown sidecar member `{cut}`"),
            ),
            (
                format!(r#"{{"{long}": 1, "{long}": 2}}"#),
                format!("member `{cut}` is given more than once"),
            ),
        ] {
            let err = parse_body_options(payload.as_bytes()).expect_err("rejected");
            let details = err.details();
            assert_eq!(details["detail"], expected);
            let body = serde_json::to_vec(&details).expect("serialises");
            assert!(
                body.len() < 256 && body.len() < payload.len() / 100,
                "the error body ({} bytes) does not grow with the request ({} bytes)",
                body.len(),
                payload.len()
            );
        }
        // A name of exactly the cut is shown whole; the cut is in characters.
        let exact = "y".repeat(64);
        let err =
            parse_body_options(format!(r#"{{"{exact}": 1}}"#).as_bytes()).expect_err("rejected");
        assert_eq!(
            err.details()["detail"],
            format!("unknown resolution option `{exact}`")
        );
        let accented = "é".repeat(65);
        let err =
            parse_body_options(format!(r#"{{"{accented}": 1}}"#).as_bytes()).expect_err("rejected");
        assert_eq!(
            err.details()["detail"],
            format!("unknown resolution option `{}…`", "é".repeat(64))
        );

        // FEATURE_NOT_SUPPORTED for the registered-but-unimplemented pair.
        for (body, names) in [
            ("{\"noCache\": true}", "noCache"),
            ("{\"expandRelativeUrls\": true}", "expandRelativeUrls"),
            ("{\"expandRelativeUrls\": false}", "expandRelativeUrls"),
            ("{\"expandRelativeUrls\": null}", "expandRelativeUrls"),
        ] {
            assert_body_rejected(body, FEATURE_NOT_SUPPORTED, names);
        }

        // The duplicate detail is the bare sentence: the check runs outside
        // serde's error channel, so no ` at line N column M` suffix.
        let err = parse_body_options(br#"{"minConf": 1, "minConf": 1}"#).expect_err("rejected");
        assert_eq!(
            err.details()["detail"],
            "member `minConf` is given more than once"
        );

        let invalid = parse_body_options(b"{\"foo\":1}").expect_err("rejected");
        assert!(matches!(invalid, OptionsError::Invalid(_)), "{invalid:?}");
        let unsupported = parse_body_options(b"{\"noCache\": true}").expect_err("rejected");
        assert!(
            matches!(unsupported, OptionsError::Unsupported(_)),
            "{unsupported:?}"
        );
    }

    #[test]
    fn digits_to_u64_rows() {
        assert_eq!(digits_to_u64("2"), Some(2));
        assert_eq!(digits_to_u64("007"), Some(7));
        assert_eq!(digits_to_u64("18446744073709551615"), Some(u64::MAX));
        assert_eq!(digits_to_u64("18446744073709551616"), None);
        for rejected in ["", "-1", "+1", "1.0", " 1", "1 ", "\u{ff11}"] {
            assert_eq!(digits_to_u64(rejected), None, "{rejected:?}");
        }
    }
}
