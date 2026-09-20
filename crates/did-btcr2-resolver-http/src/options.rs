//! Query string -> resolution options.
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
//! `INVALID_OPTIONS`. `expandRelativeUrls` is not implemented for any value
//! and is `FEATURE_NOT_SUPPORTED` outright.
//!
//! Every other name is rejected, not ignored: a silently dropped `versionld`
//! (or an `accept`, which the HTTP binding carries in the header only) would
//! resolve the wrong version and report success. A duplicated name is rejected
//! for the same reason — there is no "last one wins" to get wrong.
//!
//! `versionId` and `versionTime` together are rejected here as well as in the
//! core's `Resolver::new`, with the same detail text. The core check comes
//! after the client has fetched the chain tip, so leaving the pair to it
//! would cost a wasted backend round-trip and, with the backend down, turn a
//! deterministic 400 `INVALID_OPTIONS` into a 500.

use std::collections::HashSet;
use std::num::{NonZeroU32, NonZeroU64};

use did_btcr2::document::ResolutionOptions;
use did_btcr2::error::{Btcr2Error, ProblemDetails};
use serde_json::Value;

use crate::path::percent_decode;
use crate::problem::Problem;

/// Why the query string was rejected: the caller turns it into a problem body.
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

/// Parse the query string into the core's typed options. Accepted:
/// `versionId` (positive integer), `versionTime` (RFC 3339, normalised to
/// UTC), `minConf` (positive integer) — `versionId` and `versionTime` not
/// together — and `noCache=false`, the default, which sets nothing.
/// `noCache=true` and `expandRelativeUrls` are declined as unsupported
/// features; a `noCache` value other than `true`/`false` is invalid, as is
/// any other name, including `accept` (header-only in the HTTP binding).
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
                "parameter `{raw_key}` is not valid percent-encoding"
            ))
        })?;
        let value = percent_decode(raw_value).map_err(|_| {
            invalid(format!(
                "the value of parameter `{key}` is not valid percent-encoding"
            ))
        })?;
        if !seen.insert(key.clone()) {
            return Err(invalid(format!(
                "parameter `{key}` is given more than once"
            )));
        }
        match key.as_str() {
            "versionId" => {
                opts.version_id = Some(value.parse::<NonZeroU64>().map_err(|_| {
                    invalid(format!(
                        "versionId must be a positive integer, got `{value}`"
                    ))
                })?);
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
                opts.min_conf = Some(value.parse::<NonZeroU32>().map_err(|_| {
                    invalid(format!("minConf must be a positive integer, got `{value}`"))
                })?);
            }
            "noCache" => match value.as_str() {
                // The spec's default: caching is allowed. Nothing to set.
                "false" => {}
                "true" => {
                    return Err(OptionsError::Unsupported(Problem::FeatureNotSupported(
                        "bypassing the response cache (noCache=true) is not permitted by this resolver"
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
            _ => return Err(invalid(format!("unknown resolution option `{key}`"))),
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

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
}
