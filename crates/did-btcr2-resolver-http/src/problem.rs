//! Binding-originated errors, the error-type -> HTTP-status table, and the
//! RFC 9457 resolution-result envelope. The status is a function of the
//! emitted `type` URI only: the binding never inspects a core error variant,
//! so a change to the core's vocabulary needs no change here.

use did_btcr2::error::ProblemDetails;
use onlyerror::Error;
use serde_json::{Value, json};

use crate::Response;

/// Errors the binding itself raises (the core raises `INVALID_DID`,
/// `INVALID_OPTIONS`, `METHOD_NOT_SUPPORTED`, `NOT_FOUND` and its own
/// method-specific set). Fixed title per type; the occurrence goes in the detail.
#[derive(Debug, Error)]
pub enum Problem {
    /// `FEATURE_NOT_SUPPORTED`: DID URL dereferencing, an unimplemented
    /// registered option, or a network with no configured endpoint.
    #[error("A requested feature is not supported by this resolver: {0}")]
    FeatureNotSupported(String),
    /// `REPRESENTATION_NOT_SUPPORTED`: no `Accept` entry names a supported media type.
    #[error("The requested DID document representation is not supported: {0}")]
    RepresentationNotSupported(String),
    /// `INTERNAL_ERROR`: a backend or resolver failure; the detail is a
    /// category only — never a URL, a response body or an error chain.
    #[error("An internal error occurred during DID Resolution: {0}")]
    InternalError(String),
}

impl Problem {
    /// Fixed, per-type title (RFC 9457 `title`).
    pub fn title(&self) -> &'static str {
        match self {
            Self::FeatureNotSupported(_) => "A requested feature is not supported by this resolver",
            Self::RepresentationNotSupported(_) => {
                "The requested DID document representation is not supported"
            }
            Self::InternalError(_) => "An internal error occurred during DID Resolution",
        }
    }

    /// The W3C error identifier URI (RFC 9457 `type`).
    pub fn type_uri(&self) -> &'static str {
        match self {
            Self::FeatureNotSupported(_) => "https://www.w3.org/ns/did#FEATURE_NOT_SUPPORTED",
            Self::RepresentationNotSupported(_) => {
                "https://www.w3.org/ns/did#REPRESENTATION_NOT_SUPPORTED"
            }
            Self::InternalError(_) => "https://www.w3.org/ns/did#INTERNAL_ERROR",
        }
    }
}

impl ProblemDetails for Problem {
    fn details(&self) -> Option<Value> {
        let detail = match self {
            Self::FeatureNotSupported(d)
            | Self::RepresentationNotSupported(d)
            | Self::InternalError(d) => d.clone(),
        };
        Some(json!({ "type": self.type_uri(), "title": self.title(), "detail": detail }))
    }
}

/// The `Content-Type` of every resolution-result body: full results, every
/// error, and the 410. A bare document carries its own negotiated type instead.
pub const RESOLUTION_RESULT: &str = "application/did-resolution";

/// DID Resolution §12.1: HTTP status for an error `type` URI. Anything not in
/// the table — including every method-specific `https://btcr2.dev/…` type —
/// is a 500, with the URI kept verbatim in the body.
pub fn status_for(type_uri: &str) -> u16 {
    match type_uri {
        "https://www.w3.org/ns/did#INVALID_DID"
        | "https://www.w3.org/ns/did#INVALID_DID_URL"
        | "https://www.w3.org/ns/did#INVALID_OPTIONS" => 400,
        "https://www.w3.org/ns/did#NOT_FOUND" => 404,
        "https://www.w3.org/ns/did#REPRESENTATION_NOT_SUPPORTED" => 406,
        "https://www.w3.org/ns/did#METHOD_NOT_SUPPORTED"
        | "https://www.w3.org/ns/did#FEATURE_NOT_SUPPORTED" => 501,
        _ => 500,
    }
}

/// The resolution result for a failed resolution: `didDocument` is JSON
/// `null` and present (the suite asserts the key), `didDocumentMetadata` is `{}`.
pub fn error_body(details: &Value) -> Value {
    json!({
        "didResolutionMetadata": { "error": details },
        "didDocument": Value::Null,
        "didDocumentMetadata": {},
    })
}

/// Build the complete error response from an RFC 9457 object: status from
/// its `type`, `Content-Type: application/did-resolution`, the envelope as
/// the body, and the operator-only diagnostic (stderr, never the wire).
pub fn problem_response(details: Value, diagnostic: Option<String>) -> Response {
    let status = status_for(details["type"].as_str().unwrap_or(""));
    Response {
        status,
        headers: vec![("Content-Type", RESOLUTION_RESULT.to_string())],
        body: serde_json::to_vec(&error_body(&details)).expect("a JSON value serialises"),
        diagnostic,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use did_btcr2::error::Btcr2Error;

    #[test]
    fn status_table_rows() {
        let rows: &[(&str, u16)] = &[
            ("https://www.w3.org/ns/did#INVALID_DID", 400),
            ("https://www.w3.org/ns/did#INVALID_DID_URL", 400),
            ("https://www.w3.org/ns/did#INVALID_OPTIONS", 400),
            ("https://www.w3.org/ns/did#NOT_FOUND", 404),
            (
                "https://www.w3.org/ns/did#REPRESENTATION_NOT_SUPPORTED",
                406,
            ),
            ("https://www.w3.org/ns/did#METHOD_NOT_SUPPORTED", 501),
            ("https://www.w3.org/ns/did#FEATURE_NOT_SUPPORTED", 501),
            ("https://www.w3.org/ns/did#INVALID_DID_DOCUMENT", 500),
            ("https://www.w3.org/ns/did#INTERNAL_ERROR", 500),
            ("https://btcr2.dev/context/v1#LATE_PUBLISHING_ERROR", 500),
            ("https://btcr2.dev/context/v1#INVALID_UPDATE_PROOF", 500),
            ("https://btcr2.dev/context/v1#INVALID_DID", 500),
            ("https://www.w3.org/ns/did#invalid_did", 500),
            ("", 500),
            ("not a uri", 500),
        ];
        for (uri, status) in rows {
            assert_eq!(status_for(uri), *status, "{uri}");
        }
    }

    #[test]
    fn binding_problem_details_shape() {
        let rows: [(Problem, &str, &str); 3] = [
            (
                Problem::FeatureNotSupported("x".into()),
                "https://www.w3.org/ns/did#FEATURE_NOT_SUPPORTED",
                "A requested feature is not supported by this resolver",
            ),
            (
                Problem::RepresentationNotSupported("x".into()),
                "https://www.w3.org/ns/did#REPRESENTATION_NOT_SUPPORTED",
                "The requested DID document representation is not supported",
            ),
            (
                Problem::InternalError("x".into()),
                "https://www.w3.org/ns/did#INTERNAL_ERROR",
                "An internal error occurred during DID Resolution",
            ),
        ];
        for (problem, type_uri, title) in rows {
            let details = problem.details().expect("binding problems carry details");
            assert_eq!(
                details,
                json!({ "type": type_uri, "title": title, "detail": "x" }),
                "{problem:?}"
            );
            assert_eq!(problem.title(), title);
            assert_eq!(problem.type_uri(), type_uri);
            assert_eq!(problem.to_string(), format!("{title}: x"));
        }
        assert_eq!(
            Problem::FeatureNotSupported("x".into()).to_string(),
            "A requested feature is not supported by this resolver: x"
        );
    }

    #[test]
    fn error_body_keeps_did_document_null_present() {
        let details = json!({ "type": "t", "title": "T", "detail": "d" });
        let body = error_body(&details);
        assert_eq!(
            body,
            json!({
                "didResolutionMetadata": { "error": details },
                "didDocument": null,
                "didDocumentMetadata": {}
            })
        );
        let text = serde_json::to_string(&body).unwrap();
        assert!(text.contains("\"didDocument\":null"), "{text}");
        assert!(text.contains("\"didDocumentMetadata\":{}"), "{text}");
    }

    #[test]
    fn problem_response_takes_status_from_type() {
        let details = Btcr2Error::NotFound("g".into())
            .details()
            .expect("core errors carry details");
        let response = problem_response(details.clone(), None);
        assert_eq!(
            response,
            Response {
                status: 404,
                headers: vec![("Content-Type", "application/did-resolution".to_string())],
                body: serde_json::to_vec(&error_body(&details)).unwrap(),
                diagnostic: None,
            }
        );

        let details = Problem::InternalError("the Bitcoin backend could not be reached".into())
            .details()
            .unwrap();
        let response = problem_response(details, Some("chain: connect ECONNREFUSED".into()));
        assert_eq!(response.status, 500);
        assert_eq!(
            response.headers,
            vec![("Content-Type", RESOLUTION_RESULT.to_string())]
        );
        assert_eq!(
            response.diagnostic.as_deref(),
            Some("chain: connect ECONNREFUSED")
        );
        let body = String::from_utf8(response.body).unwrap();
        assert!(!body.contains("ECONNREFUSED"), "{body}");
        assert!(
            body.contains("the Bitcoin backend could not be reached"),
            "{body}"
        );

        // A details object with no `type` is still a 500, never a panic.
        assert_eq!(problem_response(json!({}), None).status, 500);
    }
}
