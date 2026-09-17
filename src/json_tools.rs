use crate::identifier::{DidSyntax, Sha256Hash, parse_did_syntax};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use onlyerror::Error;
use serde_json::Value;
use std::fmt::Display;

#[derive(Error, Debug)]
pub enum JsonError {
    /// Error converting JSON Value to str
    #[error("Object key `{0}` was expected to be type `{1}`")]
    UnexpectedJsonType(String, ExpectedType),

    /// Missing object key
    #[error("Object key `{0}` does not exist")]
    JsonMissingKey(String),

    /// Invalid SHA256 hash
    #[error("Invalid SHA256 hash: {0}")]
    InvalidHash(String),

    /// Expected a JSON string
    ExpectedJsonStr,

    /// A `controller` entry that does not conform to DID syntax (DID Core 1.1
    /// §3.1: `did:` + a method name + `:` + a method-specific id).
    #[error("controller `{0}` does not conform to DID syntax")]
    InvalidControllerDid(String),

    /// Invalid Base58 encoding
    // retained pending a later error-vocabulary cleanup
    #[allow(dead_code)]
    Base58(#[from] esploda::bitcoin::base58::Error),

    /// Error with key operations
    Key(#[from] crate::key::Error),

    /// DID Encoding error
    DidEncoding(#[from] crate::identifier::Error),

    /// Document beacon endpoints error
    Beacon(#[from] crate::beacon::Error),

    /// This should not happen: Only needed to satisfy `String: FromStr` trait bound
    Infallible(#[from] std::convert::Infallible),
}

#[derive(Debug)]
pub enum ExpectedType {
    Number,
    String,
    Boolean,
    Array,
    Object,
    /// Either a JSON string or a JSON object — the two shapes a
    /// verification-relationship entry may take.
    StringOrObject,
    /// Either a JSON string or a JSON array of strings — the two shapes
    /// `controller` may take.
    StringOrArray,
}

impl Display for ExpectedType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExpectedType::Number => write!(f, "Number"),
            ExpectedType::String => write!(f, "String"),
            ExpectedType::Boolean => write!(f, "Boolean"),
            ExpectedType::Array => write!(f, "Array"),
            ExpectedType::Object => write!(f, "Object"),
            ExpectedType::StringOrObject => write!(f, "string or object"),
            ExpectedType::StringOrArray => write!(f, "string or array of strings"),
        }
    }
}

pub(crate) fn hash_from_object(value: &Value, key: &str) -> Result<Sha256Hash, JsonError> {
    let s = string_from_object(value, key)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| JsonError::InvalidHash(key.into()))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| JsonError::InvalidHash(key.into()))?;
    Ok(Sha256Hash::from(arr))
}

/// Returns value[key] as a str if it is a JSON string.
pub(crate) fn string_from_object<'value>(
    value: &'value Value,
    key: &str,
) -> Result<&'value str, JsonError> {
    optional_string_from_object(value, key)
        .map(|maybe_int| maybe_int.ok_or_else(|| JsonError::JsonMissingKey(key.into())))?
}

/// Returns value[key] as a str if it is a JSON string, or `None` if the key is missing.
pub(crate) fn optional_string_from_object<'value>(
    value: &'value Value,
    key: &str,
) -> Result<Option<&'value str>, JsonError> {
    let obj = &value[key];

    if obj.is_null() {
        Ok(None)
    } else {
        obj.as_str()
            .map(Option::Some)
            .ok_or_else(|| JsonError::UnexpectedJsonType(key.into(), ExpectedType::String))
    }
}

/// Returns value[key] as an int if it is a JSON number.
pub(crate) fn int_from_object(value: &Value, key: &str) -> Result<i64, JsonError> {
    optional_int_from_object(value, key)
        .map(|maybe_int| maybe_int.ok_or_else(|| JsonError::JsonMissingKey(key.into())))?
}

/// Returns value[key] as an int if it is a JSON number, or `None` if the key is missing.
pub(crate) fn optional_int_from_object(value: &Value, key: &str) -> Result<Option<i64>, JsonError> {
    let obj = &value[key];

    if obj.is_null() {
        Ok(None)
    } else {
        obj.as_i64()
            .map(Option::Some)
            .ok_or_else(|| JsonError::UnexpectedJsonType(key.into(), ExpectedType::Number))
    }
}

/// Create a vector of any type from `value[key]` using a map function.
pub(crate) fn vec_from_object<T, F>(
    value: &Value,
    key: &str,
    map_fn: F,
) -> Result<Vec<T>, JsonError>
where
    F: Fn(&Value) -> Result<T, JsonError>,
{
    let obj = &value[key];

    if obj.is_null() {
        Ok(Vec::new())
    } else {
        obj.as_array()
            .ok_or_else(|| JsonError::UnexpectedJsonType(key.into(), ExpectedType::Array))?
            .iter()
            .map(map_fn)
            .collect::<Result<Vec<_>, JsonError>>()
    }
}

/// Returns a string if the JSON value is a string type.
pub(crate) fn string_from_value(value: &Value) -> Result<&str, JsonError> {
    value.as_str().ok_or(JsonError::ExpectedJsonStr)
}

/// `value["controller"]` per DID Core 1.1 §5.1.2: absent, a string, or a set
/// of strings, each of which conforms to DID syntax (§3.1) — any DID method,
/// not only `did:btcr2`. A `did:btcr2:_` placeholder passes (`_` is an
/// `idchar`), so intermediate documents parse with the same rule.
pub(crate) fn controllers_from_object(value: &Value) -> Result<Vec<String>, JsonError> {
    let entry = |item: &Value| -> Result<String, JsonError> {
        let s = item.as_str().ok_or_else(|| {
            JsonError::UnexpectedJsonType("controller".into(), ExpectedType::String)
        })?;
        if is_did_syntax(s) {
            Ok(s.to_owned())
        } else {
            Err(JsonError::InvalidControllerDid(s.to_owned()))
        }
    };
    match value.get("controller") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(item @ Value::String(_)) => Ok(vec![entry(item)?]),
        Some(Value::Array(items)) => items.iter().map(entry).collect(),
        Some(_) => Err(JsonError::UnexpectedJsonType(
            "controller".into(),
            ExpectedType::StringOrArray,
        )),
    }
}

/// DID Core 1.1 §3.1 DID syntax, any method — the `controller` rule. A DID
/// URL (path, query or fragment present) is not a controller DID. Delegates
/// to the crate's one DID-syntax parser, `identifier::parse_did_syntax`.
pub(crate) fn is_did_syntax(s: &str) -> bool {
    matches!(parse_did_syntax(s), Ok(DidSyntax::Did { .. }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// DID Core 1.1 §3.1: the method name is lowercase alphanumeric, the
    /// method-specific id is colon-separated `idchar` runs whose last run is
    /// non-empty, and `%HH` is the only escape.
    #[test]
    fn did_syntax_accepts_any_method_and_rejects_malformed_identifiers() {
        for ok in [
            "did:btcr2:k1qgpakaw4lwemekywf0lyth9hf6j8r2td7gqtrs4aztqfky50jnx7s8gfapup6",
            "did:btcr2:_",
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            "did:example:123456789abcdefghi",
            "did:web:example.com:user:alice",
            "did:example:a::b",
            "did:example:%E2%9C%93",
            "did:ex4mple:a-b.c_d",
        ] {
            assert!(is_did_syntax(ok), "{ok} is a DID");
        }
        for bad in [
            "",
            "did:",
            "did:example",
            "did:example:",
            "did:Example:abc",
            "did:ex ample:abc",
            "did:example:abc:",
            "did:example:ab c",
            "did:example:ab#c",
            "did:example:ab/c",
            "did:example:ab?c",
            "did:example:%G1",
            "did:example:%4",
            "https://example.com",
            "btcr2:abc",
        ] {
            assert!(!is_did_syntax(bad), "{bad} is not a DID");
        }
    }

    /// `controller` is absent, a string, or an array of strings, each a DID of
    /// any method; anything else is a typed error naming the field.
    #[test]
    fn controllers_accept_a_string_or_an_array_of_dids() {
        assert_eq!(
            controllers_from_object(&json!({})).unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            controllers_from_object(&json!({ "controller": null })).unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            controllers_from_object(&json!({ "controller": "did:example:one" })).unwrap(),
            vec!["did:example:one"]
        );
        assert_eq!(
            controllers_from_object(&json!({ "controller": ["did:btcr2:_", "did:key:z6Mk"] }))
                .unwrap(),
            vec!["did:btcr2:_", "did:key:z6Mk"]
        );
        assert!(matches!(
            controllers_from_object(&json!({ "controller": "not a did" })),
            Err(JsonError::InvalidControllerDid(s)) if s == "not a did"
        ));
        assert!(matches!(
            controllers_from_object(&json!({ "controller": ["did:example:one", 7] })),
            Err(JsonError::UnexpectedJsonType(field, ExpectedType::String)) if field == "controller"
        ));
        assert!(matches!(
            controllers_from_object(&json!({ "controller": { "id": "did:example:one" } })),
            Err(JsonError::UnexpectedJsonType(field, ExpectedType::StringOrArray)) if field == "controller"
        ));
    }
}
