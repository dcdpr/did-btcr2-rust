use crate::identifier::Sha256Hash;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use onlyerror::Error;
use serde_json::Value;
use std::{fmt::Display, str::FromStr};

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

    /// Invalid Base58 encoding
    // retained pending a later error-vocabulary cleanup
    #[allow(dead_code)]
    Base58(#[from] esploda::bitcoin::base58::Error),

    /// Error with key operations
    Key(#[from] crate::key::Error),

    /// DID Encoding error
    DidEncoding(#[from] crate::identifier::Error),

    /// Verification Error
    Verification(#[from] crate::verification::Error),

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
}

impl Display for ExpectedType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExpectedType::Number => write!(f, "Number"),
            ExpectedType::String => write!(f, "String"),
            ExpectedType::Boolean => write!(f, "Boolean"),
            ExpectedType::Array => write!(f, "Array"),
            ExpectedType::Object => write!(f, "Object"),
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

/// Create a vector of any type from `value[key]` if it can be parsed from a string.
pub(crate) fn vec_from_value<T>(value: &Value, key: &str) -> Result<Vec<T>, JsonError>
where
    T: FromStr,
    JsonError: From<<T as FromStr>::Err>,
{
    vec_from_object(value, key, |v| Ok(string_from_value(v)?.parse()?))
}
