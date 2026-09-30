//! Internal human-readable part (HRP) handling for Bech32 strings.
//!
//! This module provides internal types and functions for validating and processing
//! the human-readable part component of Bech32 strings. The HRP appears before
//! the '1' separator and provides context about the encoded data type.
//!
//! # Internal Design
//!
//! The [`HumanReadablePart`] type encapsulates HRP validation according to BIP-173
//! requirements and ensures case normalization. This type is used internally by
//! the encoding and decoding functions to maintain data integrity.
//!
//! # Validation
//!
//! HRP strings must satisfy several constraints:
//! - **Length**: Between 1 and 83 characters
//! - **Character set**: ASCII values 33-126 (printable characters)
//! - **Case handling**: Normalized to lowercase for consistency

use crate::error::Bech32Error;
use std::fmt;

use crate::validation::{
    reject_bstring_values_out_of_range, reject_hrp_too_long, reject_hrp_too_short,
};

/// Internal type representing a validated human-readable part of a Bech32 string.
///
/// This type is used internally by the encoding and decoding functions to ensure
/// HRP values meet Bech32 specification requirements. It handles validation and
/// case normalization automatically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HumanReadablePart(Box<str>);

impl HumanReadablePart {
    /// Creates a new [`HumanReadablePart`] if it meets validation requirements.
    ///
    /// Validates the input according to Bech32 specification and normalizes to lowercase.
    /// This is used internally during encoding and decoding operations.
    ///
    /// # Arguments
    ///
    /// * `s` - A string-like value to validate as an HRP
    ///
    /// # Returns
    ///
    /// * `Ok(HumanReadablePart)` - If the string is valid
    /// * `Err(Bech32Error)` - If validation fails for invalid length or character content
    ///
    pub(crate) fn new(s: impl AsRef<str>) -> Result<Self, Bech32Error> {
        let s = s.as_ref();

        reject_hrp_too_short(s)?;
        reject_hrp_too_long(s)?;
        reject_bstring_values_out_of_range(s)?;

        Ok(HumanReadablePart(Box::from(s.to_lowercase())))
    }
}

impl AsRef<str> for HumanReadablePart {
    /// Provides string slice access for internal usage.
    ///
    /// Enables [`HumanReadablePart`] to be used in contexts expecting `&str`.
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HumanReadablePart {
    /// Formats the [`HumanReadablePart`] for internal display and debugging purposes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::MAX_HRP_LENGTH;

    #[test]
    fn test_human_readable_part_valid_creation() {
        // Test with valid HRPs
        assert!(HumanReadablePart::new("a").is_ok());
        assert!(HumanReadablePart::new("bc").is_ok());
        assert!(HumanReadablePart::new("test").is_ok());

        // Test with a valid but uppercase HRP (should convert to lowercase)
        let hrp = HumanReadablePart::new("ABC").unwrap();
        assert_eq!(hrp.as_ref(), "abc");

        // Test with a String
        let owned = String::from("valid");
        assert!(HumanReadablePart::new(owned).is_ok());

        // Test with exactly the maximum length
        let max_length_hrp = "a".repeat(MAX_HRP_LENGTH);
        assert!(HumanReadablePart::new(max_length_hrp).is_ok());
    }

    #[test]
    fn test_human_readable_part_invalid_creation() {
        // Test with an empty HRP (too short)
        assert!(matches!(
            HumanReadablePart::new(""),
            Err(Bech32Error::HrpTooShort)
        ));

        // Test with an HRP that's too long
        let too_long_hrp = "a".repeat(MAX_HRP_LENGTH + 1);
        assert!(matches!(
            HumanReadablePart::new(too_long_hrp),
            Err(Bech32Error::HrpTooLong)
        ));

        // Test with invalid characters
        assert!(matches!(
            HumanReadablePart::new("invalid\0char"),
            Err(Bech32Error::BStringValueOutOfRange)
        ));
    }

    fn takes_string_ref(s: impl AsRef<str>) -> String {
        s.as_ref().to_string()
    }

    #[test]
    fn test_human_readable_part_as_ref() {
        // Test AsRef<str> implementation
        let hrp = HumanReadablePart::new("test").unwrap();
        let s: &str = hrp.as_ref();
        assert_eq!(s, "test");

        // Test it can be passed to functions accepting AsRef<str>
        assert_eq!(takes_string_ref(&hrp), "test");
    }

    #[test]
    fn test_human_readable_part_cloning() {
        // Test cloning works properly
        let hrp1 = HumanReadablePart::new("clone-test").unwrap();
        let hrp2 = hrp1.clone();
        assert_eq!(hrp1.as_ref(), hrp2.as_ref());

        // Ensure they're independent
        let s1 = hrp1.0;
        let s2 = hrp2.0;
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_human_readable_part_display() {
        let hrp = HumanReadablePart::new("display-test").unwrap();
        assert_eq!(format!("{hrp}"), "display-test");
    }
}

#[cfg(test)]
mod proptests {

    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_valid_hrp_always_creates_correctly(s in "[a-zA-Z0-9]{1,83}") {
            if let Ok(hrp) = HumanReadablePart::new(&s) {
                prop_assert_eq!(hrp.as_ref(), s.to_lowercase());
            } else {
                prop_assert!(false, "HRP creation failed when it should have succeeded");
            }
        }

        #[test]
        fn prop_too_long_string_always_fails(s in ".{84,100}") {
            prop_assert!(matches!(HumanReadablePart::new(&s), Err(Bech32Error::HrpTooLong)));
        }
    }
}
