//! Internal checksum handling for Bech32 strings.
//!
//! This module provides internal types for managing the 6-character checksum portion
//! of Bech32 strings. The checksum provides error detection capabilities and is
//! computed using polynomial arithmetic over the entire string.
//!
//! # Internal Design
//!
//! The [`Checksum`] type encapsulates the fixed-length checksum data and handles
//! conversion between different representations:
//! - Raw 5-bit values (internal computation)
//! - Alphanumeric characters (string representation)
//!
//! # Checksum Properties
//!
//! - **Fixed length**: Always exactly 6 characters/values
//! - **Error detection**: Can detect most single-character errors and character swaps
//! - **Two variants**: Supports both original Bech32 and improved Bech32m algorithms

use crate::constants::CHECKSUM_LENGTH;
use crate::core::map_from_charset;
use crate::error::Bech32Error;

/// Internal type representing the checksum portion of a Bech32 string.
///
/// The checksum is always exactly 6 values/characters and provides error detection
/// for Bech32 strings. Used internally by encoding and decoding functions to
/// validate string integrity.
///
/// Stores the checksum as 5-bit values (0-31 range) suitable for direct mapping
/// to the Bech32 character set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Checksum([u8; CHECKSUM_LENGTH]);

impl Checksum {
    /// Creates a new [`Checksum`] from 5-bit values.
    ///
    /// Used internally when constructing checksums from computed polynomial values.
    /// The data must be exactly 6 bytes representing 5-bit values.
    ///
    /// # Arguments
    ///
    /// * `data` - Slice of exactly 6 bytes representing checksum values
    ///
    /// # Returns
    ///
    /// * `Ok(Checksum)` - If the data length is correct
    /// * `Err(Bech32Error)` - If the data is not exactly 6 bytes
    pub(crate) fn new(data: &[u8]) -> Result<Self, Bech32Error> {
        if data.len() == CHECKSUM_LENGTH {
            let mut array = [0u8; CHECKSUM_LENGTH];
            array.copy_from_slice(data);
            Ok(Checksum(array))
        } else {
            Err(Bech32Error::InvalidChecksum)
        }
    }

    /// Creates a [`Checksum`] from Bech32 string characters.
    ///
    /// Used internally during decoding to convert the checksum portion of a
    /// Bech32 string from alphabetic characters to their corresponding 5-bit values.
    ///
    /// # Arguments
    ///
    /// * `data` - Slice of exactly 6 bytes representing Bech32 characters
    ///
    /// # Returns
    ///
    /// * `Ok(Checksum)` - If conversion succeeds and length is correct
    /// * `Err(Bech32Error)` - If invalid characters or wrong length
    pub(crate) fn from_alphanum(data: &[u8]) -> Result<Self, Bech32Error> {
        if data.len() == CHECKSUM_LENGTH {
            let mapped_data = map_from_charset(data)?;
            let mut array = [0u8; CHECKSUM_LENGTH];
            array.copy_from_slice(mapped_data.as_slice());
            Ok(Checksum(array))
        } else {
            Err(Bech32Error::InvalidChecksum)
        }
    }

    /// Returns a reference to the internal 5-bit checksum values.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for Checksum {
    /// Provides slice access to the internal checksum data.
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::CHECKSUM_LENGTH;
    use proptest::prelude::*;

    #[test]
    fn test_checksum_valid_creation() {
        // Test with valid data values
        let data = vec![0, 1, 2, 3, 100, 255];
        assert!(Checksum::new(&data).is_ok());
    }

    #[test]
    fn test_data_part_invalid_creation() {
        let too_short = vec![0, 1, 2, 3, 4];
        assert!(matches!(
            Checksum::new(&too_short),
            Err(Bech32Error::InvalidChecksum)
        ));

        let too_long = vec![0, 1, 2, 3, 4, 5, 6];
        assert!(matches!(
            Checksum::new(&too_long),
            Err(Bech32Error::InvalidChecksum)
        ));
    }

    #[test]
    fn test_checksum_as_ref() {
        let data = vec![1, 2, 3, 4, 5, 6];
        let dp = Checksum::new(&data).unwrap();

        // Test that as_ref returns the correct slice
        let slice: &[u8] = dp.as_ref();
        assert_eq!(slice, &[1, 2, 3, 4, 5, 6]);

        // Test that as_bytes returns the same slice
        assert_eq!(dp.as_bytes(), &[1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn test_checksum_as_bytes() {
        let dp = Checksum::new(&[1, 2, 3, 4, 5, 6]).unwrap();
        let bytes = dp.as_bytes();
        assert_eq!(bytes, vec![1, 2, 3, 4, 5, 6]);
    }

    proptest! {
        #[test]
        fn prop_valid_checksum_always_creates_correctly(data in prop::collection::vec(0..255u8, CHECKSUM_LENGTH)) {
            let dp = Checksum::new(&data);
            prop_assert!(dp.is_ok());
            let dp = dp.unwrap();
            prop_assert_eq!(dp.as_bytes(), &data);
        }

        #[test]
        fn prop_invalid_dp_always_fails(
            too_short in prop::collection::vec(0..255u8, 0..CHECKSUM_LENGTH-1),
            too_long in prop::collection::vec(0..255u8, CHECKSUM_LENGTH+1..100)
        ) {
            let data = too_short;
            prop_assert!(matches!(Checksum::new(&data), Err(Bech32Error::InvalidChecksum)));

            let data = too_long;
            prop_assert!(matches!(Checksum::new(&data), Err(Bech32Error::InvalidChecksum)));
        }

    }
}
