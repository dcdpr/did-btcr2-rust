//! Internal data part handling for Bech32 strings.
//!
//! This module provides internal types and functions for processing the data part
//! of Bech32 strings (the part between the separator and checksum). The data part
//! contains the actual encoded payload and requires conversion between different
//! bit representations.
//!
//! # Internal Design
//!
//! The [`DataPart`] type encapsulates data validation and bit conversion operations
//! required for Bech32 encoding/decoding. It handles the conversion between:
//! - 8-bit bytes (user data)
//! - 5-bit values (Bech32 encoding format)
//! - Alphanumeric characters (Bech32 string representation)
//!
//! # Bit Conversion
//!
//! Bech32 uses 5-bit values to ensure each character maps to exactly one value
//! in the 32-character alphabet. This requires conversion between standard 8-bit
//! bytes and 5-bit representations with appropriate padding handling.

use crate::core::map_from_charset;
use crate::core::{compress_bits, expand_bits};
use crate::error::Bech32Error;
use crate::validation::reject_data_values_out_of_range;
use arbitrary_int::u5;

/// Internal type representing the data portion of a Bech32 string.
///
/// Contains the encoded data portion (excluding the checksum) and handles
/// validation and conversion between different bit representations. Used
/// internally by encoding and decoding functions.
///
/// The data is stored as 5-bit values (0-31 range) suitable for direct
/// mapping to the Bech32 character set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DataPart(Vec<u8>);

impl DataPart {
    /// Creates a new [`DataPart`] from 5-bit values if they are within valid range.
    ///
    /// Used internally when constructing data parts from validated 5-bit values.
    /// All values must be in the range 0-31 to be valid for Bech32 encoding.
    ///
    /// # Arguments
    ///
    /// * `data` - Slice of bytes representing 5-bit data values
    ///
    /// # Returns
    ///
    /// * `Ok(DataPart)` - If all values are in valid 5-bit range
    /// * `Err(Bech32Error)` - If any values are out of range (> 31)
    pub(crate) fn new(data: &[u8]) -> Result<Self, Bech32Error> {
        Self::from_5bit_bytes(data)
    }

    pub(crate) fn from_u5(data: &[u5]) -> Self {
        DataPart(data.iter().map(|&x| u8::from(x)).collect())
    }

    /// Internal constructor from validated 5-bit byte data.
    fn from_5bit_bytes(data: &[u8]) -> Result<Self, Bech32Error> {
        reject_data_values_out_of_range(data)?;
        Ok(DataPart(data.to_vec()))
    }

    /// Creates a [`DataPart`] by converting 8-bit bytes to 5-bit representation.
    ///
    /// Used internally during encoding to convert user data (8-bit bytes) into
    /// the 5-bit format required for Bech32. Handles padding automatically.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw 8-bit binary data to be encoded
    ///
    /// # Returns
    ///
    /// * `Ok(DataPart)` - If conversion succeeds
    /// * `Err(Bech32Error)` - If conversion fails
    pub(crate) fn from_bytes(data: &[u8]) -> Result<Self, Bech32Error> {
        let mut result = Vec::new();
        expand_bits(&mut result, data)?;
        Self::from_5bit_bytes(result.as_ref())
    }

    /// Creates a [`DataPart`] from Bech32 string characters.
    ///
    /// Used internally during decoding to convert the alphabetic characters
    /// from a Bech32 string into their corresponding 5-bit values.
    ///
    /// # Arguments
    ///
    /// * `data` - Slice of bytes representing Bech32 characters
    ///
    /// # Returns
    ///
    /// * `Ok(DataPart)` - If all characters are valid
    /// * `Err(Bech32Error)` - If invalid characters are encountered
    pub(crate) fn from_alphanum(data: &[u8]) -> Result<Self, Bech32Error> {
        let result = map_from_charset(data)?;
        Self::from_5bit_bytes(result.as_ref())
    }

    /// Converts the 5-bit data back to 8-bit bytes.
    ///
    /// Used internally during decoding to recover the original user data
    /// from the 5-bit Bech32 representation. Validates padding correctness.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The converted 8-bit data
    /// * `Err(Bech32Error)` - If conversion fails due to invalid padding
    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>, Bech32Error> {
        let mut result = Vec::new();
        compress_bits(&mut result, &self.0)?;
        Ok(result)
    }

    /// Returns a reference to the internal 5-bit data values.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the number of 5-bit values in the data part.
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
}

impl AsRef<[u8]> for DataPart {
    /// Provides slice access to the internal 5-bit data values.
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<DataPart> for Vec<u8> {
    /// Converts a [`DataPart`] into its internal data vector.
    fn from(dp: DataPart) -> Self {
        dp.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::MAX_DP_CHARSET_INDEX;
    use proptest::prelude::*;

    #[test]
    fn test_data_part_valid_creation() {
        // Test with valid data values
        let data = vec![0, 1, 2, 3, 31];
        assert!(DataPart::new(&data).is_ok());

        // Test with empty data (which is valid)
        let empty = Vec::new();
        assert!(DataPart::new(&empty).is_ok());

        // Test with data containing maximum valid value
        let max_value = vec![MAX_DP_CHARSET_INDEX];
        assert!(DataPart::new(&max_value).is_ok());
    }

    #[test]
    fn test_data_part_invalid_creation() {
        // Test with invalid data value (too large)
        let invalid_data = vec![0, 1, MAX_DP_CHARSET_INDEX + 1, 3];
        assert!(matches!(
            DataPart::new(&invalid_data),
            Err(Bech32Error::DataValueOutOfRange)
        ));

        // Test with invalid data value (way too large)
        let very_invalid_data = vec![0, 1, 255, 3];
        assert!(matches!(
            DataPart::new(&very_invalid_data),
            Err(Bech32Error::DataValueOutOfRange)
        ));
    }

    #[test]
    fn test_data_part_as_ref() {
        let data = vec![1, 2, 3];
        let dp = DataPart::new(&data).unwrap();

        // Test that as_ref returns the correct slice
        let slice: &[u8] = dp.as_ref();
        assert_eq!(slice, &[1, 2, 3]);

        // Test that as_bytes returns the same slice
        assert_eq!(dp.as_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn test_data_part_from_bytes() {
        // Simple test with known conversion
        let original = vec![0x01, 0x02]; // binary 0000_0001 0000_0010
        let dp = DataPart::from_bytes(&original).unwrap();

        // After 8-to-5 bit conversion, we should have:
        // 00000 00100 00001 00000
        let expected = vec![0, 4, 1, 0];
        assert_eq!(dp.as_bytes(), &expected);

        // Convert back and check it matches original
        let recovered = dp.to_bytes().unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn test_data_part_empty() {
        let dp = DataPart::new(&[]).unwrap();
        assert_eq!(dp.len(), 0);
    }

    proptest! {
        #[test]
        fn prop_valid_dp_always_creates_correctly(data in prop::collection::vec(0..=MAX_DP_CHARSET_INDEX, 0..100)) {
            let dp = DataPart::new(&data);
            prop_assert!(dp.is_ok());
            let dp = dp.unwrap();
            prop_assert_eq!(dp.as_bytes(), &data);
        }

        #[test]
        fn prop_invalid_dp_always_fails(
            valid_prefix in prop::collection::vec(0..=MAX_DP_CHARSET_INDEX, 0..10),
            invalid_value in (MAX_DP_CHARSET_INDEX + 1)..255u8,
            valid_suffix in prop::collection::vec(0..=MAX_DP_CHARSET_INDEX, 0..10)
        ) {
            let mut data = valid_prefix;
            data.push(invalid_value);
            data.extend_from_slice(&valid_suffix);

            prop_assert!(matches!(DataPart::new(&data), Err(Bech32Error::DataValueOutOfRange)));
        }

        #[test]
        fn prop_byte_conversion_roundtrip(data in prop::collection::vec(any::<u8>(), 0..100)) {
            let dp = DataPart::from_bytes(&data).unwrap();
            let recovered = dp.to_bytes().unwrap();
            prop_assert_eq!(recovered, data);
        }
    }
}
