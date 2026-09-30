//! Internal combined data part and checksum handling for Bech32 strings.
//!
//! This module provides internal types for managing the combined data portion
//! of Bech32 strings that includes both the payload data and the 6-character
//! checksum. This represents the complete portion after the '1' separator.
//!
//! # Internal Design
//!
//! The [`DataPartWithChecksum`] type combines a [`DataPart`] and [`Checksum`]
//! into a single unit for processing during decoding operations. It handles
//! the parsing and separation of the data and checksum portions from the
//! raw string input.
//!
//! # String Structure
//!
//! For an example (invalid) Bech32 string `hrp1datachecks`, this type
//! represents `datachecks`:
//! - `data`: Variable-length payload data
//! - `checks`: Fixed 6-character checksum
//!
//! The boundary between data and checksum is determined by taking the last
//! 6 characters as the checksum and everything before as the data.

use crate::data_checksum::Checksum;
use crate::data_part::DataPart;
use crate::validation::reject_dp_too_short_for_decoding;
use crate::{Bech32Error, CHECKSUM_LENGTH};

/// Internal type representing the combined data part and checksum from a Bech32 string.
///
/// This type is used during decoding to separate and validate the data payload
/// and checksum portions that appear after the '1' separator. The checksum is
/// always the last 6 characters, with everything before it being the data.
///
/// Used internally by decoding functions to parse the string representation
/// into separate [`DataPart`] and [`Checksum`] components for validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DataPartWithChecksum {
    /// The data payload portion (everything except the last 6 characters).
    pub data_part: DataPart,
    /// The 6-character checksum portion (always the last 6 characters).
    pub checksum: Checksum,
}

impl DataPartWithChecksum {
    /// Creates a [`DataPartWithChecksum`] by parsing Bech32 string characters.
    ///
    /// Used internally during decoding to split the post-separator portion of
    /// a Bech32 string into data and checksum components. Validates that there
    /// are at least 6 characters available for the checksum.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw bytes from the Bech32 string after the '1' separator
    ///
    /// # Returns
    ///
    /// * `Ok(DataPartWithChecksum)` - If parsing and validation succeed
    /// * `Err(Bech32Error)` - If the data is too short or contains invalid characters
    ///
    pub(crate) fn from_alphanum(data: &[u8]) -> Result<Self, Bech32Error> {
        reject_dp_too_short_for_decoding(data)?;
        let (data_part_data, checksum_data) = data
            .split_at_checked(data.len() - CHECKSUM_LENGTH)
            .ok_or(Bech32Error::InvalidChecksum)?;
        Ok(DataPartWithChecksum {
            data_part: DataPart::from_alphanum(data_part_data)?,
            checksum: Checksum::from_alphanum(checksum_data)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation_too_short() {
        let data_part_with_checksum_string = String::from("n3a");

        assert!(matches!(
            DataPartWithChecksum::from_alphanum(data_part_with_checksum_string.as_ref()),
            Err(Bech32Error::DpTooShort)
        ));
    }

    #[test]
    fn test_creation_empty_data_part() {
        let data_part_with_checksum_string = String::from("lqfn3a");

        let result = DataPartWithChecksum::from_alphanum(data_part_with_checksum_string.as_ref());
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.data_part.len(), 0);
    }

    #[test]
    fn test_creation() {
        let data_part_with_checksum_string = String::from("l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx");

        let result = DataPartWithChecksum::from_alphanum(data_part_with_checksum_string.as_ref());
        assert!(result.is_ok());

        let result = result.unwrap();
        assert_eq!(
            result.data_part.len(),
            data_part_with_checksum_string.len() - CHECKSUM_LENGTH
        );
    }
}
