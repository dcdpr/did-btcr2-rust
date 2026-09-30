//! Internal validation functions for Bech32 string components.
//!
//! This module provides internal validation functions used throughout the encoding
//! and decoding pipeline to ensure Bech32 strings and their components meet the
//! specification requirements defined in BIP-173 and BIP-350.
//!
//! # Validation Categories
//!
//! - **String format validation**: Overall Bech32 string structure and constraints
//! - **Component validation**: Individual parts (HRP, data part, checksum)
//! - **Character validation**: ASCII ranges and valid character sets
//! - **Length validation**: Size constraints for various components
//!
//! # Design Philosophy
//!
//! Each validation function has a single responsibility and returns a specific
//! error type. This allows the encoding/decoding functions to provide precise
//! error messages and handle different validation failures appropriately.
//!
//! Functions follow a "reject if invalid" pattern, returning `Ok(())` for valid
//! input and appropriate `Bech32Error` variants for validation failures.

use crate::constants::{
    CHECKSUM_LENGTH, MAX_BECH32_LENGTH, MAX_DP_CHARSET_INDEX, MAX_HRP_CHAR_VALUE, MAX_HRP_LENGTH,
    MIN_BECH32_LENGTH, MIN_HRP_CHAR_VALUE, MIN_HRP_LENGTH, SEPARATOR, SEPARATOR_LENGTH,
};
use crate::data_part::DataPart;
use crate::error::Bech32Error;
use crate::hrp::HumanReadablePart;

/// Validates that a Bech32 string meets the minimum length requirement.
///
/// Bech32 strings must be at least 8 characters: minimum 1-character HRP +
/// '1' separator + 6-character checksum. Used internally during decoding
/// to ensure sufficient data is present.
pub(crate) fn reject_bstring_too_short(bstring: &str) -> Result<(), Bech32Error> {
    reject_bstring_values_out_of_range(bstring)?;
    if bstring.len() < MIN_BECH32_LENGTH {
        return Err(Bech32Error::BStringTooShort);
    }
    Ok(())
}

/// Validates that a Bech32 string does not exceed the maximum length.
///
/// Bech32 strings cannot exceed 90 characters total. Used internally
/// during encoding and decoding operations.
pub(crate) fn reject_bstring_too_long(bstring: &str) -> Result<(), Bech32Error> {
    reject_bstring_values_out_of_range(bstring)?;
    if bstring.len() > MAX_BECH32_LENGTH {
        return Err(Bech32Error::BStringTooLong);
    }
    Ok(())
}

/// Validates that a Bech32 string does not mix uppercase and lowercase characters.
///
/// The Bech32 specification requires strings to be either all uppercase or all
/// lowercase. Mixed case strings are rejected to prevent confusion and ensure
/// consistent processing.
pub(crate) fn reject_bstring_mixed_case(bstring: &str) -> Result<(), Bech32Error> {
    let at_least_one_upper = bstring.bytes().any(|b| b.is_ascii_uppercase());
    let at_least_one_lower = bstring.bytes().any(|b| b.is_ascii_lowercase());
    if at_least_one_upper && at_least_one_lower {
        return Err(Bech32Error::BStringMixedCase);
    }
    Ok(())
}

/// Validates that all characters in a Bech32 string are within the valid ASCII range.
///
/// All characters must have ASCII values between 33 and 126 (printable ASCII
/// excluding space).
pub(crate) fn reject_bstring_values_out_of_range(bstring: &str) -> Result<(), Bech32Error> {
    if bstring
        .bytes()
        .any(|b| !(MIN_HRP_CHAR_VALUE..=MAX_HRP_CHAR_VALUE).contains(&b))
    {
        return Err(Bech32Error::BStringValueOutOfRange);
    }
    Ok(())
}

/// Validates that a Bech32 string contains the required separator character.
///
/// Every Bech32 string must contain at least one '1' character that separates
/// the human-readable part from the data part.
pub(crate) fn reject_bstring_with_no_separator(bstring: &str) -> Result<(), Bech32Error> {
    if !bstring.bytes().any(|b| b == SEPARATOR as u8) {
        return Err(Bech32Error::BStringMissingSeparator);
    }
    Ok(())
}

/// Validates that a Bech32 string meets all structural requirements.
///
/// Performs comprehensive validation by checking all format requirements:
/// length constraints, case consistency, character ranges, and separator presence.
/// Used internally as the primary validation entry point during decoding.
pub(crate) fn reject_bstring_that_isnt_well_formed(bstring: &str) -> Result<(), Bech32Error> {
    reject_bstring_too_short(bstring)?;
    reject_bstring_too_long(bstring)?;
    reject_bstring_mixed_case(bstring)?;
    reject_bstring_values_out_of_range(bstring)?;
    reject_bstring_with_no_separator(bstring)?;
    Ok(())
}

/// Validates that an HRP string meets the minimum length requirement.
///
/// The human-readable part must contain at least one character.
/// Used internally during HRP construction to prevent empty HRPs.
pub(crate) fn reject_hrp_too_short(hrp_str: &str) -> Result<(), Bech32Error> {
    if hrp_str.len() < MIN_HRP_LENGTH {
        return Err(Bech32Error::HrpTooShort);
    }
    Ok(())
}

/// Validates that an HRP string does not exceed the maximum length.
///
/// The human-readable part cannot exceed 83 characters to ensure the total
/// Bech32 string stays within the 90-character limit. Used internally during
/// HRP construction and encoding operations.
pub(crate) fn reject_hrp_too_long(hrp_str: &str) -> Result<(), Bech32Error> {
    if hrp_str.len() > MAX_HRP_LENGTH {
        return Err(Bech32Error::HrpTooLong);
    }
    Ok(())
}

/// Validates that a data part has sufficient length for decoding operations.
///
/// During decoding, the data part (including checksum) must contain at least
/// 6 characters for the checksum. Used internally to ensure sufficient data
/// is available before attempting to separate data and checksum portions.
pub(crate) fn reject_dp_too_short_for_decoding(dp: &[u8]) -> Result<(), Bech32Error> {
    // while a DataPart could be of zero length, a DataPartWithChecksum
    // which is about to be decoded needs to be at least CHECKSUM_LENGTH
    if dp.len() < CHECKSUM_LENGTH {
        return Err(Bech32Error::DpTooShort);
    }
    Ok(())
}

/// Validates that the combined HRP and data part lengths are within limits.
///
/// The total length of HRP + separator + data part + checksum must not exceed
/// 90 characters. Used internally during encoding to ensure the resulting
/// Bech32 string will be valid before performing expensive operations.
pub(crate) fn reject_both_parts_too_long(
    hrp: &HumanReadablePart,
    dp: &DataPart,
) -> Result<(), Bech32Error> {
    if hrp.as_ref().len() + SEPARATOR_LENGTH + dp.len() + CHECKSUM_LENGTH > MAX_BECH32_LENGTH {
        return Err(Bech32Error::BothPartsTooLong);
    }
    Ok(())
}

/// Validates that data values are within the valid 5-bit range for Bech32.
///
/// All data values must be in the range 0-31 to be valid for encoding with
/// the 32-character Bech32 alphabet. Used internally during data part
/// construction to ensure values can be properly encoded.
pub(crate) fn reject_data_values_out_of_range(dp: &[u8]) -> Result<(), Bech32Error> {
    for c in dp {
        if *c > MAX_DP_CHARSET_INDEX {
            return Err(Bech32Error::DataValueOutOfRange);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // check that we reject strings less than MIN_BECH32_LENGTH chars in length
    fn ensure_correct_data_size_low() {
        let seven_chars = String::from("abcdefg");

        assert!(matches!(
            reject_bstring_too_short(&seven_chars),
            Err(Bech32Error::BStringTooShort)
        ));

        let eight_chars = String::from("abcdefgh");

        assert!(matches!(reject_bstring_too_short(&eight_chars), Ok(())));
    }

    #[test]
    // check that we reject strings greater than MAX_BECH32_LENGTH chars in length
    fn ensure_correct_data_size_high() {
        let too_many_chars: String = "a".repeat(91);

        assert!(matches!(
            reject_bstring_too_long(&too_many_chars),
            Err(Bech32Error::BStringTooLong)
        ));

        let just_enough_chars: String = "a".repeat(90);

        assert!(matches!(
            reject_bstring_too_long(&just_enough_chars),
            Ok(())
        ));
    }

    #[test]
    // check that we accept strings with all numbers, since there is no mixed case present
    fn accept_all_numeric_data() {
        assert!(matches!(
            reject_bstring_mixed_case(&String::from("1")),
            Ok(())
        ));
        assert!(matches!(
            reject_bstring_mixed_case(&String::from("9483538")),
            Ok(())
        ));
    }

    #[test]
    // check that we accept strings with all lowercase, with and without numbers
    fn accept_all_lowercase_data() {
        assert!(matches!(
            reject_bstring_mixed_case(&String::from("abcdefghi")),
            Ok(())
        ));
        assert!(matches!(
            reject_bstring_mixed_case(&String::from("abcde123fghi")),
            Ok(())
        ));
    }

    #[test]
    // check that we accept strings with all uppercase, with and without numbers
    fn accept_all_uppercase_data() {
        assert!(matches!(
            reject_bstring_mixed_case(&String::from("ABCDEFGHI")),
            Ok(())
        ));
        assert!(matches!(
            reject_bstring_mixed_case(&String::from("ABCDE123FGHI")),
            Ok(())
        ));
    }

    #[test]
    // check that we reject strings with mixedcase, with and without numbers
    fn reject_mixedcase_data() {
        assert!(matches!(
            reject_bstring_mixed_case(&String::from("abcdEfghi")),
            Err(Bech32Error::BStringMixedCase)
        ));
        assert!(matches!(
            reject_bstring_mixed_case(&String::from("ABCDeFGHI")),
            Err(Bech32Error::BStringMixedCase)
        ));
        assert!(matches!(
            reject_bstring_mixed_case(&String::from("abcde123FGHI")),
            Err(Bech32Error::BStringMixedCase)
        ));
    }

    #[test]
    // check that we accept strings with in-range characters
    fn accept_data_in_range() {
        assert!(matches!(
            reject_bstring_values_out_of_range(&String::from("abcde")),
            Ok(())
        ));
        assert!(matches!(
            reject_bstring_values_out_of_range(&String::from("!!abcde}~")),
            Ok(())
        ));
    }

    #[test]
    // check that we reject strings with out-of-range characters
    fn reject_data_out_of_range() {
        assert!(matches!(
            reject_bstring_values_out_of_range(&String::from(" ")),
            Err(Bech32Error::BStringValueOutOfRange)
        ));
        assert!(matches!(
            reject_bstring_values_out_of_range(&String::from("\x20")),
            Err(Bech32Error::BStringValueOutOfRange)
        ));
        assert!(matches!(
            reject_bstring_values_out_of_range(&String::from("\x7f")),
            Err(Bech32Error::BStringValueOutOfRange)
        ));
        assert!(matches!(
            reject_bstring_values_out_of_range(&String::from(" abc\x7fxyz\x0d")),
            Err(Bech32Error::BStringValueOutOfRange)
        ));
    }

    #[test]
    // check that we reject strings with no separator character
    fn reject_data_with_no_separator() {
        assert!(matches!(
            reject_bstring_with_no_separator(""),
            Err(Bech32Error::BStringMissingSeparator)
        ));
        assert!(matches!(
            reject_bstring_with_no_separator(&String::from("abcd")),
            Err(Bech32Error::BStringMissingSeparator)
        ));
    }

    #[test]
    // check that we accept strings with at least one separator character
    fn accept_data_with_no_separator() {
        assert!(matches!(
            reject_bstring_with_no_separator(&String::from("ab1cd")),
            Ok(())
        ));
        assert!(matches!(
            reject_bstring_with_no_separator(&String::from("111")),
            Ok(())
        ));
    }

    #[test]
    // check that we reject HRP strings that are too short
    fn ensure_reject_hrp_too_short() {
        assert!(matches!(
            reject_hrp_too_short(""),
            Err(Bech32Error::HrpTooShort)
        ));
        assert!(matches!(reject_hrp_too_short(&String::from("a")), Ok(())));
    }

    #[test]
    // check that we reject HRP strings that are too long
    fn ensure_reject_hrp_too_long() {
        let too_many_chars: String = "a".repeat(MAX_HRP_LENGTH + 1);
        assert!(matches!(
            reject_hrp_too_long(&too_many_chars),
            Err(Bech32Error::HrpTooLong)
        ));

        let just_enough_chars: String = "a".repeat(MAX_HRP_LENGTH);
        assert!(matches!(reject_hrp_too_long(&just_enough_chars), Ok(())));
    }

    #[test]
    // check that we reject data parts that are too short
    fn ensure_reject_dp_too_short() {
        let dp_too_short = &[0; CHECKSUM_LENGTH - 1];
        assert!(matches!(
            reject_dp_too_short_for_decoding(dp_too_short),
            Err(Bech32Error::DpTooShort)
        ));

        let dp_just_enough = &[0; CHECKSUM_LENGTH];
        assert!(matches!(
            reject_dp_too_short_for_decoding(dp_just_enough),
            Ok(())
        ));
    }

    #[test]
    fn ensure_reject_data_values_out_of_range() {
        let dp = &[1u8, 2, 3];
        assert!(matches!(reject_data_values_out_of_range(dp), Ok(())));

        let dp = &[1u8, 2, 65];
        assert!(matches!(
            reject_data_values_out_of_range(dp),
            Err(Bech32Error::DataValueOutOfRange)
        ));
    }

    #[test]
    // check that we reject HRPs and data parts that are too long together
    fn ensure_reject_both_parts_too_long() {
        let hrp_max_chars = HumanReadablePart::new("a".repeat(MAX_HRP_LENGTH)).unwrap();
        let dp_empty = DataPart::new(&[]).unwrap();
        assert!(matches!(
            reject_both_parts_too_long(&hrp_max_chars, &dp_empty),
            Ok(())
        ));

        let dp_one_byte = DataPart::new(&[0x0]).unwrap();
        assert!(matches!(
            reject_both_parts_too_long(&hrp_max_chars, &dp_one_byte),
            Err(Bech32Error::BothPartsTooLong)
        ));
    }
}

#[cfg(test)]
mod proptests {
    use crate::constants::MIN_BECH32_LENGTH;
    use crate::validation::*;
    use proptest::prelude::*;

    fn str_of_len(min: usize, max: usize) -> impl Strategy<Value = String> {
        prop::string::string_regex(&format!(".{{{min},{max}}}")).unwrap()
    }

    fn str_of_len_numbers(min: usize, max: usize) -> impl Strategy<Value = String> {
        prop::string::string_regex(&format!("[0-9]{{{min},{max}}}")).unwrap()
    }

    fn str_of_len_lower(min: usize, max: usize) -> impl Strategy<Value = String> {
        prop::string::string_regex(&format!("[a-z]{{{min},{max}}}")).unwrap()
    }

    fn str_of_len_upper(min: usize, max: usize) -> impl Strategy<Value = String> {
        prop::string::string_regex(&format!("[A-Z]{{{min},{max}}}")).unwrap()
    }

    fn str_of_len_mixed(min: usize, max: usize) -> impl Strategy<Value = String> {
        // simply asking for [A-Za-z] may not always produce a mixedcase string, so we should
        // force a couple characters at the start. This hampers the randomness of the test
        // case but not yet sure how to do it better. Maybe with a filter?
        prop::string::string_regex(&format!(
            "[A-Z]{{1}}[a-z]{{1}}[A-Za-z]{{{},{}}}",
            min - 2,
            max
        ))
        .unwrap()
    }

    fn str_of_len_numbers_lower(min: usize, max: usize) -> impl Strategy<Value = String> {
        // simply asking for [a-z0-9] may not always produce a string with at least one lowercase
        // char and at least one number, so we should force a couple characters at the start. This
        // hampers the randomness of the test case but not yet sure how to do it better. Maybe
        // with a filter?
        prop::string::string_regex(&format!(
            "[a-z]{{1}}[0-9]{{1}}[a-z0-9]{{{},{}}}",
            min - 2,
            max
        ))
        .unwrap()
    }

    fn str_of_len_numbers_upper(min: usize, max: usize) -> impl Strategy<Value = String> {
        // simply asking for [A-Z0-9] may not always produce a string with at least one uppercase
        // char and at least one number, so we should force a couple characters at the start. This
        // hampers the randomness of the test case but not yet sure how to do it better. Maybe
        // with a filter?
        prop::string::string_regex(&format!(
            "[A-Z]{{1}}[0-9]{{1}}[A-Z0-9]{{{},{}}}",
            min - 2,
            max
        ))
        .unwrap()
    }

    fn str_of_len_numbers_mixed(min: usize, max: usize) -> impl Strategy<Value = String> {
        // simply asking for [A-Za-z0-9] may not always produce a string with at least one uppercase,
        // one lowercase char and at least one number, so we should force a few characters at the start. This
        // hampers the randomness of the test case but not yet sure how to do it better. Maybe
        // with a filter?
        prop::string::string_regex(&format!(
            "[A-Z]{{1}}[a-z]{{1}}[0-9]{{1}}[A-Za-z0-9]{{{},{}}}",
            min - 3,
            max
        ))
        .unwrap()
    }

    fn str_of_len_chars_in_range(min: usize, max: usize) -> impl Strategy<Value = String> {
        prop::string::string_regex(&format!("[\x21-\x7e]{{{min},{max}}}")).unwrap()
    }

    fn str_of_len_chars_out_of_range(min: usize, max: usize) -> impl Strategy<Value = String> {
        prop::string::string_regex(&format!("[\x00-\x20\x7f]{{{min},{max}}}")).unwrap()
    }

    fn str_of_len_no_separator(min: usize, max: usize) -> impl Strategy<Value = String> {
        prop::string::string_regex(&format!("[a-z02-9]{{{min},{max}}}")).unwrap()
    }

    fn str_of_len_with_separator(min: usize, max: usize) -> impl Strategy<Value = String> {
        // simply asking for [a-z0-9] may not always produce a string with at least one '1'
        // char, so we should force one at the start. This hampers the randomness of the test
        // case but not yet sure how to do it better. Maybe with a filter?
        prop::string::string_regex(&format!("1[a-z02-9]{{{},{}}}", min - 1, max)).unwrap()
    }

    proptest! {

        #[test]
        fn strings_too_short_are_rejected(s in str_of_len(0, MIN_BECH32_LENGTH-1))
        {
            let res = reject_bstring_too_short(&s);
            prop_assert!(
            matches!(res, Err(Bech32Error::BStringTooShort)) ||
            matches!(res, Err(Bech32Error::BStringValueOutOfRange)));
        }

        #[test]
        fn strings_not_too_short_and_not_too_long_are_accepted(s in str_of_len(MIN_BECH32_LENGTH, MAX_BECH32_LENGTH))
        {
            let mut res = reject_bstring_too_short(&s);
            prop_assert!(
            matches!(res, Ok(())) ||
            matches!(res, Err(Bech32Error::BStringValueOutOfRange)));

            res = reject_bstring_too_long(&s);
            prop_assert!(
            matches!(res, Ok(())) ||
            matches!(res, Err(Bech32Error::BStringValueOutOfRange)));
        }

        #[test]
        fn strings_too_long_are_rejected(s in str_of_len(MAX_BECH32_LENGTH+1, 200))
        {
            let res = reject_bstring_too_long(&s);
            prop_assert!(
            matches!(res, Err(Bech32Error::BStringTooLong)) ||
            matches!(res, Err(Bech32Error::BStringValueOutOfRange)));
        }

        // check that we accept strings with all numbers, since there is no mixedcase present
        #[test]
        fn strings_with_all_numbers_are_accepted(s in str_of_len_numbers(MIN_BECH32_LENGTH, MAX_BECH32_LENGTH))
        {
            prop_assert!(matches!(reject_bstring_mixed_case(&s), Ok(())));
        }

        // check that we accept strings with all lowercase, since there is no mixedcase present
        #[test]
        fn strings_with_all_lowercase_are_accepted(s in str_of_len_lower(MIN_BECH32_LENGTH, MAX_BECH32_LENGTH))
        {
            prop_assert!(matches!(reject_bstring_mixed_case(&s), Ok(())));
        }

        // check that we accept strings with all uppercase, since there is no mixedcase present
        #[test]
        fn strings_with_all_uppercase_are_accepted(s in str_of_len_upper(MIN_BECH32_LENGTH, MAX_BECH32_LENGTH))
        {
            prop_assert!(matches!(reject_bstring_mixed_case(&s), Ok(())));
        }

        // check that we accept strings with all lowercase and numbers, since there is no mixedcase present
        #[test]
        fn strings_with_all_lowercase_and_numbers_are_accepted(s in str_of_len_numbers_lower(MIN_BECH32_LENGTH, MAX_BECH32_LENGTH))
        {
            prop_assert!(matches!(reject_bstring_mixed_case(&s), Ok(())));
        }

        // check that we accept strings with all uppercase and numbers, since there is no mixedcase present
        #[test]
        fn strings_with_all_uppercase_and_numbers_are_accepted(s in str_of_len_numbers_upper(MIN_BECH32_LENGTH, MAX_BECH32_LENGTH))
        {
            prop_assert!(matches!(reject_bstring_mixed_case(&s), Ok(())));
        }

        // check that we reject strings with mixedcase
        #[test]
        fn strings_with_mixedcase_are_rejected(s in str_of_len_mixed(MIN_BECH32_LENGTH, MAX_BECH32_LENGTH))
        {
            prop_assert!(matches!(reject_bstring_mixed_case(&s), Err(Bech32Error::BStringMixedCase)));
        }

        // check that we reject strings with mixedcase and numbers
        #[test]
        fn strings_with_mixedcase_and_numbers_are_rejected(s in str_of_len_numbers_mixed(MIN_BECH32_LENGTH, MAX_BECH32_LENGTH))
        {
            prop_assert!(matches!(reject_bstring_mixed_case(&s), Err(Bech32Error::BStringMixedCase)));
        }

        // check that we accept strings with any chars within the acceptable range
        #[test]
        fn strings_with_chars_within_range_are_accepted(s in str_of_len_chars_in_range(MIN_BECH32_LENGTH, MAX_BECH32_LENGTH))
        {
            prop_assert!(matches!(reject_bstring_values_out_of_range(&s), Ok(())));
        }

        // check that we reject strings with chars outside the acceptable range
        #[test]
        fn strings_with_chars_outside_range_are_rejected(s in str_of_len_chars_out_of_range(MIN_BECH32_LENGTH, MAX_BECH32_LENGTH))
        {
            prop_assert!(matches!(reject_bstring_values_out_of_range(&s), Err(Bech32Error::BStringValueOutOfRange)));
        }

        // check that we reject strings with no separator character
        #[test]
        fn strings_with_no_separator_char_are_rejected(s in str_of_len_no_separator(MIN_BECH32_LENGTH, MAX_BECH32_LENGTH))
        {
            prop_assert!(matches!(reject_bstring_with_no_separator(&s), Err(Bech32Error::BStringMissingSeparator)));
        }

        // check that we accept strings with a separator character
        #[test]
        fn strings_with_separator_char_are_accepted(s in str_of_len_with_separator(MIN_BECH32_LENGTH, MAX_BECH32_LENGTH))
        {
            prop_assert!(matches!(reject_bstring_with_no_separator(&s), Ok(())));
        }
    }
}
