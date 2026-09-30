//! Core internal algorithms for Bech32 encoding and decoding.
//!
//! This module contains the fundamental algorithms that power the Bech32 implementation,
//! including string parsing, checksum computation, bit conversion, and the main
//! encoding/decoding pipelines. These functions implement the mathematical and
//! algorithmic core of the BIP-173 and BIP-350 specifications.
//!
//! # Key Algorithms
//!
//! - **String parsing**: Extracting and validating HRP and data parts from strings
//! - **Checksum computation**: Polynomial arithmetic for error detection
//! - **Bit conversion**: Converting between 8-bit and 5-bit representations
//! - **Character mapping**: Converting between values and Bech32 alphabet
//! - **Encoding pipeline**: Complete process from data to Bech32 string
//! - **Decoding pipeline**: Complete process from Bech32 string to data

use crate::constants::{
    CHECKSUM_LENGTH, DP_CHARSET, M, M0, MAX_DP_CHARSET_INDEX, MAX_REVERSE_CHARSET_INDEX,
    REVERSE_CHARSET, SEPARATOR,
};
use crate::data_checksum::Checksum;
use crate::data_part::DataPart;
use crate::data_part_with_checksum::DataPartWithChecksum;
use crate::hrp::HumanReadablePart;
use crate::validation::{reject_both_parts_too_long, reject_bstring_that_isnt_well_formed};
use crate::{Bech32Error, DecodedResult, DecodedResult5bit, Encoding};
use arbitrary_int::u5;
use std::io::Write;

/// Finds the position of the separator character in a Bech32 string.
///
/// Locates the rightmost '1' character which serves as the separator between
/// the human-readable part and the data part. Used internally during decoding
/// to split the string into components.
///
/// # Arguments
///
/// * `bstring` - The Bech32 string to search
///
/// # Returns
///
/// * `Ok(usize)` - Position of the separator character
/// * `Err(Bech32Error)` - If no separator is found
fn find_separator_position(bstring: &str) -> Result<usize, Bech32Error> {
    let result = bstring.rfind(SEPARATOR);
    result.ok_or(Bech32Error::BStringMissingSeparator)
}

/// Extracts and validates the human-readable part from a Bech32 string.
///
/// Splits the string at the separator position and creates a validated HRP.
/// The result is automatically converted to lowercase for consistency.
/// Used internally during the decoding process.
///
/// # Arguments
///
/// * `bstring` - The Bech32 string to parse
///
/// # Returns
///
/// * `Ok(HumanReadablePart)` - The validated HRP
/// * `Err(Bech32Error)` - If parsing or validation fails
fn extract_human_readable_part(bstring: &str) -> Result<HumanReadablePart, Bech32Error> {
    let pos = find_separator_position(bstring)?;
    HumanReadablePart::new(bstring.to_lowercase().split_at(pos).0)
}

/// Extracts the data part (including checksum) from a Bech32 string.
///
/// Takes everything after the separator character and converts it from
/// alphanumeric characters to the internal representation. Used internally
/// during decoding to separate data and checksum components.
///
/// # Arguments
///
/// * `bstring` - The Bech32 string to parse
///
/// # Returns
///
/// * `Ok(DataPartWithChecksum)` - The parsed data and checksum
/// * `Err(Bech32Error)` - If parsing or validation fails
fn extract_data_part(bstring: &str) -> Result<DataPartWithChecksum, Bech32Error> {
    let pos = find_separator_position(bstring)?;
    DataPartWithChecksum::from_alphanum(bstring.split_at(pos + 1).1.as_bytes())
}

/// Converts alphanumeric characters to 5-bit values using the Bech32 character set.
///
/// Maps characters from ASCII range to 5-bit values (0-31) using the reverse
/// character lookup table. Handles both uppercase and lowercase characters.
/// Used internally during decoding to convert string characters to numeric values.
///
/// # Arguments
///
/// * `dp` - Slice of ASCII bytes representing Bech32 characters
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - The converted 5-bit values
/// * `Err(Bech32Error)` - If invalid characters are encountered
#[allow(clippy::cast_sign_loss)]
pub(crate) fn map_from_charset(dp: &[u8]) -> Result<Vec<u8>, Bech32Error> {
    let mut result = Vec::from(dp);
    for c in &mut result {
        if *c > MAX_REVERSE_CHARSET_INDEX {
            return Err(Bech32Error::BStringValueOutOfRange);
        }
        let d = REVERSE_CHARSET[*c as usize];
        if d == -1 {
            return Err(Bech32Error::BStringInvalidCharacter);
        }
        // Regarding "allow(clippy::cast_sign_loss)": There is only one
        // value in REVERSE_CHARSET that is negative and that is accounted
        // for above before casting 'd' here.
        *c = d as u8;
    }
    Ok(result)
}

/// Expands the HRP for use in checksum computation.
///
/// Creates a representation of the HRP suitable for polynomial arithmetic by
/// separating high and low bits of each character. This follows the algorithm
/// described in BIP-173 for incorporating the HRP into checksum calculation.
///
/// The expansion creates: [`high_bits`] + [0] + [`low_bits`]
/// where `high_bits` are the upper 3 bits and `low_bits` are the lower 5 bits
/// of each character's ASCII value.
///
/// For example, for an HRP string "abc":
///
/// ```text
/// index char dec  binary
///    i0  'a'  97  0110 0001
///    i1  'b'  98  0110 0010
///    i2  'c'  99  0110 0011
/// ```
///
/// "expanding" turns it into a Vec<u8>:
///
/// ```text
/// index dec  binary
///    i0   3  0000 0011
///    i1   3  0000 0011
///    i2   3  0000 0011
///    i3   0  0000 0000
///    i4   1  0000 0001
///    i5   2  0000 0010
///    i6   3  0000 0011
/// ```
///
/// # Arguments
///
/// * `hrp` - The human-readable part to expand
///
/// # Returns
///
/// * `Vec<u8>` - The expanded representation
fn expand_hrp(hrp: &HumanReadablePart) -> Vec<u8> {
    let sz = hrp.as_ref().len();
    let mut result = vec![0; sz * 2 + 1];
    for item in hrp.as_ref().as_bytes().iter().enumerate() {
        let (i, c): (usize, &u8) = item;
        result[i] = *c >> 5;
        result[i + sz + 1] = *c & 0x1f;
    }
    result[sz] = 0;
    result
}

/// Computes the polynomial used in Bech32 checksum calculation.
///
/// Implements the core polynomial arithmetic as specified in BIP-173.
/// This function processes a sequence of 5-bit values and returns a
/// result used for checksum generation and validation.
///
/// The implementation uses a generator polynomial with coefficients designed
/// to provide optimal error detection properties for the Bech32 use case.
///
/// # Arguments
///
/// * `values` - Sequence of 5-bit values to process
///
/// # Returns
///
/// * `u32` - The computed polynomial result
fn polymod(values: &[u8]) -> u32 {
    let coefficients: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    for value in values {
        let top: u8 = (chk >> 25) as u8;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(*value);
        for item in coefficients.iter().enumerate() {
            let (i, c): (usize, &u32) = item;
            if (top >> i) & 1 == 1 {
                chk ^= *c;
            }
        }
    }
    chk
}

/// Internal helper for checksum verification with a specific constant.
fn verify_checksum_basis(hrp: &HumanReadablePart, dp: &DataPartWithChecksum, m: u32) -> bool {
    let mut values = expand_hrp(hrp);
    values.extend_from_slice(dp.data_part.as_bytes());
    values.extend_from_slice(dp.checksum.as_bytes());
    polymod(&values) == m
}

/// Verifies a checksum using the Bech32m constant.
///
/// Computes the polynomial over the entire string and checks if it equals
/// the Bech32m constant (0x2bc830a3). Used internally during decoding to
/// validate string integrity using the improved checksum algorithm.
///
/// # Arguments
///
/// * `hrp` - The human-readable part
/// * `dp` - The data part with checksum
///
/// # Returns
///
/// * `bool` - True if checksum is valid for Bech32m
fn verify_checksum(hrp: &HumanReadablePart, dp: &DataPartWithChecksum) -> bool {
    verify_checksum_basis(hrp, dp, M)
}

/// Verifies a checksum using the original Bech32 constant.
///
/// Computes the polynomial over the entire string and checks if it equals
/// the original Bech32 constant (1). Used internally during decoding to
/// validate legacy strings using the original checksum algorithm.
///
/// # Arguments
///
/// * `hrp` - The human-readable part
/// * `dp` - The data part with checksum
///
/// # Returns
///
/// * `bool` - True if checksum is valid for original Bech32
fn verify_checksum_using_original_constant(
    hrp: &HumanReadablePart,
    dp: &DataPartWithChecksum,
) -> bool {
    verify_checksum_basis(hrp, dp, M0)
}

/// Converts 5-bit values to their corresponding Bech32 characters.
///
/// Maps numeric values (0-31) to the Bech32 alphabet characters using the
/// character set lookup table. Used internally during encoding to convert
/// computed values to their string representation.
///
/// # Arguments
///
/// * `v` - Slice of 5-bit values to convert
///
/// # Returns
///
/// * `Ok(String)` - The corresponding Bech32 characters
/// * `Err(Bech32Error)` - If any values are invalid
fn map_to_charset(v: &[u8]) -> Result<String, Bech32Error> {
    let mut buf = String::with_capacity(v.len());
    for c in v {
        if *c > MAX_DP_CHARSET_INDEX {
            return Err(Bech32Error::BStringInvalidCharacter);
        }
        buf.push(DP_CHARSET[*c as usize] as char);
    }
    Ok(buf)
}

/// Internal helper for checksum creation with a specific constant.
fn create_checksum_basis(
    hrp: &HumanReadablePart,
    dp: &DataPart,
    m: u32,
) -> Result<Checksum, Bech32Error> {
    let mut expanded = expand_hrp(hrp);
    expanded.extend_from_slice(dp.as_bytes());
    expanded.extend_from_slice(&[0; CHECKSUM_LENGTH]);
    let p = polymod(&expanded);
    let pmod = p ^ m;
    let mut checksum_data = [0u8; CHECKSUM_LENGTH];
    let mut i = 0;
    while i < CHECKSUM_LENGTH {
        checksum_data[i] = ((pmod >> (5 * (5 - i))) & 31u32) as u8;
        i += 1;
    }
    Checksum::new(&checksum_data)
}

/// Creates a checksum using the Bech32m constant.
///
/// Computes the polynomial over HRP and data, then generates the 6-character
/// checksum. Used internally during encoding with the improved Bech32m algorithm.
///
/// # Arguments
///
/// * `hrp` - The human-readable part
/// * `dp` - The data part
///
/// # Returns
///
/// * `Ok(Checksum)` - The computed checksum
/// * `Err(Bech32Error)` - If computation fails
fn create_checksum(hrp: &HumanReadablePart, dp: &DataPart) -> Result<Checksum, Bech32Error> {
    create_checksum_basis(hrp, dp, M)
}

/// Creates a checksum using the original Bech32 constant.
///
/// Computes the polynomial over HRP and data using the original constant (1), then
/// generates the 6-character checksum.
/// Used internally for compatibility with legacy Bech32 encoding when explicitly
/// requested.
///
/// # Arguments
///
/// * `hrp` - The human-readable part
/// * `dp` - The data part
///
/// # Returns
///
/// * `Ok(Checksum)` - The computed checksum
/// * `Err(Bech32Error)` - If computation fails
#[cfg_attr(not(test), allow(dead_code))]
fn create_checksum_using_original_constant(
    hrp: &HumanReadablePart,
    dp: &DataPart,
) -> Result<Checksum, Bech32Error> {
    create_checksum_basis(hrp, dp, M0)
}

/// Converts between different bit representations with padding control.
///
/// Generic bit conversion function that can convert between any bit sizes
/// with configurable padding behavior. Used internally for 8-bit to 5-bit
/// conversions during encoding and 5-bit to 8-bit during decoding.
///
/// # Arguments
///
/// * `out` - Output writer for converted data
/// * `input` - Input data to convert
/// * `from_bits` - Source bit size per value
/// * `to_bits` - Target bit size per value
/// * `pad` - Whether to pad incomplete final groups
///
/// # Returns
///
/// * `Ok(())` - If conversion succeeds
/// * `Err(Bech32Error)` - If conversion fails due to invalid padding
#[allow(clippy::cast_possible_truncation)]
fn convert_bits(
    out: &mut impl Write,
    input: &[u8],
    from_bits: u8,
    to_bits: u8,
    pad: bool,
) -> Result<(), Bech32Error> {
    let mut acc = 0;
    let mut bits = 0;
    let maxv = (1 << to_bits) - 1;
    let max_acc = (1 << (from_bits + to_bits - 1)) - 1;

    for &value in input {
        acc = ((acc << from_bits) | (value as usize)) & max_acc;
        bits += from_bits;
        while bits >= to_bits {
            bits -= to_bits;
            out.write_all(&[((acc >> bits) & maxv) as u8])?;
        }
    }

    if pad {
        if bits > 0 {
            out.write_all(&[((acc << (to_bits - bits)) & maxv) as u8])?;
        }
    } else if bits >= from_bits || ((acc << (to_bits - bits)) & maxv) != 0 {
        return Err(Bech32Error::BitConversionError);
    }

    Ok(())
}

/// Converts 8-bit bytes to 5-bit values with padding.
///
/// Expands user data from standard 8-bit representation to 5-bit values
/// suitable for Bech32 encoding. Adds padding as needed to complete the
/// final 5-bit group. Used internally during the encoding process.
///
/// # Arguments
///
/// * `out` - Output writer for 5-bit values
/// * `input` - Input 8-bit data
///
/// # Returns
///
/// * `Ok(())` - If conversion succeeds
/// * `Err(Bech32Error)` - If I/O errors occur
pub(crate) fn expand_bits(
    out: &mut impl Write,
    input: impl AsRef<[u8]>,
) -> Result<(), Bech32Error> {
    convert_bits(out, input.as_ref(), 8, 5, true)
}

/// Converts 5-bit values back to 8-bit bytes without padding.
///
/// Compresses 5-bit Bech32 values back to standard 8-bit representation,
/// validating that padding bits are zero. Used internally during the
/// decoding process to recover original user data.
///
/// # Arguments
///
/// * `out` - Output writer for 8-bit data
/// * `input` - Input 5-bit values
///
/// # Returns
///
/// * `Ok(())` - If conversion succeeds
/// * `Err(Bech32Error)` - If padding validation fails
pub(crate) fn compress_bits(
    out: &mut impl Write,
    input: impl AsRef<[u8]>,
) -> Result<(), Bech32Error> {
    convert_bits(out, input.as_ref(), 5, 8, false)
}

/// Generic encoding function.
///
/// Provides the core encoding pipeline. This function accepts data
/// to be encoded as 8-bit unsigned integers.
///
/// # Arguments
///
/// * `hrp_str` - Human-readable part string
/// * `dp` - Data to encode
///
/// # Returns
///
/// * `Ok(String)` - The encoded Bech32 string
/// * `Err(Bech32Error)` - If encoding fails
pub(crate) fn encode(
    hrp_str: impl AsRef<str>,
    dp: impl AsRef<[u8]>,
) -> Result<String, Bech32Error> {
    let hrp = HumanReadablePart::new(hrp_str.as_ref())?;
    let dp = DataPart::from_bytes(dp.as_ref())?;
    reject_both_parts_too_long(&hrp, &dp)?;
    let checksum = create_checksum(&hrp, &dp)?;
    let result = format!(
        "{}{}{}{}",
        hrp.as_ref(),
        SEPARATOR,
        map_to_charset(dp.as_bytes())?,
        map_to_charset(checksum.as_bytes())?
    );
    Ok(result)
}

/// Generic encoding function.
///
/// Provides the core encoding pipeline. This function accepts data
/// to be encoded as 5-bit unsigned integers.
///
/// # Arguments
///
/// * `hrp_str` - Human-readable part string
/// * `dp` - Data to encode
///
/// # Returns
///
/// * `Ok(String)` - The encoded Bech32 string
/// * `Err(Bech32Error)` - If encoding fails
pub(crate) fn encode_5bit(
    hrp_str: impl AsRef<str>,
    dp: impl AsRef<[u5]>,
) -> Result<String, Bech32Error> {
    let hrp = HumanReadablePart::new(hrp_str.as_ref())?;
    let dp = DataPart::from_u5(dp.as_ref());
    reject_both_parts_too_long(&hrp, &dp)?;
    let checksum = create_checksum(&hrp, &dp)?;
    let result = format!(
        "{}{}{}{}",
        hrp.as_ref(),
        SEPARATOR,
        map_to_charset(dp.as_bytes())?,
        map_to_charset(checksum.as_bytes())?
    );
    Ok(result)
}

/// Encodes data using the original Bech32 constant with 5-bit values.
///
/// For internal use when legacy Bech32 encoding is required with 5-bit input.
/// Uses the original checksum constant (1) instead of the improved Bech32m
/// constant.
///
/// # Arguments
///
/// * `hrp_str` - Human-readable part string
/// * `dp` - 5-bit data values
///
/// # Returns
///
/// * `Ok(String)` - The encoded Bech32 string
/// * `Err(Bech32Error)` - If encoding fails
#[cfg_attr(not(test), allow(dead_code))]
fn encode_5bit_using_original_constant(
    hrp_str: impl AsRef<str>,
    dp: impl AsRef<[u8]>,
) -> Result<String, Bech32Error> {
    let hrp = HumanReadablePart::new(hrp_str.as_ref())?;
    let dp = DataPart::new(dp.as_ref())?;

    reject_both_parts_too_long(&hrp, &dp)?;

    let checksum = create_checksum_using_original_constant(&hrp, &dp)?;

    let result = format!(
        "{}{}{}{}",
        hrp.as_ref(),
        SEPARATOR,
        map_to_charset(dp.as_bytes())?,
        map_to_charset(checksum.as_bytes())?
    );
    Ok(result)
}

/// Converts a vector of u8 values to u5 values with validation.
///
/// This function takes a vector of 8-bit unsigned integers and converts each
/// to a 5-bit unsigned integer. All input values must be in the range 0-31
/// (the valid range for 5-bit integers).
///
/// # Arguments
///
/// * `input` - A vector of u8 values to convert
///
/// # Returns
///
/// * `Ok(Vec<u5>)` - Successfully converted vector if all values are ≤ 31
/// * `Err(Bech32Error)` - Error if any input value exceeds 31
///
fn u8_to_u5_checked(input: Vec<u8>) -> Result<Vec<u5>, Bech32Error> {
    input
        .into_iter()
        .map(|byte| {
            if byte <= 31 {
                Ok(u5::new(byte))
            } else {
                Err(Bech32Error::BitConversionError)
            }
        })
        .collect()
}

/// Generic decoding function.
///
/// Provides the core decoding pipeline. Handles checksum
/// validation for both Bech32 and Bech32m variants
/// automatically. This function returns the decoded data
/// as 8-bit unsigned integers.
///
/// # Arguments
///
/// * `bstring` - Bech32 string to decode
///
/// # Returns
///
/// * `Ok(DecodedResult)` - The decoded data with encoding type
/// * `Err(Bech32Error)` - If decoding fails
pub(crate) fn decode(bstring: impl AsRef<str>) -> Result<DecodedResult, Bech32Error> {
    let bstring_ref = bstring.as_ref();

    reject_bstring_that_isnt_well_formed(bstring_ref)?;

    let hrp = extract_human_readable_part(bstring_ref)?;

    let dp = extract_data_part(bstring_ref)?;

    let encoding;
    if verify_checksum(&hrp, &dp) {
        encoding = Encoding::Bech32m;
    } else if verify_checksum_using_original_constant(&hrp, &dp) {
        encoding = Encoding::Bech32;
    } else {
        return Err(Bech32Error::InvalidChecksum);
    }

    let res = DecodedResult {
        encoding,
        hrp: hrp.as_ref().to_string(),
        dp: DataPart::to_bytes(&dp.data_part)?,
    };
    Ok(res)
}

/// Generic decoding function.
///
/// Provides the core decoding pipeline. Handles checksum
/// validation for both Bech32 and Bech32m variants
/// automatically. This function returns the decoded data
/// as 5-bit unsigned integers.
///
/// # Arguments
///
/// * `bstring` - Bech32 string to decode
///
/// # Returns
///
/// * `Ok(DecodedResult5bit)` - The decoded data with encoding type
/// * `Err(Bech32Error)` - If decoding fails
pub(crate) fn decode_5bit(bstring: impl AsRef<str>) -> Result<DecodedResult5bit, Bech32Error> {
    let bstring_ref = bstring.as_ref();

    reject_bstring_that_isnt_well_formed(bstring_ref)?;

    let hrp = extract_human_readable_part(bstring_ref)?;

    let dp = extract_data_part(bstring_ref)?;

    let encoding;
    if verify_checksum(&hrp, &dp) {
        encoding = Encoding::Bech32m;
    } else if verify_checksum_using_original_constant(&hrp, &dp) {
        encoding = Encoding::Bech32;
    } else {
        return Err(Bech32Error::InvalidChecksum);
    }

    let res = DecodedResult5bit {
        encoding,
        hrp: hrp.as_ref().to_string(),
        dp: u8_to_u5_checked(Vec::from(dp.data_part.as_bytes()))?,
    };
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // check that we can find the position of the separator character
    fn ensure_find_separator_position() {
        let result = find_separator_position(&String::from("ab1cd"));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 2);

        let result = find_separator_position(&String::from("abc1def1lalala"));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 7);
    }

    #[test]
    fn find_separator_position_error() {
        assert!(matches!(
            find_separator_position(&String::from("lalalalalala")),
            Err(Bech32Error::BStringMissingSeparator)
        ));
    }

    #[test]
    // check that we can extract the human-readable part of the string
    fn ensure_extract_human_readable_part() {
        assert_eq!("ab", extract_human_readable_part("ab1").unwrap().as_ref());
        assert_eq!("ab", extract_human_readable_part("ab1cd").unwrap().as_ref());
    }

    #[test]
    // check that we can extract the data part of the string
    fn ensure_extract_data_part() {
        let bs = String::from("ab1cdcdcd");
        let dp = extract_data_part(&bs).unwrap();

        assert_eq!(0, dp.data_part.len());

        let bs = String::from("ab1cdcdcdcd");
        let dp = extract_data_part(&bs).unwrap();

        assert_eq!(2, dp.data_part.len());
        assert_eq!(24, dp.data_part.as_bytes()[0]); // REVERSE_CHARSET['c'] == 24
        assert_eq!(13, dp.data_part.as_bytes()[1]); // REVERSE_CHARSET['d'] == 13

        let bs = String::from("1cdcdcdcd");
        let dp = extract_data_part(&bs).unwrap();

        assert_eq!(2, dp.data_part.len());
        assert_eq!(24, dp.data_part.as_bytes()[0]);
        assert_eq!(13, dp.data_part.as_bytes()[1]);
    }

    #[test]
    // check that we can expand the hrp
    fn ensure_expand_hrp() {
        let hrp = HumanReadablePart::new("ABC").unwrap();
        let expanded = expand_hrp(&hrp);

        assert_eq!(7, expanded.len());
        assert_eq!(b'\x03', expanded[0]);
        assert_eq!(b'\x03', expanded[1]);
        assert_eq!(b'\x03', expanded[2]);
        assert_eq!(b'\x00', expanded[3]);
        assert_eq!(b'\x01', expanded[4]);
        assert_eq!(b'\x02', expanded[5]);
        assert_eq!(b'\x03', expanded[6]);

        let hrp = HumanReadablePart::new("abc").unwrap();
        let expanded = expand_hrp(&hrp);

        assert_eq!(7, expanded.len());
        assert_eq!(b'\x03', expanded[0]);
        assert_eq!(b'\x03', expanded[1]);
        assert_eq!(b'\x03', expanded[2]);
        assert_eq!(b'\x00', expanded[3]);
        assert_eq!(b'\x01', expanded[4]);
        assert_eq!(b'\x02', expanded[5]);
        assert_eq!(b'\x03', expanded[6]);
    }

    #[test]
    // check the polymod method
    fn ensure_polymod() {
        let hrp = HumanReadablePart::new("A").unwrap();
        let expanded = expand_hrp(&hrp);
        let p = polymod(&expanded);
        assert_eq!(35841, p);

        let hrp = HumanReadablePart::new("a").unwrap();
        let expanded = expand_hrp(&hrp);
        let p = polymod(&expanded);
        assert_eq!(35841, p);

        let hrp = HumanReadablePart::new("B").unwrap();
        let expanded = expand_hrp(&hrp);
        let p = polymod(&expanded);
        assert_eq!(35842, p);

        let hrp = HumanReadablePart::new("qwerty").unwrap();
        let expanded = expand_hrp(&hrp);
        let p = polymod(&expanded);
        assert_eq!(448_484_437, p);
    }

    #[test]
    // check the verifyChecksum method
    fn verify_checksum_good() {
        let bstring = String::from("a1lqfn3a");
        let hrp = extract_human_readable_part(&bstring).unwrap();
        let dp = extract_data_part(&bstring).unwrap();
        assert!(verify_checksum(&hrp, &dp));

        let bstring = String::from("A1LQFN3A");
        let hrp = extract_human_readable_part(&bstring).unwrap();
        let dp = extract_data_part(&bstring).unwrap();
        assert!(verify_checksum(&hrp, &dp));

        let bstring = String::from("abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx");
        let hrp = extract_human_readable_part(&bstring).unwrap();
        let dp = extract_data_part(&bstring).unwrap();
        assert!(verify_checksum(&hrp, &dp));

        let bstring = String::from("split1checkupstagehandshakeupstreamerranterredcaperredlc445v");
        let hrp = extract_human_readable_part(&bstring).unwrap();
        let dp = extract_data_part(&bstring).unwrap();
        assert!(verify_checksum(&hrp, &dp));

        let bstring = String::from("an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6");
        let hrp = extract_human_readable_part(&bstring).unwrap();
        let dp = extract_data_part(&bstring).unwrap();
        assert!(verify_checksum(&hrp, &dp));

        let bstring = String::from("11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8");
        let hrp = extract_human_readable_part(&bstring).unwrap();
        let dp = extract_data_part(&bstring).unwrap();
        assert!(verify_checksum(&hrp, &dp));
    }

    #[test]
    // check the verifyChecksum method
    // these are simply the "good" tests from above with a single character changed
    fn verify_checksum_bad() {
        let bstring = String::from("a1lqfn33");
        let hrp = extract_human_readable_part(&bstring).unwrap();
        let dp = extract_data_part(&bstring).unwrap();
        assert!(!verify_checksum(&hrp, &dp));

        let bstring = String::from("A1LQFN33");
        let hrp = extract_human_readable_part(&bstring).unwrap();
        let dp = extract_data_part(&bstring).unwrap();
        assert!(!verify_checksum(&hrp, &dp));

        let bstring = String::from("abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryy");
        let hrp = extract_human_readable_part(&bstring).unwrap();
        let dp = extract_data_part(&bstring).unwrap();
        assert!(!verify_checksum(&hrp, &dp));

        let bstring = String::from("split1checkupstagehandshakeupstreamerranterredcaperredlc445s");
        let hrp = extract_human_readable_part(&bstring).unwrap();
        let dp = extract_data_part(&bstring).unwrap();
        assert!(!verify_checksum(&hrp, &dp));

        let bstring = String::from("an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg7");
        let hrp = extract_human_readable_part(&bstring).unwrap();
        let dp = extract_data_part(&bstring).unwrap();
        assert!(!verify_checksum(&hrp, &dp));

        let bstring = String::from("11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsrc");
        let hrp = extract_human_readable_part(&bstring).unwrap();
        let dp = extract_data_part(&bstring).unwrap();
        assert!(!verify_checksum(&hrp, &dp));
    }

    #[test]
    fn ensure_map_to_charset() {
        let d = &[0x1f, 0x00, 0x09, 0x13, 0x11, 0x1d];

        let s: String = map_to_charset(d).unwrap();

        assert_eq!("lqfn3a", s);

        let d = &[
            0x1f, 0x00, 0x09, 0x13, 0x11, 0x1d, 0x1f, 0x00, 0x09, 0x13, 0x11, 0x1d,
        ];

        let s: String = map_to_charset(d).unwrap();

        assert_eq!("lqfn3alqfn3a", s);
    }

    #[test]
    fn ensure_create_checksum() {
        let hrp = HumanReadablePart::new("a").unwrap();
        let dp = Vec::from("".as_bytes());
        let dp = DataPart::new(dp.as_ref()).unwrap();
        let checksum = create_checksum(&hrp, &dp).unwrap();
        let checksum_bytes = checksum.as_bytes();

        assert_eq!(0x1f, checksum_bytes[0]);
        assert_eq!(0x00, checksum_bytes[1]);
        assert_eq!(0x09, checksum_bytes[2]);
        assert_eq!(0x13, checksum_bytes[3]);
        assert_eq!(0x11, checksum_bytes[4]);
        assert_eq!(0x1d, checksum_bytes[5]);

        let hrp = HumanReadablePart::new("abcdef").unwrap();
        let dp = vec![
            b'l', b'7', b'a', b'u', b'm', b'6', b'e', b'c', b'h', b'k', b'4', b'5', b'n', b'j',
            b'3', b's', b'0', b'w', b'd', b'v', b't', b'2', b'f', b'g', b'8', b'x', b'9', b'y',
            b'r', b'z', b'p', b'q',
        ];

        let dp = DataPart::from_alphanum(dp.as_ref()).unwrap();
        let checksum = create_checksum(&hrp, &dp).unwrap();
        let checksum_bytes = checksum.as_bytes();

        assert_eq!(0x02, checksum_bytes[0]);
        assert_eq!(0x0d, checksum_bytes[1]);
        assert_eq!(0x11, checksum_bytes[2]);
        assert_eq!(0x03, checksum_bytes[3]);
        assert_eq!(0x04, checksum_bytes[4]);
        assert_eq!(0x06, checksum_bytes[5]);

        let hrp = HumanReadablePart::new("split").unwrap();
        let dp = vec![
            b'c', b'h', b'e', b'c', b'k', b'u', b'p', b's', b't', b'a', b'g', b'e', b'h', b'a',
            b'n', b'd', b's', b'h', b'a', b'k', b'e', b'u', b'p', b's', b't', b'r', b'e', b'a',
            b'm', b'e', b'r', b'r', b'a', b'n', b't', b'e', b'r', b'r', b'e', b'd', b'c', b'a',
            b'p', b'e', b'r', b'r', b'e', b'd',
        ];

        let dp = DataPart::from_alphanum(dp.as_ref()).unwrap();
        let checksum = create_checksum(&hrp, &dp).unwrap();
        let checksum_bytes = checksum.as_bytes();

        assert_eq!(0x1f, checksum_bytes[0]);
        assert_eq!(0x18, checksum_bytes[1]);
        assert_eq!(0x15, checksum_bytes[2]);
        assert_eq!(0x15, checksum_bytes[3]);
        assert_eq!(0x14, checksum_bytes[4]);
        assert_eq!(0x0c, checksum_bytes[5]);

        let hrp = HumanReadablePart::new(
            "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber1",
        )
        .unwrap();
        let dp = vec![];

        let dp = DataPart::from_alphanum(dp.as_ref()).unwrap();
        let checksum = create_checksum(&hrp, &dp).unwrap();
        let checksum_bytes = checksum.as_bytes();

        assert_eq!(0x10, checksum_bytes[0]);
        assert_eq!(0x08, checksum_bytes[1]);
        assert_eq!(0x1e, checksum_bytes[2]);
        assert_eq!(0x17, checksum_bytes[3]);
        assert_eq!(0x08, checksum_bytes[4]);
        assert_eq!(0x1a, checksum_bytes[5]);

        let hrp = HumanReadablePart::new("1").unwrap();
        let dp = vec![
            b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l',
            b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l',
            b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l',
            b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l',
            b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l',
            b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l',
        ];

        let dp = DataPart::from_alphanum(dp.as_ref()).unwrap();
        let checksum = create_checksum(&hrp, &dp).unwrap();
        let checksum_bytes = checksum.as_bytes();

        assert_eq!(0x1f, checksum_bytes[0]);
        assert_eq!(0x1c, checksum_bytes[1]);
        assert_eq!(0x0d, checksum_bytes[2]);
        assert_eq!(0x10, checksum_bytes[3]);
        assert_eq!(0x03, checksum_bytes[4]);
        assert_eq!(0x07, checksum_bytes[5]);
    }

    #[rustfmt::skip]
    #[test]
    fn test_convert_bits() {
        let mut out = Vec::new();
        let input = &[0b0001, 0b0010, 0b0011, 0b0100];
        let result = convert_bits(&mut out, input, 4, 8, true);
        assert!(result.is_ok());
        assert_eq!(out, &[0b0001_0010, 0b0011_0100]);

        let mut out = Vec::new();
        let input = &[0b0001, 0b0010, 0b0011, 0b0100];
        let result = convert_bits(&mut out, input, 4, 8, false);
        assert!(result.is_ok());
        assert_eq!(out, &[0b0001_0010, 0b0011_0100]);

        let mut out = Vec::new();
        let input = &[0b1111, 0b1111, 0b1111, 0b1111];
        let result = convert_bits(&mut out, input, 4, 8, false);
        assert!(result.is_ok());
        assert_eq!(out, &[0b1111_1111, 0b1111_1111]);

        let mut out = Vec::new();
        let input = &[0b1111, 0b1111, 0b1111, 0b1111];
        let result = convert_bits(&mut out, input, 4, 5, true);
        assert!(result.is_ok());
        assert_eq!(out, &[0b1_1111, 0b1_1111, 0b1_1111, 0b1_0000]);

        let mut out = Vec::new();
        let input = &[0b1111, 0b1111, 0b1111, 0b1111];
        let result = convert_bits(&mut out, input, 4, 5, false);
        assert!(result.is_err());

        let mut out = Vec::new();
        let input = &[0b0000_0001, 0b0000_0010, 0b0000_0011, 0b0000_0100];
        let result = convert_bits(&mut out, input, 8, 4, true);
        assert!(result.is_ok());
        assert_eq!(out, &[0b0000, 0b0001, 0b0000, 0b0010, 0b0000, 0b0011, 0b0000, 0b0100]);


        let mut out = Vec::new();
        let input = &[0b0000_0001, 0b0000_0010, 0b0000_0011, 0b0000_0100];
        let result = convert_bits(&mut out, input, 8, 5, true);
        assert!(result.is_ok());
        assert_eq!(out, &[0b0_0000, 0b0_0100, 0b0_0001, 0b0_0000, 0b0_0110, 0b0_0001, 0b0_0000]);

        // the following several examples label the input and output bit indexes with
        // letters to illustrate how they convert

        let mut out = Vec::new();
        let input =
               &[0b0000_0000, 0b0000_0001, 0b0000_1010, 0b0001_0100, 0b0001_1110, ]; // 0, 1, 10, 20, 30
        // index:  abcd_efgh    ijkl_mnop    qrst_uvwx    yzab_cdef    ghij_klmn
        let result = convert_bits(&mut out, input, 8, 5, true);
        assert!(result.is_ok());
        assert_eq!(out, &[0b0_0000, 0b0_0000, 0b0_0000, 0b1_0000, 0b1_0100, 0b0_0101, 0b0_0000, 0b1_1110, ]);
        //           index: a_bcde    f_ghij    k_lmno    p_qrst    u_vwxy    z_abcd    e_fghi    j_klmn

        let mut out = Vec::new();
        let input =
               &[0b0_0000, 0b0_0000, 0b0_0000, 0b1_0000, 0b1_0100, 0b0_0101, 0b0_0000, 0b1_1110, ];
        //  index: a_bcde    f_ghij    k_lmno    p_qrst    u_vwxy    z_abcd    e_fghi    j_klmn
        let result = convert_bits(&mut out, input, 5, 8, false);
        assert!(result.is_ok());
        assert_eq!(out, &[0b0000_0000, 0b0000_0001, 0b0000_1010, 0b0001_0100, 0b0001_1110, ]);
        //          index:  abcd_efgh    ijkl_mnop    qrst_uvwx    yzab_cdef    ghij_klmn


        let mut out = Vec::new();
        let input =
               &[0b0010_0011, 0b0010_1101, 0b0110_0100, 0b1111_1111, ]; // 35, 45, 150, 255
        // index:  abcd_efgh    ijkl_mnop    qrst_uvwx    yzab_cdef
        let result = convert_bits(&mut out, input, 8, 5, true);
        assert!(result.is_ok());
        assert_eq!(out, &[0b0_0100, 0b0_1100, 0b1_0110, 0b1_0110, 0b0_1001, 0b1_1111, 0b1_1000, ]);
        //           index: a_bcde    f_ghij    k_lmno    p_qrst    u_vwxy    z_abcd    e_f


        let mut out = Vec::new();
        let input =
               &[0b0_0100, 0b0_1100, 0b1_0110, 0b1_0110, 0b0_1001, 0b1_1111, 0b1_1000, ];
        //  index: a_bcde    f_ghij    k_lmno    p_qrst    u_vwxy    z_abcd    e_fghi
        let result = convert_bits(&mut out, input, 5, 8, false);
        assert!(result.is_ok());
        assert_eq!(out, &[0b0010_0011, 0b0010_1101, 0b0110_0100, 0b1111_1111 ]);
        //          index:  abcd_efgh    ijkl_mnop    qrst_uvwx    yzab_cdef

    }

    #[test]
    fn test_convert_bits_for_hash() {
        let orig_hash = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30";
        let expected_decoded_hash_data = &[
            207, 199, 116, 155, 150, 246, 59, 211, 28, 60, 66, 181, 196, 113, 191, 117, 104, 20, 5,
            62, 132, 124, 16, 243, 235, 0, 52, 23, 188, 82, 61, 48,
        ];

        let hash_data = hex::decode(orig_hash).unwrap();
        assert_eq!(hash_data, expected_decoded_hash_data);

        // convert from 8 bits to 5 bits

        let mut five_bit_data = Vec::new();
        let expected_five_bit_data = &[
            25, 31, 3, 23, 9, 6, 28, 22, 30, 24, 29, 29, 6, 7, 1, 28, 8, 10, 26, 28, 8, 28, 13, 31,
            14, 21, 20, 1, 8, 1, 9, 30, 16, 17, 30, 1, 1, 28, 31, 11, 0, 0, 26, 1, 15, 15, 2, 18,
            7, 20, 24, 0,
        ];

        let result = convert_bits(&mut five_bit_data, &hash_data, 8, 5, true);
        assert!(result.is_ok());
        assert_eq!(five_bit_data, expected_five_bit_data);

        // convert from 5 bits back to 8 bits and compare

        let mut eight_bit_data = Vec::new();

        let result = convert_bits(&mut eight_bit_data, &five_bit_data, 5, 8, false);
        assert!(result.is_ok());
        assert_eq!(eight_bit_data, expected_decoded_hash_data);
        assert_eq!(hex::encode(eight_bit_data), orig_hash);
    }

    #[test]
    // check that we can lowercase strings
    fn ensure_lowercase_strings() {
        assert_eq!("abc", String::from("ABC").to_lowercase());
        assert_eq!("abc", String::from("AbC").to_lowercase());
        assert_eq!("123", String::from("123").to_lowercase());
    }

    #[test]
    fn test_expand_and_compress_bits() {
        // Test with simple data
        let original_data = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];

        // First expand the bits (8->5)
        let mut expanded = Vec::new();
        let result = expand_bits(&mut expanded, &original_data);
        assert!(result.is_ok());

        // Then compress them back (5->8)
        let mut compressed = Vec::new();
        let result = compress_bits(&mut compressed, &expanded);
        assert!(result.is_ok());

        // Verify the round trip worked correctly
        assert_eq!(original_data, compressed);
    }

    #[test]
    fn test_expand_bits_empty_input() {
        let mut output = Vec::new();
        let result = expand_bits(&mut output, []);
        assert!(result.is_ok());
        assert!(output.is_empty());
    }

    #[test]
    fn test_compress_bits_empty_input() {
        let mut output = Vec::new();
        let result = compress_bits(&mut output, []);
        assert!(result.is_ok());
        assert!(output.is_empty());
    }

    #[test]
    fn test_expand_bits_single_byte() {
        // Test expanding a single byte
        let mut output = Vec::new();
        let result = expand_bits(&mut output, [0xFF]);
        assert!(result.is_ok());
        assert_eq!(output, &[0x1F, 0x1C]);
    }

    #[test]
    fn test_compress_bits_partial_byte() {
        // This should fail because we can't compress 5 bits to 8 bits without padding
        // and there's only one 5-bit value which isn't enough to make a full byte
        let mut output = Vec::new();
        let result = compress_bits(&mut output, [0x1F]);
        assert!(result.is_err());
        assert!(matches!(result, Err(Bech32Error::BitConversionError)));
    }

    #[test]
    fn encode_using_original_constant_small_hrp_empty_data() {
        let result = encode_5bit_using_original_constant("a", []);
        let expected = "a12uel5l";

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected);
    }

    #[test]
    fn encode_using_original_constant_small_hrp_small_data() {
        let result = encode_5bit_using_original_constant("xyz", [1, 2, 3]);
        let expected = "xyz1pzr9dvupm";

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected);
    }
}

#[cfg(test)]
mod proptests {

    use crate::constants::{MAX_BECH32_LENGTH, MIN_BECH32_LENGTH, SEPARATOR};
    use crate::core::find_separator_position;
    use proptest::prelude::*;
    use rand::Rng;

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

    proptest! {
        // check that we can find the position of the separator character
        #[test]
        fn check_find_last_separator_position(mut s in str_of_len_numbers_lower(MIN_BECH32_LENGTH, MAX_BECH32_LENGTH))
        {
            // whatever s is, see if there is already a separator character within it
            let result = s.rfind(SEPARATOR);
            let pos: usize = result.unwrap_or_default();

            // if separator character is already at the end of the string, then inserting
            // another anywhere else won't test much, so let's skip to next test
            if pos+1 == s.len() {
                return Ok(());
            }

            // insert separator character at a known position between pos+1 and the end
            // of the string
            let pos2 = rand::rng().random_range(pos+1 .. s.len());
            s.insert(pos2, SEPARATOR);

            // call our function and verify
            let found_pos = find_separator_position(&s).unwrap();
            prop_assert_eq!(pos2, found_pos);
        }

    }
}
