#[cfg(test)]
mod proptests {
    use arbitrary_int::u5;
    use bech32_rust::*;
    use proptest::prelude::*;

    fn convert_u8_to_u5(input: Vec<u8>) -> Vec<u5> {
        input
            .into_iter()
            .map(u5::new) // This will panic if input element is > 31
            .collect()
    }

    fn str_of_len_valid_hrp_chars_only(min: usize, max: usize) -> impl Strategy<Value = String> {
        // these values correspond to MIN_HRP_CHAR_VALUE and MAX_HRP_CHAR_VALUE
        prop::string::string_regex(&format!("[\x21-\x7e]{{{min},{max}}}")).unwrap()
    }

    fn vec_of_len_valid_dp_vals_only(min: usize, max: usize) -> impl Strategy<Value = Vec<u8>> {
        // these values correspond to u8s within VALID_DP_CHARSET_SIZE range
        prop::collection::vec(0..=MAX_DP_CHARSET_INDEX, min..=max)
    }

    prop_compose! {
    fn hrp_and_dp_vals()
        (hrp in str_of_len_valid_hrp_chars_only(MIN_HRP_LENGTH, MAX_HRP_LENGTH))
        (dp in vec_of_len_valid_dp_vals_only (MIN_DP_LENGTH, max_dp_length(hrp.len())), hrp in Just(hrp))
        -> (String, Vec<u8>) {
            (hrp, dp)
        }
    }

    prop_compose! {
    fn hrp_and_dp_vals_5bit()
        (hrp in str_of_len_valid_hrp_chars_only(MIN_HRP_LENGTH, MAX_HRP_LENGTH))
        (dp in vec_of_len_valid_dp_vals_only (MIN_DP_LENGTH, max_dp_length_5bit(hrp.len())), hrp in Just(hrp))
        -> (String, Vec<u8>) {
            (hrp, dp)
        }
    }

    proptest! {

        #[test]
        fn check_encode_then_decode_produces_initial_data((hrp, dp) in hrp_and_dp_vals())
        {
            let bstr = encode(&hrp, &dp).unwrap();
            let result = decode(&bstr).unwrap();

            prop_assert_eq!(hrp.to_lowercase(), result.hrp);
            prop_assert_eq!(dp, result.dp);
        }

        #[test]
        fn check_encode_then_decode_produces_initial_data_5bit((hrp, dp) in hrp_and_dp_vals())
        {
            let v = convert_u8_to_u5(dp.clone());
            let bstr = encode_5bit(&hrp, &v).unwrap();
            let result = decode_5bit(&bstr).unwrap();

            prop_assert_eq!(hrp.to_lowercase(), result.hrp);
            prop_assert_eq!(v, result.dp);
        }

    }
}
