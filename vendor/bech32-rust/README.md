# bech32-rust

This is a rust implementation of "Bech32:" a checksummed base32 data
encoding format. It is primarily used as a new bitcoin address format
specified by [BIP 0173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki). 

## Building bech32-rust

To build bech32-rust, you will need:

* cargo
* rustc

```
cargo build
```

You can also run all the tests:

```
cargo test
```

### Installing prerequisites

If the above doesn't work...

## Usage Examples

### Encoding Example

```rust
use bech32_rust::encode;

fn encode_example() {
    let bstr = encode("hello", &vec![14, 15, 3, 31, 13]);

    assert!(bstr.is_ok());
    assert_eq!(bstr.unwrap(), "hello1w0rldjn365x");
    // ... "hello" + Bech32.separator ("1") + encoded data ("w0rld") + 6 char checksum ("jn365x")
}
```

### Decoding Example

```rust
use bech32_rust::decode;

fn decode_example() {
    let bstr = String::from("hello1w0rldjn365x");
    let decoded_result = decode(&bstr).unwrap();
    
    assert_eq!(String::from("hello"), decoded_result.hrp);
    assert_eq!(b'\x0e', decoded_result.dp[0]);
    assert_eq!(Encoding::Bech32m, decoded_result.encoding);
}
```

For more examples, see...

## Regarding bech32 checksums

The Bech32 data encoding format was first proposed by Pieter Wuille in early 2017 in
[BIP 0173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki). Later, in November 2019, Pieter published
some research that a constant used in the bech32 checksum algorithm (value = 1) may not be
optimal for the error detecting properties of bech32. In February 2021, Pieter published
[BIP 0350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki) reporting that "exhaustive analysis" showed the best possible constant value is
0x2bc830a3. This improved variant of Bech32 is called "Bech32m".

When decoding a possible bech32 encoded string, bech32-rust returns an enum value showing whether bech32m or bech32
was used to encode. This can be seen in the examples above.

When encoding data, bech32-rust defaults to using the new constant value of 0x2bc830a3. If the original constant value
of 1 is desired, then the following function may be used:

### Usage Example

```rust
use bech32_rust::encode;

fn using_original_constant_example() {
    let bstr = encode_using_original_constant("hello", &vec![14, 15, 3, 31, 13]);

    assert!(bstr.is_ok());
    assert_eq!(bstr.unwrap(), "hello1w0rld80pk3y");
    // ... "hello" + Bech32.separator ("1") + encoded data ("w0rld") + 6 char checksum ("80pk3y")

    let decoded_result = decode(&bstring).unwrap();
    assert_eq!(Encoding::Bech32, decoded_result.encoding);
}
```

### TODO: Add motivation section

Why are we creating this crate? Mainly to have a readable easy to understand implementation of bech32. There are other crates, but ours is the best.
