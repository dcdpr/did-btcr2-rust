//! Optimized Sparse Merkle Tree implementation.
//!
//! This is the core of the implementation that is shared across supported backends. It implements
//! the major algorithms for node insertion, proof construction, and Mermaid diagram rendering.
//! Supporting types and functions are also found here.

use bincode::{Encode, enc, error::EncodeError};
use monotree::Hash;
use onlyerror::Error;
use sha2::{Digest as _, Sha256};
use std::fmt::{self, Write as _};

#[derive(Debug, Error)]
pub enum Error {
    /// Invalid Merkle root
    InvalidRoot,

    /// Invalid Proof
    InvalidProof,

    /// Sparse Merkle Tree depth exceeded maximum
    TooDeep,

    /// Values cannot be changed
    ValueChanged,
}

/// This trait is an implementation detail. It provides the shared algorithms as default
/// implementations and leaves the Read/Write operations to be defined by implementers.
pub(crate) trait SmtBackend {
    type Error: From<Error>;

    fn insert_inner(
        &self,
        root: Option<&Hash>,
        key: &Hash,
        value: &Hash,
        depth: u16,
    ) -> Result<(Option<Hash>, Option<Prefix>), Self::Error> {
        // Keep track of depth, ensure it never exceeds 257 (256 levels + the root)
        if depth > (u8::MAX as u16) + 1 {
            return Err(Error::TooDeep.into());
        }

        if let Some(root) = root {
            match self.get_node(root).ok_or(Error::InvalidRoot)? {
                SmtNode::Leaf {
                    key: old_key,
                    key_value,
                } => {
                    // When the root is a leaf node, create a new root and sibling leaf node, unless
                    // the key already exists.
                    if key == &old_key {
                        if hash_concat(key, value) != key_value {
                            Err(Error::ValueChanged.into())
                        } else {
                            Ok((Some(*root), None))
                        }
                    } else {
                        let prefix = Prefix::longest_matching(key, &old_key);

                        Ok(self.insert_node(root, key, value, prefix))
                    }
                }

                SmtNode::Node {
                    prefix,
                    left,
                    right,
                } => {
                    // When the root is a full node, compare against the prefix to determine whether
                    // the new node will be internal or external.
                    //
                    // It's internal if the prefix matches: traverse the tree to find the insert
                    // location. Otherwise it's external and the new node needs to point to the
                    // existing node.
                    let matching = Prefix::longest_matching(&prefix.path, key);
                    if matching.bit_count < prefix.bit_count {
                        // Create external node.
                        Ok(self.insert_node(root, key, value, matching))
                    } else {
                        // Insert internal node.
                        let depth = depth.max(prefix.bit_count);
                        let insert_on_right = get_nth_bit(key, depth);
                        let target_root = if insert_on_right { &right } else { &left };
                        let (new_node, child_prefix) =
                            self.insert_inner(Some(target_root), key, value, depth + 1)?;
                        let Some(child_prefix) = child_prefix else {
                            return Ok((Some(*root), None));
                        };
                        let new_node = new_node.unwrap();
                        let new_prefix = Prefix::new(child_prefix.bit_count.min(depth), key);

                        // Update the existing node to point at the new node.
                        let new_root = if insert_on_right {
                            self.update(root, &new_prefix, &left, &new_node)
                        } else {
                            self.update(root, &new_prefix, &new_node, &right)
                        };

                        Ok((Some(new_root), Some(new_prefix)))
                    }
                }
            }
        } else {
            let leaf = self.insert_leaf(key, value);

            Ok((Some(leaf), None))
        }
    }

    /// Get a node by its [`type@Hash`] identifier.
    fn get_node(&self, id: &Hash) -> Option<SmtNode>;

    /// Insert a key-value pair as a leaf node, returning its [`type@Hash`] identifier.
    fn insert_leaf(&self, key: &Hash, value: &Hash) -> Hash;

    /// Insert a new parent node that will point to the previous `root` and to a new leaf node using
    /// the key-value pair.
    ///
    /// The [`Prefix`] must be the longest matching key prefix between both subtrees.
    fn insert_node(
        &self,
        root: &Hash,
        key: &Hash,
        value: &Hash,
        prefix: Prefix,
    ) -> (Option<Hash>, Option<Prefix>);

    /// Update the links and prefix in an existing intermediate node identified by its [`type@Hash`]
    /// identifier.
    ///
    /// The [`Prefix`] must be the longest matching key prefix between both subtrees.
    fn update(&self, id: &Hash, prefix: &Prefix, left: &Hash, right: &Hash) -> Hash;

    fn build_proof(
        &self,
        proof: &mut Proof,
        root: &Hash,
        key: &Hash,
        depth: u16,
    ) -> Result<(), Self::Error> {
        match self.get_node(root).ok_or(Error::InvalidRoot)? {
            SmtNode::Leaf {
                key: leaf_key,
                key_value,
            } => {
                if &leaf_key != key {
                    // Proof-of-non-inclusion
                    proof.path.push((Arrow::sibling(&leaf_key), key_value));
                }

                Ok(())
            }

            SmtNode::Node {
                prefix,
                left,
                right,
            } => {
                let depth = depth.max(prefix.bit_count);
                if get_nth_bit(key, depth) {
                    // Sibling is on the left.
                    proof.path.push((Arrow::Left, left));

                    self.build_proof(proof, &right, key, depth + 1)
                } else {
                    // Sibling is on the right.
                    proof.path.push((Arrow::Right, right));

                    self.build_proof(proof, &left, key, depth + 1)
                }
            }
        }
    }

    fn render(&self, root: &Hash) -> Option<String> {
        let mut mermaid = String::new();
        writeln!(&mut mermaid, "graph TD").unwrap();
        self.render_inner(&mut mermaid, root)?;

        Some(mermaid)
    }

    fn render_inner(&self, mermaid: &mut String, hash: &Hash) -> Option<()> {
        match self.get_node(hash)? {
            SmtNode::Leaf { key, key_value } => {
                writeln!(
                    mermaid,
                    r#"  {}["Leaf<br />hash: {}<br />key-value: {}<br />key: {}"]"#,
                    hex::encode(&hash[..4]),
                    hex::encode(&hash[..4]),
                    hex::encode(&key_value[..4]),
                    hex::encode(&key[..4]),
                )
                .unwrap();
            }

            SmtNode::Node {
                prefix,
                left,
                right,
            } => {
                self.render_node(mermaid, hash, &prefix, &left);
                self.render_node(mermaid, hash, &prefix, &right);
            }
        }

        Some(())
    }

    fn render_node(&self, mermaid: &mut String, hash: &Hash, prefix: &Prefix, next: &Hash) {
        let prefix_bytes = prefix.to_bytes();

        writeln!(
            mermaid,
            r#"  {}["Node<br />hash: {}<br />prefix: (bit_count {}) {}"] --> {}"#,
            hex::encode(&hash[..4]),
            hex::encode(&hash[..4]),
            prefix.bit_count,
            hex::encode(&prefix_bytes[2..6.min(prefix_bytes.len())]),
            hex::encode(&next[..4]),
        )
        .unwrap();
        self.render_inner(mermaid, next);
    }
}

#[derive(Clone, Encode)]
pub(crate) enum SmtNode {
    Leaf {
        key: Hash,
        key_value: Hash,
    },
    Node {
        prefix: Prefix,
        left: Hash,
        right: Hash,
    },
}

impl fmt::Debug for SmtNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SmtNode::")?;
        match self {
            Self::Leaf { key, key_value } => f
                .debug_struct("Leaf")
                .field("key", &hex::encode(key))
                .field("key_value", &hex::encode(key_value))
                .finish(),

            Self::Node {
                prefix,
                left,
                right,
            } => f
                .debug_struct("Node")
                .field("prefix", &prefix)
                .field("left", &hex::encode(left))
                .field("right", &hex::encode(right))
                .finish(),
        }
    }
}

pub fn hash_concat(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);

    hasher.finalize().as_slice().try_into().unwrap()
}

pub(crate) fn get_nth_bit(hash: &Hash, n: u16) -> bool {
    let i = usize::from(n / 8);
    let shift = 7 - (n % 8);

    (hash[i] & (1 << shift)) != 0
}

#[derive(Clone)]
pub(crate) struct Prefix {
    pub(crate) bit_count: u16,
    pub(crate) path: Hash,
}

impl Prefix {
    pub(crate) fn new(bit_count: u16, bytes: &Hash) -> Self {
        let byte_count = Self::byte_count(bit_count);

        let mut path = [0; 32];
        path[..byte_count].copy_from_slice(&bytes[..byte_count]);

        // Mask bits between bit_count up to (byte_count * 8)
        let leading_bits = bit_count % 8;
        if leading_bits > 0 {
            let mask = 0xff << (8 - leading_bits);
            let i = byte_count - 1;
            path[i] &= mask;
        }

        Self { bit_count, path }
    }

    fn longest_matching(a: &Hash, b: &Hash) -> Self {
        for i in 0..32 {
            if a[i] != b[i] {
                for j in (0..8).rev() {
                    if a[i] >> j != b[i] >> j {
                        return Self::new((i * 8 + (7 - j)).try_into().unwrap(), a);
                    }
                }
            }
        }

        Self::new(256, a)
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let byte_count = Self::byte_count(self.bit_count);
        let mut bytes = Vec::with_capacity(byte_count + 2);

        // Encode the bit count into the first two bytes
        bytes.extend(self.bit_count.to_le_bytes());
        bytes.extend(&self.path[..byte_count]);

        bytes
    }

    pub(crate) fn byte_count(bit_count: u16) -> usize {
        (bit_count as f32 / 8.0).ceil() as usize
    }
}

impl fmt::Debug for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Prefix")
            .field("bit_count", &self.bit_count)
            .field(
                "bytes",
                &hex::encode(&self.path[..Prefix::byte_count(self.bit_count)]),
            )
            .finish()
    }
}

// // TODO: Implement decode to allow loading from disk.
// impl<'de, Context> de::BorrowDecode<'de, Context> for Prefix {
//     fn borrow_decode<D: de::BorrowDecoder<'de, Context = Context>>(
//         decoder: &mut D,
//     ) -> Result<Self, DecodeError> {
//         todo!()
//     }
// }

// impl<Context> de::Decode<Context> for Prefix {
//     fn decode<D: de::Decoder<Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
//         todo!()
//     }
// }

impl enc::Encode for Prefix {
    fn encode<E: enc::Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        // Encode the bit count.
        bincode::Encode::encode(&self.bit_count, encoder)?;

        // Encode the prefix bytes as a variable-length slice.
        let byte_count = Self::byte_count(self.bit_count);
        bincode::Encode::encode(&self.path[..byte_count], encoder)?;

        Ok(())
    }
}

/// A cryptographic proof of inclusion (or non-inclusion) of a key-value pair within a Sparse Merkle
/// tree.
///
/// Constructed by [`Smt::get_proof`].
///
/// [`Smt::get_proof`]: crate::smt::Smt::get_proof
#[derive(Clone, Encode)]
pub struct Proof {
    // TODO: `Arrow` should not be embedded with the hashes. It should be separate variable-length
    // bitmap. This will reduce the size of serialized proofs proportional to the cohort size. It
    // will also allow proofs of non-inclusion to be verifiable. They are not currently (see below).
    // // bitmap: Prefix,

    // TODO: Probably want to reverse the order to be compatible with the spec. VecDeque can do that
    // cheaply.
    //
    /// Stores sibling hashes along the tree traversal path, ordered root -> leaf (omitting both).
    ///
    /// [`Self::verify`] requires the root and leaf to be provided as arguments.
    path: Vec<(Arrow, Hash)>,
}

impl Proof {
    pub(crate) fn new() -> Self {
        Self { path: Vec::new() }
    }

    /// Verify the proof against a known `root` and key-value pair.
    ///
    /// The key-value pair is hashed to create the initial leaf hash: `hash(key | value)`.
    pub fn verify(&self, root: &Hash, key: &Hash, value: &Hash) -> Result<(), Error> {
        let hash = Arrow::leaf_hash(key, &hash_concat(key, value));

        self.verify_inner(root, hash)
    }

    // TODO: The proof chain is guaranteed to begin at zero. However, because the key is not
    // included in the hash chain, there is an implicit trust required on the implementation being
    // correct.
    //
    // Suppose a bitmap of empty nodes was included in the proof. That would allow replacement of
    // the internal `Arrow` type with a variable-length bitmap of empty nodes in the path. With that
    // change, the proof uses the key to compute every intermediate hash all the way down all 257
    // levels of the tree, starting from zero.
    //
    // This is not a problem if a nonce is required to prove non-inclusion. (The nonce is in fact a
    // proof of inclusion with a zero value for the KV pair.)
    //
    /// Verify that the proof is a non-inclusion against a known `root`.
    pub fn verify_noninclusion(&self, root: &Hash) -> Result<(), Error> {
        self.verify_inner(root, [0; 32])
    }

    fn verify_inner(&self, root: &Hash, mut hash: Hash) -> Result<(), Error> {
        for (arrow, sibling) in self.path.iter().rev() {
            hash = arrow.hash(&hash, sibling);
        }

        if hash.as_slice() == root {
            Ok(())
        } else {
            Err(Error::InvalidProof)
        }
    }
}

impl fmt::Display for Proof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Proof [\n")?;
        for (arrow, sibling) in &self.path {
            writeln!(f, "    {arrow} {},", hex::encode(sibling))?;
        }
        f.write_str("]")
    }
}

/// The sibling direction in relation to the traversal path.
#[derive(Copy, Clone, Encode)]
pub(crate) enum Arrow {
    Left,
    Right,
}

impl Arrow {
    /// Get a sibling arrow for a key.
    pub(crate) fn sibling(key: &Hash) -> Self {
        if key[31] & 1 == 1 {
            Self::Left
        } else {
            Self::Right
        }
    }

    /// Get a leaf hash for key and key-value hashes.
    pub(crate) fn leaf_hash(key: &Hash, key_value: &Hash) -> Hash {
        // TODO: This wonky proof of non-inclusion scheme requires the KV pair to be the sibling of
        // a zero. Don't get confused! It will go away when the proof of non-inclusion problem is
        // proper fixed.
        Self::sibling(key).hash(&[0; 32], key_value)
    }

    /// Get a hash for key, key-value, and sibling hashes.
    pub(crate) fn hash(self, key_value: &Hash, sibling: &Hash) -> Hash {
        match self {
            Self::Left => hash_concat(sibling, key_value),
            Self::Right => hash_concat(key_value, sibling),
        }
    }
}

impl fmt::Display for Arrow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Left => f.write_str("<--"),
            Self::Right => f.write_str("-->"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smt::nih::Error as NihError;
    use crate::smt::{Smt as _, SmtNih};
    use arbtest::arbitrary::{Result as ArbResult, Unstructured};
    use arbtest::arbtest;
    use std::{collections::HashSet, ops::Range};
    use tempfile::NamedTempFile;

    /// Generate hashes that share a prefix determined by the prefix range.
    ///
    /// Prefix ranges starting at 0 will always share the first bit.
    ///
    /// Generated hashes will be distributed across the prefix range. For instance, when
    /// `prefix_range = 4..17`, all hashes will share a prefix between 5 and 17 (inclusive) bits.
    ///
    /// In other words, all hashes are guaranteed to start with exactly the same 5 bits (0 to 4),
    /// and have successively diminishing probability to share the next 12 bits:
    ///
    /// - Approximately 50% of hashes will share a 6-bit prefix.
    /// - Approximately 25% of hashes will share a 7-bit prefix.
    /// - Approximately 12.5% of hashes will share an 8-bit prefix.
    /// - ...
    /// - Approximately 0.0244140625% of hashes will share a 17-bit prefix.
    ///
    /// Bits beyond `prefix_range.end` are entirely random.
    ///
    /// In general, the probability for each bit is calculated by:
    ///
    /// ```
    /// P = 1 / 2 ** (bit_index - prefix_range.start)
    /// ```
    ///
    /// Where `bit_index` is a 0-based bit index within the hash.
    fn arb_hashes(
        u: &mut Unstructured,
        num_hashes: usize,
        prefix_range: Range<u16>,
    ) -> ArbResult<HashSet<Hash>> {
        let bit_count = u.int_in_range(prefix_range.start..=prefix_range.end)?;
        let byte_count = Prefix::byte_count(bit_count);
        let hash = u.arbitrary()?;
        let prefix = Prefix::new(bit_count, &hash);
        let mut mask = 0xff;

        let leading_bits = bit_count % 8;
        if leading_bits > 0 {
            mask = 0xff >> leading_bits;
        }

        Ok((0..num_hashes)
            .map(|_| {
                let random_hash: Hash = u.arbitrary().unwrap();
                let mut new_hash = [0; 32];
                new_hash[byte_count..].copy_from_slice(&random_hash[byte_count..]);
                new_hash[..byte_count].copy_from_slice(&prefix.path[..byte_count]);

                if byte_count > 0 {
                    let i = byte_count - 1;
                    new_hash[i] |= random_hash[i] & mask;
                }

                new_hash
            })
            .collect())
    }

    #[test]
    fn test_prefix_new() {
        let actual = Prefix::new(3, &[0xff; 32]).to_bytes();
        assert_eq!(actual, [3, 0, 0b1110_0000]);

        let actual = Prefix::new(17, &[0xff; 32]).to_bytes();
        assert_eq!(actual, [17, 0, 0b1111_1111, 0b1111_1111, 0b1000_0000]);

        let actual = Prefix::new(22, &[0xa5; 32]).to_bytes();
        assert_eq!(actual, [22, 0, 0b1010_0101, 0b1010_0101, 0b1010_0100]);
    }

    #[test]
    fn test_prefix_longest_matching() {
        let actual = Prefix::longest_matching(&[0; 32], &[0; 32]).to_bytes();
        let mut expected = [0; 2 + 32];
        expected[..2].copy_from_slice(&256_u16.to_le_bytes()[..2]);
        assert_eq!(actual, expected);

        let actual = Prefix::longest_matching(&[0xff; 32], &[0; 32]).to_bytes();
        assert_eq!(actual, [0, 0]);

        let mut a = [0; 32];
        a[8..].copy_from_slice(&[0xff; 32 - 8]);
        let actual = Prefix::longest_matching(&a, &[0; 32]).to_bytes();
        let mut expected = [0; 2 + 8];
        expected[..2].copy_from_slice(&64_u16.to_le_bytes()[..2]);
        assert_eq!(actual, expected);

        let actual = Prefix::longest_matching(&[6; 32], &[0; 32]).to_bytes();
        let mut expected = [0; 3];
        expected[..2].copy_from_slice(&5_u16.to_le_bytes()[..2]);
        assert_eq!(actual, expected);

        let actual = Prefix::longest_matching(&[0x66; 32], &[0; 32]).to_bytes();
        let mut expected = [0; 3];
        expected[..2].copy_from_slice(&1_u16.to_le_bytes()[..2]);
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_tree_duplicate_inserts() {
        let db_path = NamedTempFile::new().unwrap();
        let tree = SmtNih::new(&db_path.path().to_string_lossy()).unwrap();

        let key = [0; 32];
        let value = [0; 32];

        let mut root = None;

        // Insert the first key, then attempt to insert a duplicate.
        root = tree.insert(root.as_ref(), &key, &value).unwrap();
        root = tree.insert(root.as_ref(), &key, &value).unwrap();

        // Insert a bunch of random keys.
        for _ in 0..32 {
            let random_key = rand::random();

            root = tree.insert(root.as_ref(), &random_key, &value).unwrap();
        }

        // The root must not change when a duplicate is inserted.
        assert_eq!(tree.insert(root.as_ref(), &key, &value).unwrap(), root);

        // Attempting to change the value at an existing key will return an error.
        assert!(matches!(
            tree.insert(root.as_ref(), &key, &[0xff; 32]),
            Err(NihError::Smt(Error::ValueChanged)),
        ));
    }

    #[test]
    fn arbtest_proofs() {
        arbtest(|u| {
            // Generate a bunch of hashes
            let num_hashes = u.int_in_range(1..=100_000)?;
            let prefix_bit_range_start = u.int_in_range(0..=256)?;
            let prefix_bit_range_end = u.int_in_range(prefix_bit_range_start..=256)?;
            let hashes = arb_hashes(u, num_hashes, prefix_bit_range_start..prefix_bit_range_end)?;

            // Create an SMT. Note that the temp file will be empty, because we do not call
            // the `commit()` method.
            let db_path = NamedTempFile::new().unwrap();
            let tree = SmtNih::new(&db_path.path().to_string_lossy()).unwrap();

            // Insert all of the hashes into the tree.
            let mut root = None;
            for hash in &hashes {
                root = tree.insert(root.as_ref(), hash, hash).unwrap();
            }

            // Verify all proof paths for every hash inserted.
            let root = root.unwrap();
            for hash in &hashes {
                let proof = tree.get_proof(&root, hash).unwrap();

                proof.verify(&root, hash, hash).unwrap();

                assert!(proof.verify_noninclusion(&root).is_err());
            }

            Ok(())
        })
        .size_min(100_000)
        .size_max(1_000_000);
    }

    #[test]
    fn arbtest_proof_sibling_boundaries() {
        arbtest(|u| {
            let db_path = NamedTempFile::new().unwrap();
            let tree = SmtNih::new(&db_path.path().to_string_lossy()).unwrap();

            // Check proof paths for the keys at the boundaries of the keyspace.
            let leftmost = [0x00; 32];
            let rightmost = [0xff; 32];

            let num_hashes = u.int_in_range(10..=10_000)?;
            let mut root = None;
            for hash in arb_hashes(u, num_hashes, 0..256)? {
                root = tree.insert(root.as_ref(), &hash, &hash).unwrap();
            }

            // Insert leftmost and rightmost hashes, then verify proofs.
            root = tree.insert(root.as_ref(), &leftmost, &leftmost).unwrap();
            root = tree.insert(root.as_ref(), &rightmost, &rightmost).unwrap();

            let root = root.unwrap();
            let left_proof = tree.get_proof(&root, &leftmost).unwrap();
            let right_proof = tree.get_proof(&root, &rightmost).unwrap();

            left_proof.verify(&root, &leftmost, &leftmost).unwrap();
            right_proof.verify(&root, &rightmost, &rightmost).unwrap();

            assert!(left_proof.verify_noninclusion(&root).is_err());
            assert!(right_proof.verify_noninclusion(&root).is_err());

            // All siblings in the leftmost proof will point to the right.
            for (arrow, _) in left_proof.path {
                assert!(matches!(arrow, Arrow::Right));
            }

            // All siblings in the rightmost proof will point to the left.
            for (arrow, _) in right_proof.path {
                assert!(matches!(arrow, Arrow::Left));
            }

            Ok(())
        })
        .size_min(100_000)
        .size_max(1_000_000)
        .budget_ms(500);
    }

    #[test]
    fn arbtest_proof_sibling_sides() {
        arbtest(|u| {
            let db_path = NamedTempFile::new().unwrap();
            let tree = SmtNih::new(&db_path.path().to_string_lossy()).unwrap();

            // Create hashes within a narrow band (they all share a random 32-bit prefix)
            // It is highly unlikely that all 32 bits will be all 0's or 0xff's.
            let num_hashes = u.int_in_range(10..=10_000)?;
            let hashes = arb_hashes(u, num_hashes, 32..32)?;

            // If a random hash begins with 0x0 or 0xf, then we'll exit early to allow arbtest to
            // try another iteration.
            let random_hash = hashes.iter().next().copied().unwrap();
            if random_hash[0] <= 0x0f || random_hash[0] >= 0xf0 {
                return Ok(());
            }

            // Copy the random hash into leftmost and rightmost, then update the first byte.
            let mut leftmost = random_hash;
            leftmost[0] &= 0x0f;
            let mut rightmost = random_hash;
            rightmost[0] |= 0xf0;

            // Insert leftmost and rightmost hashes.
            let mut root = None;
            root = tree.insert(root.as_ref(), &leftmost, &leftmost).unwrap();
            root = tree.insert(root.as_ref(), &rightmost, &rightmost).unwrap();

            // Insert all of the random hashes.
            for hash in hashes {
                root = tree.insert(root.as_ref(), &hash, &hash).unwrap();
            }

            // Get and verify leftmost and rightmost proofs.
            let root = root.unwrap();
            let left_proof = tree.get_proof(&root, &leftmost).unwrap();
            let right_proof = tree.get_proof(&root, &rightmost).unwrap();

            left_proof.verify(&root, &leftmost, &leftmost).unwrap();
            right_proof.verify(&root, &rightmost, &rightmost).unwrap();

            assert!(left_proof.verify_noninclusion(&root).is_err());
            assert!(right_proof.verify_noninclusion(&root).is_err());

            // All siblings in the leftmost proof will point to the right.
            for (arrow, _) in left_proof.path {
                assert!(matches!(arrow, Arrow::Right));
            }

            // All siblings in the rightmost proof will point to the left.
            for (arrow, _) in right_proof.path {
                assert!(matches!(arrow, Arrow::Left));
            }

            Ok(())
        })
        .size_min(100_000)
        .size_max(1_000_000)
        .budget_ms(500);
    }

    #[test]
    fn arbtest_proof_of_non_inclusion() {
        arbtest(|u| {
            let db_path = NamedTempFile::new().unwrap();
            let tree = SmtNih::new(&db_path.path().to_string_lossy()).unwrap();

            let num_hashes = u.int_in_range(10..=100)?;
            let hashes = arb_hashes(u, num_hashes, 0..0)?;
            let half = hashes.len() / 2;
            let mut i = 0;
            let (included, excluded): (Vec<_>, Vec<_>) = hashes.into_iter().partition(|_| {
                i += 1;
                i >= half
            });

            // Insert half of the nodes.
            let mut root = None;
            for hash in included {
                root = tree.insert(root.as_ref(), &hash, &hash).unwrap();
            }

            // Ensure that proofs for all random hashes are proofs of non-inclusion
            let root = root.unwrap();
            for hash in excluded {
                let proof = tree.get_proof(&root, &hash).unwrap();
                proof.verify_noninclusion(&root).unwrap();
            }

            Ok(())
        })
        .size_min(10_000)
        .size_max(100_000);
    }
}
