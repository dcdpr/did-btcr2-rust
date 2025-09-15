//! Types for facilitating storage of SMT proofs.

use super::hash_concat;
use super::tree::{Arrow, SmtBackend, SmtNode};
use bincode::{Decode, Encode};
use monotree::Hash;
use std::collections::BTreeMap;

// TODO: Get proofs
/// A "hydrated" proof store that can produce proofs.
///
/// Constructed by conversion from [`CompactProofStore`].
#[derive(Clone, Debug)]
pub struct ProofStore {
    root: Hash,
    nodes: BTreeMap<Hash, ProofNode>,
}

#[derive(Copy, Clone, Debug)]
enum ProofNode {
    KvPair { key: Hash, key_value: Hash },

    Intermediate { left: Hash, right: Hash },
}

impl From<CompactProofStore> for ProofStore {
    fn from(compact: CompactProofStore) -> Self {
        let mut nodes = BTreeMap::new();
        let root = from_compact(&mut nodes, &compact, compact.root).unwrap();

        Self { root, nodes }
    }
}

fn from_compact(
    nodes: &mut BTreeMap<Hash, ProofNode>,
    compact: &CompactProofStore,
    root: u64,
) -> Option<Hash> {
    match *compact.nodes.get(&root)? {
        CompactProofNode::KvPair { key, key_value } => {
            let id = Arrow::leaf_hash(&key, &key_value);

            nodes.insert(id, ProofNode::KvPair { key, key_value });

            Some(id)
        }
        CompactProofNode::Intermediate { left, right } => {
            let left = from_compact(nodes, compact, left)?;
            let right = from_compact(nodes, compact, right)?;
            let id = hash_concat(&left, &right);

            nodes.insert(id, ProofNode::Intermediate { left, right });

            Some(id)
        }
    }
}

// TODO: Construct from `Vec<Proof>`
/// A compact proof store is ideal for long-term storage and bandwidth reduction.
///
/// It cannot create proofs itself, but it can be converted into a [`ProofStore`] which can.
///
/// It is a compact representation of a list of SMT proofs. The data structure resembles an SMT with
/// subtree truncation (substitution of irrelevant subtrees with their hash) and replacement of
/// intermediate hashes with variable length integers.
///
/// An SMT with `N` leaves has `N - 1` intermediate nodes. By replacing intermediate node hashes
/// with VLIs, we see a reduction from `32N` bytes to `M * N` bytes where `M = ceil(log2(N) / 8)`.
///
/// E.g.:
///
/// - `N` bytes for `N < 2^7`.
/// - `2N` bytes for `N < 2^14`.
/// - `3N` bytes for `N < 2^21`.
///
/// `M` is guaranteed less than 32 until `N` approaches `2^256`.
#[derive(Clone, Debug, Decode, Encode)]
pub struct CompactProofStore {
    root: u64,
    nodes: BTreeMap<u64, CompactProofNode>,
}

#[derive(Copy, Clone, Debug, Decode, Encode)]
enum CompactProofNode {
    KvPair { key: Hash, key_value: Hash },

    // TODO: Either side can be a sibling hash.
    Intermediate { left: u64, right: u64 },
}

impl CompactProofStore {
    pub(crate) fn from_smt<T: SmtBackend>(smt: &T, root: &Hash) -> Option<Self> {
        let mut nodes = BTreeMap::new();
        let root = from_smt_inner(&mut nodes, smt, root, 0)?;

        Some(Self { root, nodes })
    }
}

fn from_smt_inner<T: SmtBackend>(
    tree: &mut BTreeMap<u64, CompactProofNode>,
    smt: &T,
    root: &Hash,
    mut id: u64,
) -> Option<u64> {
    let node = match smt.get_node(root)? {
        SmtNode::Leaf { key, key_value, .. } => CompactProofNode::KvPair { key, key_value },
        SmtNode::Node { left, right, .. } => {
            let left = from_smt_inner(tree, smt, &left, id + 1)?;
            let right = from_smt_inner(tree, smt, &right, left + 1)?;
            id = right + 1;

            CompactProofNode::Intermediate { left, right }
        }
    };

    tree.insert(id, node);

    Some(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smt::{Smt, SmtNih};
    use arbtest::{arbitrary::Unstructured, arbtest};
    use tempfile::NamedTempFile;

    fn create_smt(u: &mut Unstructured) -> (Hash, SmtNih, Vec<Hash>) {
        let db_path = NamedTempFile::new().unwrap();
        let smt = SmtNih::new(&db_path.path().to_string_lossy()).unwrap();

        let mut root = None;

        // Insert random keys into the SMT.
        let cohort_size = 1_000;
        let keys = (0..cohort_size)
            .map(|_| u.arbitrary().unwrap())
            .collect::<Vec<_>>();

        for key in &keys {
            root = smt.insert(root.as_ref(), key, &[0; 32]).unwrap();
        }

        (root.unwrap(), smt, keys)
    }

    #[test]
    fn arbtest_proofstore_root() {
        arbtest(|u| {
            let (root, smt, _) = create_smt(u);

            // Create a CompactProofStore from the SMT.
            let cps = CompactProofStore::from_smt(&smt, &root).unwrap();

            // Hydrate the compact proofs (re-hash everything).
            let ps = ProofStore::from(cps);

            // The hydrated root should be equal to the known root.
            assert_eq!(ps.root, root);

            Ok(())
        });
    }

    #[test]
    fn arbtest_compact_proofstore_size() {
        arbtest(|u| {
            let (root, smt, keys) = create_smt(u);

            // Create a CompactProofStore from the SMT.
            let cps = CompactProofStore::from_smt(&smt, &root);

            // Get the size in bytes of the encoded CompactProofStore.
            let mut proof_store_bytes = Vec::new();
            bincode::encode_into_std_write(
                cps,
                &mut proof_store_bytes,
                bincode::config::standard(),
            )
            .unwrap();

            // Compare size of list of proofs to size of CompactProofStore.
            let my_proofs = keys
                .iter()
                .map(|key| smt.get_proof(&root, key))
                .collect::<Result<Vec<_>, _>>()
                .unwrap();

            let mut vec_proof_bytes = Vec::new();
            bincode::encode_into_std_write(
                my_proofs,
                &mut vec_proof_bytes,
                bincode::config::standard(),
            )
            .unwrap();

            // The compact proof store is expected to be at least 4x smaller.
            //
            // TODO: This might change after addressing the proof of non-inclusion problem. The current
            // implementation includes the `key` and a zero in every leaf node. But we can remove those
            // with a proper implementation.
            //
            // The expected theoretical compression ratio is approximately 10:1.
            assert!(proof_store_bytes.len() < vec_proof_bytes.len() / 4);

            Ok(())
        });
    }
}
