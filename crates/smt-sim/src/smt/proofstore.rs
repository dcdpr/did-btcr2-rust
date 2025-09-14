use crate::smt::tree::SmtNode;
use bincode::Encode;
use monotree::Hash;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Encode)]
pub struct ProofStore {
    nodes: BTreeMap<u64, ProofNode>,
}

#[derive(Clone, Debug, Encode)]
pub enum ProofNode {
    KvPair(Option<Hash>),

    Intermediate { left: u64, right: u64 },
}

impl ProofStore {
    pub(crate) fn from_smt(smt: &BTreeMap<Hash, SmtNode>, root: &Hash) -> Option<Self> {
        let mut nodes = BTreeMap::new();

        from_smt_inner(&mut nodes, smt, root)?;

        Some(Self { nodes })
    }
}

fn from_smt_inner(
    tree: &mut BTreeMap<u64, ProofNode>,
    smt: &BTreeMap<Hash, SmtNode>,
    root: &Hash,
) -> Option<u64> {
    let id = tree.len() as u64;

    let node = match smt.get(root)? {
        SmtNode::Leaf { key_value, .. } => ProofNode::KvPair(Some(*key_value)),
        SmtNode::Node { left, right, .. } => {
            let left = from_smt_inner(tree, smt, left)?;
            let right = from_smt_inner(tree, smt, right)?;

            ProofNode::Intermediate { left, right }
        }
    };

    tree.insert(id, node);

    Some(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smt::{Smt, SmtNih};
    use rand::Rng;
    use tempfile::NamedTempFile;

    #[test]
    fn test_proof_store_size() {
        let db_path = NamedTempFile::new().unwrap();
        let smt = SmtNih::new(&db_path.path().to_string_lossy()).unwrap();

        let mut root = None;

        // Insert random keys into the SMT.
        let cohort_size = 1_000;
        let keys = (0..cohort_size)
            .map(|_| rand::thread_rng().r#gen())
            .collect::<Vec<_>>();

        for key in &keys {
            root = smt.insert(root.as_ref(), key, &[0; 32]).unwrap();
        }

        // Create a ProofStore from the SMT.
        let root = root.unwrap();
        let proofstore = ProofStore::from_smt(&smt.map.borrow(), &root);

        // Get the size in bytes of the encoded ProofStore.
        let mut proof_store_bytes = Vec::new();
        bincode::encode_into_std_write(
            proofstore,
            &mut proof_store_bytes,
            bincode::config::standard(),
        )
        .unwrap();

        // Compare size of list of proofs to size of ProofStore
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

        assert!(proof_store_bytes.len() < vec_proof_bytes.len());
    }
}
