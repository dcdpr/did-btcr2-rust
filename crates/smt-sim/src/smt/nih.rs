//! Sparse Merkle Tree "Not-Invented-Here" backend. (TODO: Needs a better name!)
//!
//! This backend implements the database in-memory with a batch writer for persistent storage. It is
//! the fastest and smallest (on disk) implementation among all currently supported backends. It's
//! also the least durable and is susceptible to corruption and data loss if the application crashes
//! or the machine suffers a power failure during writes.
//!
//! Recommendations for production deployments: Store a separate durable transaction log that can
//! replay all inserts. Inserts are commutative (order-independent) and idempotent, making it
//! somewhat trivial to rebuild tree state from logs.

use super::Smt;
use super::tree::{Arrow, Prefix, Proof, SmtBackend, SmtNode, get_nth_bit, hash_concat};
use monotree::Hash;
use onlyerror::Error;
use std::io::{BufWriter, Write as _};
use std::{cell::RefCell, collections::BTreeMap, fs::File};

#[derive(Debug, Error)]
pub enum Error {
    /// I/O error
    Io(#[from] std::io::Error),

    /// SMT error
    Smt(#[from] super::tree::Error),
}

pub struct SmtNih {
    db: File,
    // TODO: Remove RefCell ... it's only needed because I made the trait take `&self` for all
    // methods.
    pub(crate) map: RefCell<BTreeMap<Hash, SmtNode>>,
}

impl Smt for SmtNih {
    const EXT: &str = "nih";
    type Proof = Proof;
    type Error = Error;

    type Transaction<'a> = ();

    fn new(db_path: &str) -> Result<Self, Self::Error> {
        Ok(Self {
            // TODO: Load from disk (requires `Decode` implementations on `SmtNode` and `Prefix`)
            db: File::create(db_path)?,
            map: RefCell::default(),
        })
    }

    fn prepare(&self) -> Self::Transaction<'_> {}

    fn commit(&self, _tx: Self::Transaction<'_>) {
        let mut writer = BufWriter::new(&self.db);
        bincode::encode_into_std_write(&self.map, &mut writer, bincode::config::standard())
            .unwrap();
        writer.flush().unwrap();
    }

    fn insert(
        &self,
        root: Option<&Hash>,
        key: &Hash,
        value: &Hash,
    ) -> Result<Option<Hash>, Self::Error> {
        let (root, _) = self.insert_inner(root, key, value, 0)?;

        Ok(root)
    }

    fn get_proof(&self, root: &Hash, key: &Hash) -> Result<Self::Proof, Self::Error> {
        let mut proof = Proof::new();

        self.build_proof(&mut proof, root, key, 0)?;

        Ok(proof)
    }

    fn render(&self, root: &Hash) -> Option<String> {
        <Self as SmtBackend>::render(self, root)
    }
}

impl SmtBackend for SmtNih {
    type Error = Error;

    fn get_node(&self, id: &Hash) -> Option<SmtNode> {
        // TODO: Remove clone
        self.map.borrow().get(id).cloned()
    }

    fn insert_leaf(&self, key: &Hash, value: &Hash) -> Hash {
        let key_value = hash_concat(key, value);
        let id = Arrow::leaf_hash(key, &key_value);

        self.map.borrow_mut().insert(
            id,
            SmtNode::Leaf {
                key: *key,
                key_value,
            },
        );

        id
    }

    fn insert_node(
        &self,
        root: &Hash,
        key: &Hash,
        value: &Hash,
        prefix: Prefix,
    ) -> (Option<Hash>, Option<Prefix>) {
        let new_node = self.insert_leaf(key, value);
        let (left, right) = if get_nth_bit(key, prefix.bit_count) {
            (root, &new_node)
        } else {
            (&new_node, root)
        };
        let id = hash_concat(left, right);

        self.map.borrow_mut().insert(
            id,
            SmtNode::Node {
                // TODO: Remove clone
                prefix: prefix.clone(),
                left: *left,
                right: *right,
            },
        );

        (Some(id), Some(prefix))
    }

    fn update(&self, id: &Hash, prefix: &Prefix, left: &Hash, right: &Hash) -> Hash {
        let new_id = hash_concat(left, right);

        let mut map = self.map.borrow_mut();
        if let Some(SmtNode::Node { .. }) = map.remove(id) {
            map.insert(
                new_id,
                SmtNode::Node {
                    // TODO: Remove clone
                    prefix: prefix.clone(),
                    left: *left,
                    right: *right,
                },
            );
        }

        new_id
    }
}
