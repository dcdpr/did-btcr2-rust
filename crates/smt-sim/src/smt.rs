pub use self::{nih::SmtNih, sqlite::SmtSqlite, tree::hash_concat};
pub use monotree::Hash;
use monotree::database::{rocksdb::RocksDB, sled::Sled};
use monotree::{Monotree, hasher::Sha2};
use std::cell::RefCell;

mod nih;
mod proofstore;
mod sqlite;
mod tree;

pub struct SmtRocks(RefCell<Monotree<RocksDB, Sha2>>);
pub struct SmtSled(RefCell<Monotree<Sled, Sha2>>);

pub trait Smt {
    const EXT: &str;
    type Proof: bincode::Encode;
    type Error;

    type Transaction<'a>
    where
        Self: 'a;

    /// Create a new Sparse Merkle Tree.
    fn new(db_path: &str) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Create a transaction.
    ///
    /// All write operations will be batched until committed with [`Self::commit`].
    fn prepare(&self) -> Self::Transaction<'_>;

    /// Commit the transaction. Writes all pending data to disk.
    fn commit(&self, tx: Self::Transaction<'_>);

    /// Insert a key-value pair into the tree at the given root (if any).
    fn insert(
        &self,
        root: Option<&Hash>,
        key: &Hash,
        value: &Hash,
    ) -> Result<Option<Hash>, Self::Error>;

    /// Get a proof (SMT audit path) for the key starting from the given root.
    fn get_proof(&self, root: &Hash, key: &Hash) -> Result<Self::Proof, Self::Error>;

    /// Render the tree to a Mermaid diagram starting from the given root.
    ///
    /// Not all implementations support diagram rendering. They will always return `None`.
    #[allow(unused_variables)]
    fn render(&self, root: &Hash) -> Option<String> {
        None
    }
}

impl Smt for SmtRocks {
    const EXT: &str = "rocksdb";
    type Proof = Vec<(bool, Vec<u8>)>;
    type Error = monotree::Errors;

    type Transaction<'a> = ();

    fn new(db_path: &str) -> Result<Self, Self::Error> {
        Ok(Self(RefCell::new(Monotree::new(db_path))))
    }

    fn prepare(&self) -> Self::Transaction<'_> {
        self.0.borrow_mut().prepare();
    }

    fn commit(&self, _tx: Self::Transaction<'_>) {
        self.0.borrow_mut().commit();
    }

    fn insert(
        &self,
        root: Option<&Hash>,
        key: &Hash,
        value: &Hash,
    ) -> Result<Option<Hash>, Self::Error> {
        self.0.borrow_mut().insert(root, key, value)
    }

    fn get_proof(&self, root: &Hash, key: &Hash) -> Result<Self::Proof, Self::Error> {
        self.0
            .borrow_mut()
            .get_merkle_proof(Some(root), key)?
            .ok_or_else(|| monotree::Errors::new("Invalid root"))
    }
}

impl Smt for SmtSled {
    const EXT: &str = "sled";
    type Proof = Vec<(bool, Vec<u8>)>;
    type Error = monotree::Errors;

    type Transaction<'a> = ();

    fn new(db_path: &str) -> Result<Self, Self::Error> {
        Ok(Self(RefCell::new(Monotree::new(db_path))))
    }

    fn prepare(&self) -> Self::Transaction<'_> {
        self.0.borrow_mut().prepare();
    }

    fn commit(&self, _tx: Self::Transaction<'_>) {
        self.0.borrow_mut().commit();
    }

    fn insert(
        &self,
        root: Option<&Hash>,
        key: &Hash,
        value: &Hash,
    ) -> Result<Option<Hash>, Self::Error> {
        self.0.borrow_mut().insert(root, key, value)
    }

    fn get_proof(&self, root: &Hash, key: &Hash) -> Result<Self::Proof, Self::Error> {
        self.0
            .borrow_mut()
            .get_merkle_proof(Some(root), key)?
            .ok_or_else(|| monotree::Errors::new("Invalid root"))
    }
}
