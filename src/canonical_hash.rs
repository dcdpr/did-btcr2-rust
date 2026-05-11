use crate::identifier::Sha256Hash;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

pub(crate) trait CanonicalHash: AsRef<Value> {
    fn hash(&self) -> Sha256Hash {
        let jcs = serde_jcs::to_string(self.as_ref()).expect("JSON is always valid JCS");
        let hash_bytes = Sha256::digest(jcs.as_bytes());

        Sha256Hash(hash_bytes[..].try_into().unwrap())
    }
}
