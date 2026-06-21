//! Beacon services: the Bitcoin addresses through which a did:btcr2 DID
//! announces its updates, plus parsing of beacon types and BIP21 service
//! endpoints.

use crate::identifier::Network;
use esploda::bitcoin::address::Address;
use esploda::bitcoin::blockdata::{opcodes::all::OP_RETURN, script::Instruction};
use onlyerror::Error;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{fmt, str::FromStr};

/// Errors arising while parsing beacon types, BIP21 service endpoints, or
/// Bitcoin addresses for a beacon descriptor.
#[derive(Debug, Error)]
pub enum Error {
    /// Invalid beacon type
    InvalidBeaconType,

    /// Invalid BIP21 address.
    InvalidBip21,

    /// Bitcoin Address Parse error
    AddressParse(#[from] esploda::bitcoin::address::Error),

    /// Identifier Parse Error
    IdentifierParse(#[from] crate::identifier::Error),
}

/// Extension trait for [`Address`]. Allows parsing from [BIP21] URI.
///
/// [BIP21]: https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki
pub trait AddressExt {
    /// Parse a Bitcoin address from a `bitcoin:` BIP21 URI, requiring the
    /// address to belong to the given [`Network`]. Any unrecognized `req-`
    /// parameter is rejected as required by BIP21.
    fn from_bip21(uri: &str, network: Network) -> Result<Self, Error>
    where
        Self: Sized;
}

impl AddressExt for Address {
    fn from_bip21(uri: &str, network: Network) -> Result<Self, Error> {
        let body = uri.strip_prefix("bitcoin:").ok_or(Error::InvalidBip21)?;
        let (address, params) = match body.split_once('?') {
            Some((addr, params)) => (addr, Some(params)),
            None => (body, None),
        };

        // BIP21 requires a parser to REJECT any `req-` parameter it does not
        // understand. This implementation understands NONE, so any `req-`
        // parameter is a hard error rather than being silently dropped.
        // Non-`req-` parameters (amount/label/message) are intentionally ignored:
        // for a beacon serviceEndpoint only the address matters.
        if let Some(params) = params {
            for kv in params.split('&').filter(|s| !s.is_empty()) {
                let key = kv.split_once('=').map_or(kv, |(k, _)| k);
                if key.starts_with("req-") {
                    return Err(Error::InvalidBip21);
                }
            }
        }

        Ok(address
            .parse::<Address<_>>()?
            .require_network(network.try_into()?)?)
    }
}

/// A beacon service declared in a DID document: an identifier, a beacon type,
/// and the Bitcoin address that announces DID updates for this DID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Beacon {
    id: String,
    pub(crate) ty: BeaconType,
    pub(crate) descriptor: Address,
}

/// The kind of beacon a DID uses to announce updates, per the did:btcr2 spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub enum BeaconType {
    /// Singleton beacon: a single Bitcoin address controlled by one party that
    /// announces updates for exactly one DID.
    #[serde(rename = "SingletonBeacon")]
    Singleton,
    /// CAS (Content-Addressable Storage) beacon: aggregates updates for many
    /// DIDs, with payloads retrieved from content-addressed storage.
    #[serde(rename = "CASBeacon")]
    Cas,
    /// Sparse Merkle Tree beacon: aggregates updates for many DIDs, proving
    /// inclusion or non-inclusion via an SMT proof.
    #[serde(rename = "SMTBeacon")]
    SparseMerkleTree,
}

impl FromStr for BeaconType {
    type Err = Error;

    fn from_str(ty: &str) -> Result<Self, Self::Err> {
        match ty {
            "SingletonBeacon" => Ok(Self::Singleton),
            "CASBeacon" => Ok(Self::Cas),
            "SMTBeacon" => Ok(Self::SparseMerkleTree),
            _ => Err(Error::InvalidBeaconType),
        }
    }
}

impl fmt::Display for BeaconType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Singleton => f.write_str("SingletonBeacon"),
            Self::Cas => f.write_str("CASBeacon"),
            Self::SparseMerkleTree => f.write_str("SMTBeacon"),
        }
    }
}

impl Beacon {
    pub(crate) fn new(id: String, ty: BeaconType, descriptor: Address) -> Self {
        Self { id, ty, descriptor }
    }

    /// The Bitcoin address this beacon spends from when announcing signals.
    ///
    /// Read-only borrow of the beacon's `serviceEndpoint` address; an
    /// out-of-crate caller (e.g. the `did-btcr2-client` facade) uses it to
    /// discover the UTXOs it must spend. No I/O is performed.
    pub fn address(&self) -> &Address {
        &self.descriptor
    }

    /// The beacon mechanism (Singleton / CAS / SMT).
    pub fn beacon_type(&self) -> BeaconType {
        self.ty
    }

    /// The beacon service id (e.g. `did:btcr2:k1...#initialP2TR`).
    pub fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn into_json(self) -> Value {
        json!({
            "id": self.id,
            "type": self.ty.to_string(),
            "serviceEndpoint": format!("bitcoin:{}", self.descriptor),
            // "minimumConfirmationsRequired": self.min_confirmations_required,
        })
    }
}

/// A funding input to spend when announcing a beacon signal.
///
/// Carries everything the three default beacon signing schemes need: P2TR
/// commits to every prevout's `value` + `script_pubkey`, P2WPKH needs the
/// amount + a script_code derived from the `script_pubkey`, and P2PKH needs its
/// own `script_pubkey`. The signer infers the address kind from
/// `script_pubkey` (`is_p2pkh()` / `is_p2wpkh()` / `is_p2tr()`) — single source
/// of truth, no separate kind tag.
///
/// API contract (GIGO): every `Prevout` passed to
/// [`Update::announce_singleton`](crate::Update::announce_singleton) is signed
/// with the SAME `beacon_secret_key`. The caller MUST pass only prevouts
/// spendable by that key; a prevout locked to a foreign key produces a silently
/// invalid transaction. This is a sans-I/O primitive — it performs no runtime
/// key/scriptPubKey cross-check (UTXO ownership is the caller's I/O concern).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prevout {
    /// The outpoint (txid + vout) being spent.
    pub outpoint: esploda::bitcoin::OutPoint,
    /// The value of the spent output, in satoshis.
    pub value: u64,
    /// The scriptPubKey of the spent output (determines the signing scheme).
    pub script_pubkey: esploda::bitcoin::ScriptBuf,
}

/// A signed singleton-beacon announcement transaction.
///
/// Newtype over [`esploda::bitcoin::Transaction`] carrying the "valid singleton
/// beacon signal" invariant: the last output is `OP_RETURN <32-byte push>` (the
/// JSON Document Hash of the announced update). The internal infallible producer
/// ([`Update::announce_singleton`](crate::Update::announce_singleton)) builds it
/// directly; the public [`TryFrom`] validates the invariant for externally-built
/// transactions (parse-don't-validate). The caller extracts the inner
/// transaction at broadcast time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedBeaconTx(pub(crate) esploda::bitcoin::Transaction);

impl SignedBeaconTx {
    /// Consume the newtype and return the inner transaction for serialization /
    /// broadcast.
    pub fn into_inner(self) -> esploda::bitcoin::Transaction {
        self.0
    }

    /// Borrow the inner transaction (e.g. to serialize without consuming).
    pub fn as_tx(&self) -> &esploda::bitcoin::Transaction {
        &self.0
    }
}

/// Errors from building or validating a singleton-beacon announcement.
///
/// A named public type, separate from the BIP21/parse-concerned [`enum@Error`] in
/// this module, so a downstream facade caller can name and match the
/// announce error on its own.
#[derive(Debug, Error)]
pub enum AnnounceError {
    /// The transaction's last output is not `OP_RETURN`, or it has no outputs.
    MissingOpReturnSignal,

    /// The `OP_RETURN` push is present but is not exactly 32 bytes.
    WrongSignalLength {
        /// The actual push length found.
        len: usize,
    },

    /// The prevouts slice was empty (would yield a consensus-invalid zero-input
    /// transaction).
    NoPrevouts,

    /// `sum(prevout.value)` is less than the requested fee (would underflow
    /// change).
    InsufficientFunds {
        /// Sum of the supplied prevout values, in satoshis.
        inputs: u64,
        /// The requested absolute fee, in satoshis.
        fee: u64,
    },

    /// A prevout scriptPubKey is not one of P2PKH / P2WPKH / P2TR.
    UnsupportedScriptType,

    /// Sighash computation or signing failed.
    Signing(String),
}

/// Validate that an externally-built transaction is a well-formed singleton
/// beacon signal: its last output must be exactly `OP_RETURN <32-byte push>`.
///
/// Re-asserts the same invariant the resolver matches on
/// (`resolver.rs` `find_next_signals`), so a transaction that passes here is
/// guaranteed to be picked up by the resolver's signal-extraction path.
impl TryFrom<esploda::bitcoin::Transaction> for SignedBeaconTx {
    type Error = AnnounceError;

    fn try_from(tx: esploda::bitcoin::Transaction) -> Result<Self, Self::Error> {
        let txout = tx
            .output
            .last()
            .ok_or(AnnounceError::MissingOpReturnSignal)?;
        // Collect into a Result rather than `.flatten()`: a `.flatten()` on a
        // Result-yielding iterator silently drops Err instruction-parse results,
        // so a malformed scriptPubKey could collapse to a shorter `ops` vec. We
        // want any parse error to reject the transaction outright (the intent is
        // "exactly OP_RETURN <push>", not "OP_RETURN <push> after dropping
        // unparseable instructions").
        let ops: Vec<_> = txout
            .script_pubkey
            .instructions()
            .collect::<Result<_, _>>()
            .map_err(|_| AnnounceError::MissingOpReturnSignal)?;

        let [Instruction::Op(OP_RETURN), Instruction::PushBytes(bytes)] = ops[..] else {
            return Err(AnnounceError::MissingOpReturnSignal);
        };

        let len = bytes.as_bytes().len();
        if len != 32 {
            return Err(AnnounceError::WrongSignalLength { len });
        }

        Ok(SignedBeaconTx(tx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_beacon_address_uri() {
        let address =
            Address::from_bip21("foo:mh8h6FXkMzHaW4RKerGT33ZLqx52xL28dU", Network::Regtest);

        assert!(matches!(address, Err(Error::InvalidBip21)));
    }

    /// BIP21 says a parser MUST reject an unrecognized `req-` parameter.
    /// This implementation understands none, so any `req-*` is rejected rather
    /// than silently dropped.
    #[test]
    fn bip21_rejects_unknown_required_parameter() {
        let uri = "bitcoin:mh8h6FXkMzHaW4RKerGT33ZLqx52xL28dU?req-future=1";
        let address = Address::from_bip21(uri, Network::Regtest);
        assert!(
            matches!(address, Err(Error::InvalidBip21)),
            "got {address:?}"
        );
    }

    /// Non-`req-` parameters (amount/label) are intentionally ignored: only the
    /// address matters for a beacon serviceEndpoint, so the URI still parses.
    #[test]
    fn bip21_ignores_benign_parameters() {
        let uri = "bitcoin:mh8h6FXkMzHaW4RKerGT33ZLqx52xL28dU?amount=0.1&label=beacon";
        Address::from_bip21(uri, Network::Regtest)
            .expect("a BIP21 URI with only benign parameters parses to its address");
    }

    #[test]
    fn cas_beacon_string_round_trip() {
        // Spec: did-btcr2/src/beacons.md Table 1 — on-wire string is "CASBeacon".
        assert_eq!("CASBeacon".parse::<BeaconType>().unwrap(), BeaconType::Cas);
        assert_eq!(BeaconType::Cas.to_string(), "CASBeacon");
    }

    #[test]
    fn old_mapbeacon_string_rejected() {
        // The old-spec on-wire string "MapBeacon" must NOT parse — wire-level rename
        assert!("MapBeacon".parse::<BeaconType>().is_err());
    }

    #[test]
    fn beacon_type_serde_round_trips_spec_strings() {
        // BeaconType's derived Serialize/Deserialize must use
        // the spec wire strings (per did-btcr2/src/beacons.md Table 1), NOT
        // the Rust variant names. This pins the contract for the HashMap
        // wire paths (Resolver::process_responses, transactions fixtures,
        // and any other HashMap<BeaconType, _> consumer).

        // Deserialize: spec wire strings -> Rust variants.
        assert_eq!(
            serde_json::from_str::<BeaconType>("\"SingletonBeacon\"").unwrap(),
            BeaconType::Singleton
        );
        assert_eq!(
            serde_json::from_str::<BeaconType>("\"CASBeacon\"").unwrap(),
            BeaconType::Cas
        );
        assert_eq!(
            serde_json::from_str::<BeaconType>("\"SMTBeacon\"").unwrap(),
            BeaconType::SparseMerkleTree
        );

        // Serialize: Rust variants -> spec wire strings.
        assert_eq!(
            serde_json::to_string(&BeaconType::Singleton).unwrap(),
            "\"SingletonBeacon\""
        );
        assert_eq!(
            serde_json::to_string(&BeaconType::Cas).unwrap(),
            "\"CASBeacon\""
        );
        assert_eq!(
            serde_json::to_string(&BeaconType::SparseMerkleTree).unwrap(),
            "\"SMTBeacon\""
        );

        // Old Rust-variant-name wire strings must NOT deserialize after the
        // rename — that was the bug.
        assert!(serde_json::from_str::<BeaconType>("\"Singleton\"").is_err());
        assert!(serde_json::from_str::<BeaconType>("\"Cas\"").is_err());
        assert!(serde_json::from_str::<BeaconType>("\"SparseMerkleTree\"").is_err());
    }

    use esploda::bitcoin::blockdata::script::{Builder, PushBytesBuf};
    use esploda::bitcoin::{
        ScriptBuf, Transaction, TxOut, absolute::LockTime, blockdata::opcodes::all::OP_RETURN,
    };

    /// Build an `OP_RETURN <n-byte push>` output for test transactions.
    fn op_return_output(payload: &[u8]) -> TxOut {
        let mut pb = PushBytesBuf::new();
        pb.extend_from_slice(payload)
            .expect("payload fits a single push");
        let script_pubkey: ScriptBuf = Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(&pb)
            .into_script();
        TxOut {
            value: 0,
            script_pubkey,
        }
    }

    /// A non-OP_RETURN output (a bare `OP_TRUE` scriptPubKey is enough for the
    /// last-output-ordering tests).
    fn dummy_output() -> TxOut {
        TxOut {
            value: 1000,
            script_pubkey: Builder::new()
                .push_opcode(esploda::bitcoin::blockdata::opcodes::all::OP_PUSHNUM_1)
                .into_script(),
        }
    }

    fn tx_with_outputs(output: Vec<TxOut>) -> Transaction {
        Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![],
            output,
        }
    }

    /// a transaction whose last output is `OP_RETURN <32-byte push>`
    /// parses into a `SignedBeaconTx`.
    #[test]
    fn signed_beacon_tx_tryfrom_accepts_valid() {
        let signal = [0x42u8; 32];
        let tx = tx_with_outputs(vec![dummy_output(), op_return_output(&signal)]);

        let signed = SignedBeaconTx::try_from(tx.clone()).expect("valid beacon tx must parse");
        assert_eq!(signed.as_tx(), &tx);
        // last output is the OP_RETURN signal
        assert!(
            signed
                .as_tx()
                .output
                .last()
                .unwrap()
                .script_pubkey
                .is_op_return()
        );
    }

    /// OP_RETURN must be LAST. A tx where the OP_RETURN is followed by
    /// another output is rejected (the resolver reads only `outputs.last()`).
    #[test]
    fn signed_beacon_tx_tryfrom_rejects_not_last() {
        let signal = [0x42u8; 32];
        let tx = tx_with_outputs(vec![op_return_output(&signal), dummy_output()]);

        let err = SignedBeaconTx::try_from(tx).expect_err("OP_RETURN-not-last must be rejected");
        assert!(matches!(err, AnnounceError::MissingOpReturnSignal));
    }

    /// the OP_RETURN push must be exactly 32 bytes. A 31-byte push is
    /// rejected with the length carried in the error.
    #[test]
    fn signed_beacon_tx_tryfrom_rejects_wrong_push_len() {
        let short = [0x42u8; 31];
        let tx = tx_with_outputs(vec![op_return_output(&short)]);

        let err =
            SignedBeaconTx::try_from(tx).expect_err("wrong-length signal push must be rejected");
        assert!(matches!(err, AnnounceError::WrongSignalLength { len: 31 }));
    }

    /// a scriptPubKey that is `OP_RETURN <32-byte push>` FOLLOWED BY a
    /// parse error (a truncated push) must be rejected. Under the old
    /// `.flatten()` the trailing Err was silently dropped, leaving exactly
    /// `[OP_RETURN, PushBytes(32)]`, which matched and was (wrongly) accepted.
    /// Collecting into a Result surfaces the error and rejects the transaction.
    #[test]
    fn signed_beacon_tx_tryfrom_rejects_trailing_parse_error() {
        // OP_RETURN (0x6a), OP_PUSHBYTES_32 (0x20) + 32 data bytes, then a
        // truncated OP_PUSHBYTES_5 (0x05) with no following data — an Err at the
        // tail of the instruction stream.
        let mut raw = vec![0x6a, 0x20];
        raw.extend_from_slice(&[0x42u8; 32]);
        raw.push(0x05);
        let script_pubkey = ScriptBuf::from_bytes(raw);
        let tx = tx_with_outputs(vec![TxOut {
            value: 0,
            script_pubkey,
        }]);

        let err = SignedBeaconTx::try_from(tx)
            .expect_err("a script with a trailing instruction-parse error must be rejected");
        assert!(matches!(err, AnnounceError::MissingOpReturnSignal));
    }
}
