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
        // BIP21 URI schemes are case-insensitive (RFC 3986 §3.1); QR encoders
        // routinely uppercase URIs (e.g. `BITCOIN:`). Case-fold the scheme ONLY
        // — the address body stays untouched because Bitcoin addresses are
        // case-sensitive.
        let (scheme, body) = uri.split_once(':').ok_or(Error::InvalidBip21)?;
        if !scheme.eq_ignore_ascii_case("bitcoin") {
            return Err(Error::InvalidBip21);
        }
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
/// API contract: every `Prevout` passed to
/// [`Update::build_unsigned`](crate::Update::build_unsigned) contributes one
/// input to the [`UnsignedBeaconTx`], and each must be
/// spendable by the beacon key that will sign the returned sighashes. The
/// keyless build path does not touch any secret; the ownership cross-check
/// therefore runs at the SIGNING site (where the beacon key lives): for each
/// prevout the signer derives the expected script from the beacon key's public
/// key (the key-hash for P2PKH/P2WPKH, the tweaked output key for P2TR) and
/// compares it against `script_pubkey`, returning
/// [`AnnounceError::KeyDoesNotOwnPrevout`]
/// on mismatch rather than emitting a silently invalid, fund-committing
/// transaction. (Whether the outpoint is unspent is still the caller's I/O
/// concern.)
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
/// JSON Document Hash of the announced update). The core assembles it from an
/// [`UnsignedBeaconTx`] plus the caller's signatures;
/// the public [`TryFrom`] validates the invariant for externally-built
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

/// Which of the three default beacon signing schemes a funding input uses.
///
/// Resolved at build time from the prevout scriptPubKey; carried in the handback
/// so finalize/sign are type-driven rather than re-classifying the script.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BeaconInputScheme {
    /// Legacy pay-to-pubkey-hash (ECDSA, `script_sig`).
    P2pkh,
    /// SegWit v0 pay-to-witness-pubkey-hash (ECDSA, witness).
    P2wpkh,
    /// Taproot key-path (BIP340 Schnorr, witness).
    P2tr,
}

/// The per-input message-to-sign in the construct/sign handback.
///
/// A BIP341 taproot sighash is a *tagged* hash and the legacy/segwit sighashes
/// are double-SHA256 — none is a plain SHA-256 digest — so this is a dedicated
/// domain newtype, NOT a reuse of
/// [`Sha256Hash`](crate::identifier::Sha256Hash). Fixed 32-byte structural
/// invariant; follows the repo two-constructor newtype rule
/// ([`From<[u8; 32]>`](Sighash::from) infallible +
/// [`TryFrom<Vec<u8>>`](Sighash::try_from) length-validating), no
/// `to_hex`/`from_hex` — callers extract via [`as_bytes`](Sighash::as_bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sighash([u8; 32]);

impl From<[u8; 32]> for Sighash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl TryFrom<Vec<u8>> for Sighash {
    type Error = AnnounceError;

    fn try_from(v: Vec<u8>) -> Result<Self, Self::Error> {
        let len = v.len();
        let arr: [u8; 32] = v
            .try_into()
            .map_err(|_| AnnounceError::InvalidSighashLength { len })?;
        Ok(Self(arr))
    }
}

impl Sighash {
    /// The raw 32 sighash bytes. Extract only at the point of signing.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// One funding input of an unsigned beacon-announcement tx, with its
/// precomputed sighash.
///
/// Keeps `value` + `script_pubkey` so a later non-breaking
/// `From<UnsignedBeaconTx> for Psbt` stays possible.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BeaconInput {
    /// Index of this input within the unsigned transaction.
    pub input_index: usize,
    /// The precomputed sighash the caller must sign for this input.
    pub sighash: Sighash,
    /// The signing scheme resolved from the prevout scriptPubKey.
    pub scheme: BeaconInputScheme,
    /// The value of the spent output, in satoshis.
    pub value: u64,
    /// The scriptPubKey of the spent output.
    pub script_pubkey: esploda::bitcoin::ScriptBuf,
}

/// A built-but-unsigned singleton-beacon announcement.
///
/// The unsigned transaction plus each input's precomputed sighash. The core
/// produces this (no secret key); the wallet signs the sighashes and hands
/// `Vec<Sig>` to `finalize`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsignedBeaconTx {
    pub(crate) tx: esploda::bitcoin::Transaction,
    pub(crate) inputs: Vec<BeaconInput>,
}

impl UnsignedBeaconTx {
    /// Borrow the unsigned transaction (e.g. to compute a fee or inspect
    /// outputs).
    pub fn as_tx(&self) -> &esploda::bitcoin::Transaction {
        &self.tx
    }

    /// The per-input handback entries, in transaction input order.
    pub fn inputs(&self) -> &[BeaconInput] {
        &self.inputs
    }

    /// Deterministic predicted vsize for `Fee::Rate` resolution — no signing, no
    /// throwaway keys.
    ///
    /// EXACT for the P2TR key-path default-sighash beacon (64-byte Schnorr); an
    /// upper bound for P2WPKH/P2PKH (ECDSA DER length varies), which never
    /// under-pays the fee. `to_vbytes_ceil()` is `(wu + 3) / 4`, the same math
    /// [`Transaction::vsize`](esploda::bitcoin::Transaction::vsize) uses, so for
    /// the P2TR default-sighash case this equals the real signed tx's `vsize()`.
    pub fn predicted_vsize(&self) -> u64 {
        use esploda::bitcoin::transaction::{InputWeightPrediction, predict_weight};
        // NB: the library consts `InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH`
        // (66-wu witness) and `InputWeightPrediction::P2WPKH_MAX` (109-wu witness)
        // hardcode `script_size: 0`, which omits the 1-byte length prefix of the
        // (empty) scriptSig that a real segwit input always serializes. Using
        // them directly under-counts total vsize by exactly 1 byte per input,
        // breaking the exact P2TR match the fee path relies on. We therefore
        // build the equivalent predictions via `new`, whose scriptSig length
        // prefix is counted correctly, reproducing the same witness sizes.
        let preds: Vec<InputWeightPrediction> = self
            .inputs
            .iter()
            .map(|i| match i.scheme {
                // P2TR key-path default sighash: one 64-byte Schnorr witness
                // element (the 66-wu witness of P2TR_KEY_DEFAULT_SIGHASH). EXACT.
                BeaconInputScheme::P2tr => InputWeightPrediction::new(0usize, [64usize]),
                // P2WPKH with the largest DER signature (the 109-wu witness of
                // P2WPKH_MAX = [73-byte sig, 33-byte pubkey]). UPPER BOUND, since
                // real ECDSA DER length varies — never under-pays.
                BeaconInputScheme::P2wpkh => InputWeightPrediction::new(0usize, [73usize, 33usize]),
                // P2PKH: no witness; script_sig ~= 1 + 73 (sig+sighash) + 1 + 33
                // (pubkey) = 108 B, counted x4 in weight. UPPER BOUND.
                BeaconInputScheme::P2pkh => {
                    InputWeightPrediction::new(108usize, std::iter::empty::<usize>())
                }
            })
            .collect();
        let weight = predict_weight(preds, self.tx.script_pubkey_lens());
        weight.to_vbytes_ceil()
    }

    /// Assemble the broadcastable signed transaction from caller signatures (one
    /// per input, same order as [`inputs`](UnsignedBeaconTx::inputs)), then
    /// re-assert the `OP_RETURN <32>` invariant by routing through
    /// [`SignedBeaconTx::try_from`].
    ///
    /// Bitcoin tx-assembly stays in the tested core: the per-scheme
    /// witness/`script_sig` is built here (P2TR: `[sig]`; P2WPKH: `[sig,
    /// pubkey]`; P2PKH: `<sig><pubkey>` script_sig), so a signal-less tx cannot
    /// be produced. A wrong number of signatures is a typed
    /// [`Signing`](AnnounceError::Signing) error; a signature whose scheme does
    /// not match the input's script type fails closed with
    /// [`SignatureSchemeMismatch`](AnnounceError::SignatureSchemeMismatch)
    /// rather than a panic or a misdiagnosing
    /// [`UnsupportedScriptType`](AnnounceError::UnsupportedScriptType).
    pub fn finalize(self, sigs: &[Sig]) -> Result<SignedBeaconTx, AnnounceError> {
        use esploda::bitcoin::{Witness, blockdata::script::Builder, script::PushBytes};
        if sigs.len() != self.inputs.len() {
            return Err(AnnounceError::Signing(format!(
                "expected {} signatures, got {}",
                self.inputs.len(),
                sigs.len()
            )));
        }
        let mut tx = self.tx;
        for (input, sig) in self.inputs.iter().zip(sigs) {
            let idx = input.input_index;
            match (input.scheme, sig) {
                (BeaconInputScheme::P2tr, Sig::Schnorr(s)) => {
                    let mut w = Witness::new();
                    w.push(s.to_vec());
                    tx.input[idx].witness = w;
                }
                (BeaconInputScheme::P2wpkh, Sig::Ecdsa { sig, pubkey }) => {
                    let mut w = Witness::new();
                    w.push(sig.to_vec());
                    w.push(pubkey.to_bytes());
                    tx.input[idx].witness = w;
                }
                (BeaconInputScheme::P2pkh, Sig::Ecdsa { sig, pubkey }) => {
                    let sig_bytes = sig.to_vec();
                    let sig_push = <&PushBytes>::try_from(sig_bytes.as_slice())
                        .map_err(|e| AnnounceError::Signing(e.to_string()))?;
                    tx.input[idx].script_sig = Builder::new()
                        .push_slice(sig_push)
                        .push_key(pubkey)
                        .into_script();
                }
                // Scheme/Sig mismatch (e.g. a Schnorr sig for an ECDSA scheme):
                // fail closed with the dedicated variant, NOT UnsupportedScriptType.
                _ => return Err(AnnounceError::SignatureSchemeMismatch { index: idx }),
            }
        }
        SignedBeaconTx::try_from(tx) // re-asserts OP_RETURN <32> (parse-don't-validate)
    }
}

/// A caller-supplied signature for one input.
///
/// P2TR key-path needs only the Schnorr signature; P2WPKH/P2PKH additionally
/// need the beacon [`PublicKey`](esploda::bitcoin::PublicKey) for witness /
/// `script_sig` assembly (the core no longer derives it from the secret).
#[derive(Clone, Debug)]
pub enum Sig {
    /// A BIP340 Schnorr signature for a P2TR key-path input.
    Schnorr(esploda::bitcoin::taproot::Signature),
    /// An ECDSA signature plus the beacon public key for a P2PKH/P2WPKH input.
    Ecdsa {
        /// The ECDSA signature over this input's sighash.
        sig: esploda::bitcoin::ecdsa::Signature,
        /// The beacon public key committed to by the prevout scriptPubKey.
        pubkey: esploda::bitcoin::PublicKey,
    },
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

    /// A prevout's scriptPubKey is not spendable by `beacon_secret_key`: the
    /// script the beacon key derives (P2PKH/P2WPKH key-hash, or the P2TR tweaked
    /// output key) does not match `prevout.script_pubkey`. Signing it would
    /// produce a silently invalid, fund-committing transaction, so it is
    /// rejected before signing.
    KeyDoesNotOwnPrevout {
        /// Index of the offending prevout within the supplied slice.
        index: usize,
    },

    /// Sighash computation or signing failed.
    Signing(String),

    /// A caller-supplied signature's scheme does not match the input's script
    /// type (e.g. a Schnorr signature paired with a P2WPKH input). Returned by
    /// [`UnsignedBeaconTx::finalize`] — distinct from
    /// [`UnsupportedScriptType`](AnnounceError::UnsupportedScriptType), which
    /// would misdiagnose this caller-triggerable mismatch.
    SignatureSchemeMismatch {
        /// Index of the offending input within the handback.
        index: usize,
    },

    /// A byte slice offered as a `Sighash` was not exactly 32 bytes.
    InvalidSighashLength {
        /// The actual byte length supplied.
        len: usize,
    },
}

/// BIP341 key-path tweak with NO merkle root (`d' = d + H_TapTweak(P)`).
///
/// Returns the tweaked [`KeyPair`](esploda::bitcoin::secp256k1::KeyPair) the
/// wallet signs a P2TR key-path input with. The tweak modifies the *secret*, so
/// it runs wallet-side (where the beacon key lives), but the finicky,
/// fund-moving computation stays this single core helper rather than being
/// reimplemented per wallet — pinned by the BIP341 known-answer test.
pub fn beacon_taproot_tweak(
    secp: &esploda::bitcoin::secp256k1::Secp256k1<esploda::bitcoin::secp256k1::All>,
    beacon_sk: &esploda::bitcoin::secp256k1::SecretKey,
) -> esploda::bitcoin::secp256k1::KeyPair {
    use esploda::bitcoin::{key::TapTweak, secp256k1::KeyPair};
    let untweaked = KeyPair::from_secret_key(secp, beacon_sk);
    untweaked.tap_tweak(secp, None).to_inner()
}

/// Cross-check that `beacon_sk` actually controls `script_pubkey` for its scheme.
///
/// Derives the expected script (P2PKH/P2WPKH key-hash, or the P2TR *tweaked*
/// output key) and compares it to `script_pubkey`. Fails closed with
/// [`AnnounceError::KeyDoesNotOwnPrevout`] so a foreign-key prevout is never
/// signed into a silently invalid, fund-committing transaction; `index` names
/// the offending input for the caller. This guard is the primary mitigation for
/// the beacon-signing ownership threat, and the P2TR arm's tweaked-key
/// comparison is pinned permanently by the BIP341 known-answer test.
pub fn check_prevout_ownership(
    secp: &esploda::bitcoin::secp256k1::Secp256k1<esploda::bitcoin::secp256k1::All>,
    beacon_sk: &esploda::bitcoin::secp256k1::SecretKey,
    index: usize,
    scheme: BeaconInputScheme,
    script_pubkey: &esploda::bitcoin::ScriptBuf,
) -> Result<(), AnnounceError> {
    use esploda::bitcoin::{PublicKey, ScriptBuf};
    let bitcoin_pubkey = PublicKey::new(beacon_sk.public_key(secp));
    let expected = match scheme {
        BeaconInputScheme::P2pkh => ScriptBuf::new_p2pkh(&bitcoin_pubkey.pubkey_hash()),
        BeaconInputScheme::P2wpkh => match bitcoin_pubkey.wpubkey_hash() {
            Some(wpkh) => ScriptBuf::new_v0_p2wpkh(&wpkh),
            None => return Err(AnnounceError::KeyDoesNotOwnPrevout { index }),
        },
        // new_v1_p2tr applies the BIP341 key-path tweak internally — this
        // compares the TWEAKED output key, the same key the wallet signs with.
        BeaconInputScheme::P2tr => {
            let internal = beacon_sk.x_only_public_key(secp).0;
            ScriptBuf::new_v1_p2tr(secp, internal, None)
        }
    };
    if &expected != script_pubkey {
        return Err(AnnounceError::KeyDoesNotOwnPrevout { index });
    }
    Ok(())
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

    /// `Sighash::try_from(Vec<u8>)` is public API (the runtime-length-validating
    /// constructor). A wrong-length input must be rejected with a typed
    /// `InvalidSighashLength` carrying the actual length; exactly 32 bytes
    /// succeed.
    #[test]
    fn sighash_try_from_validates_length() {
        let err = Sighash::try_from(vec![0u8; 31]).expect_err("31 bytes is not a sighash");
        assert!(
            matches!(err, AnnounceError::InvalidSighashLength { len: 31 }),
            "got {err:?}"
        );
        Sighash::try_from(vec![0u8; 32]).expect("32 bytes is a valid sighash");
    }

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

    /// BIP21 URI schemes are case-insensitive (RFC 3986). An uppercase
    /// `BITCOIN:` and a mixed-case `Bitcoin:` URI must parse to the SAME address
    /// as the lowercase form; the address body is never case-folded.
    #[test]
    fn bip21_scheme_is_case_insensitive() {
        let addr = "mh8h6FXkMzHaW4RKerGT33ZLqx52xL28dU";
        let lower = Address::from_bip21(&format!("bitcoin:{addr}"), Network::Regtest)
            .expect("lowercase scheme parses");
        let upper = Address::from_bip21(&format!("BITCOIN:{addr}"), Network::Regtest)
            .expect("uppercase scheme parses");
        let mixed = Address::from_bip21(&format!("Bitcoin:{addr}"), Network::Regtest)
            .expect("mixed-case scheme parses");
        assert_eq!(lower, upper, "BITCOIN: must equal bitcoin:");
        assert_eq!(lower, mixed, "Bitcoin: must equal bitcoin:");
    }

    /// A beacon `serviceEndpoint` BIP21 URI is
    /// attacker-controllable; a well-formed URI carrying a valid MAINNET address
    /// parsed with `Network::Regtest` must be rejected as `AddressParse` (the
    /// network-validation failure), NOT `InvalidBip21` (a shape failure, which
    /// `test_invalid_beacon_address_uri` covers). This prevents a beacon from
    /// being watched on the wrong chain.
    ///
    /// The URI carries a valid mainnet bech32 address (BIP173 test vector), so it
    /// clears the `bitcoin:`-prefix + `req-` shape checks FIRST (beacon.rs:44-62,
    /// confirmed to precede network validation); the failure lands at
    /// `require_network(Regtest)` (beacon.rs:66), surfaced as `AddressParse`.
    /// (The `multibase_decode` length half of this rule lives in cryptosuite.rs.)
    #[test]
    fn test_from_bip21_rejects_network_mismatched_address() {
        let uri = "bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let result = Address::from_bip21(uri, Network::Regtest);
        assert!(
            matches!(result, Err(Error::AddressParse(_))),
            "mainnet address parsed with Regtest must be AddressParse, got {result:?}"
        );
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

    // ---- predicted_vsize: exact for P2TR default-sighash, bound for ECDSA

    /// A 1-input / 2-output unsigned beacon tx with the given input scheme. The
    /// input starts empty (no script_sig / witness); the two outputs (a change
    /// script + an OP_RETURN 32-byte signal) mirror the real build shape so the
    /// non-witness serialization matches an actual finalized tx.
    fn unsigned_one_input(scheme: BeaconInputScheme) -> UnsignedBeaconTx {
        use esploda::bitcoin::{OutPoint, Sequence, TxIn, Txid, Witness, hashes::Hash};
        let spk =
            ScriptBuf::new_v0_p2wpkh(&esploda::bitcoin::WPubkeyHash::from_byte_array([7u8; 20]));
        let txin = TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0u8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        };
        let tx = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![txin],
            output: vec![
                TxOut {
                    value: 90_000,
                    script_pubkey: spk.clone(),
                },
                op_return_output(&[0x11u8; 32]),
            ],
        };
        let input = BeaconInput {
            input_index: 0,
            sighash: Sighash::from([0u8; 32]),
            scheme,
            value: 100_000,
            script_pubkey: spk,
        };
        UnsignedBeaconTx {
            tx,
            inputs: vec![input],
        }
    }

    /// P2TR key-path default sighash uses a fixed 64-byte Schnorr signature, so
    /// the prediction is EXACT: attaching a real 64-byte witness reproduces the
    /// predicted vsize to the byte.
    #[test]
    fn predicted_vsize_p2tr_is_exact() {
        use esploda::bitcoin::Witness;
        let unsigned = unsigned_one_input(BeaconInputScheme::P2tr);
        let mut signed = unsigned.as_tx().clone();
        let mut w = Witness::new();
        w.push([0u8; 64]); // 64-byte key-path default-sighash Schnorr signature
        signed.input[0].witness = w;
        assert_eq!(
            unsigned.predicted_vsize(),
            u64::try_from(signed.vsize()).expect("vsize fits u64"),
            "P2TR default-sighash predicted vsize must equal the real signed vsize"
        );
    }

    /// P2WPKH ECDSA signatures vary in DER length, so the prediction is an UPPER
    /// BOUND (never under-pays): a representative ~72-byte-sig witness yields a
    /// real vsize at or below the prediction.
    #[test]
    fn predicted_vsize_p2wpkh_is_upper_bound() {
        use esploda::bitcoin::Witness;
        let unsigned = unsigned_one_input(BeaconInputScheme::P2wpkh);
        let mut signed = unsigned.as_tx().clone();
        let mut w = Witness::new();
        w.push([0u8; 72]); // representative max-length DER ECDSA signature
        w.push([0u8; 33]); // compressed public key
        signed.input[0].witness = w;
        assert!(
            unsigned.predicted_vsize() >= u64::try_from(signed.vsize()).expect("vsize fits u64"),
            "P2WPKH predicted vsize must be an upper bound on the real signed vsize"
        );
    }

    // ---- Task 1/2/3: tweak + ownership helpers, finalize, BIP341 KAT --------
    mod sign_tests {
        use super::super::{
            AnnounceError, BeaconInputScheme, Sig, beacon_taproot_tweak, check_prevout_ownership,
        };
        use crate::Update;
        use crate::beacon::Prevout;
        use esploda::bitcoin::{
            Address, Amount, Network as BtcNetwork, OutPoint, PublicKey, ScriptBuf, Txid,
            consensus, ecdsa,
            hashes::Hash as _,
            secp256k1::{All, KeyPair, Message, Secp256k1, SecretKey, schnorr},
            sighash::{EcdsaSighashType, TapSighashType},
            taproot,
        };

        /// A deterministic beacon secret key.
        fn test_secret_key() -> SecretKey {
            SecretKey::from_slice(&[0x07; 32]).expect("0x07.. is a valid secret key")
        }

        fn p2pkh_address(secp: &Secp256k1<All>, sk: &SecretKey) -> Address {
            Address::p2pkh(&PublicKey::new(sk.public_key(secp)), BtcNetwork::Regtest)
        }
        fn p2wpkh_address(secp: &Secp256k1<All>, sk: &SecretKey) -> Address {
            Address::p2wpkh(&PublicKey::new(sk.public_key(secp)), BtcNetwork::Regtest)
                .expect("compressed key yields p2wpkh")
        }
        fn p2tr_address(secp: &Secp256k1<All>, sk: &SecretKey) -> Address {
            let (xonly, _) = KeyPair::from_secret_key(secp, sk).x_only_public_key();
            Address::p2tr(secp, xonly, None, BtcNetwork::Regtest)
        }
        fn change_address(secp: &Secp256k1<All>) -> Address {
            let sk = SecretKey::from_slice(&[0x09; 32]).expect("valid key");
            p2wpkh_address(secp, &sk)
        }
        fn outpoint(n: u32) -> OutPoint {
            OutPoint {
                txid: Txid::from_byte_array([n as u8; 32]),
                vout: n,
            }
        }
        /// The golden signed update is only used as a signal source (finalize /
        /// build_unsigned consume its `hash()`), so any valid Update works.
        fn sample_update() -> Update {
            let raw = include_str!("../fixtures/spec-form/golden-signed-update.json");
            Update::from_json_string(raw).expect("golden signed update parses")
        }

        // ---- Task 1: ownership guard fails closed on a non-owning key --------

        /// A P2TR scriptPubKey built from a DIFFERENT key must be rejected by the
        /// ownership guard as `KeyDoesNotOwnPrevout` (the T1 mitigation).
        #[test]
        fn ownership_rejects_foreign_p2tr_key() {
            let secp = Secp256k1::new();
            let mine = test_secret_key();
            let other = SecretKey::from_slice(&[0x11u8; 32]).expect("valid key");
            let other_internal = other.x_only_public_key(&secp).0;
            let other_spk = ScriptBuf::new_v1_p2tr(&secp, other_internal, None);
            assert!(
                matches!(
                    check_prevout_ownership(&secp, &mine, 0, BeaconInputScheme::P2tr, &other_spk),
                    Err(AnnounceError::KeyDoesNotOwnPrevout { index: 0 })
                ),
                "a foreign-key P2TR prevout must fail closed"
            );
        }

        /// The guard ACCEPTS the P2TR scriptPubKey the key actually owns.
        #[test]
        fn ownership_accepts_owning_p2tr_key() {
            let secp = Secp256k1::new();
            let sk = test_secret_key();
            let spk = ScriptBuf::new_v1_p2tr(&secp, sk.x_only_public_key(&secp).0, None);
            check_prevout_ownership(&secp, &sk, 0, BeaconInputScheme::P2tr, &spk)
                .expect("owning key must be accepted");
        }

        // ---- Task 2: finalize failure paths (typed, no panic) ---------------

        /// A wrong number of signatures is a typed `Signing` error.
        #[test]
        fn finalize_length_mismatch_is_typed_error() {
            let unsigned = super::unsigned_one_input(BeaconInputScheme::P2tr);
            let err = unsigned
                .finalize(&[])
                .expect_err("0 sigs for a 1-input tx must error");
            assert!(matches!(err, AnnounceError::Signing(_)), "got {err:?}");
        }

        /// A Schnorr signature for a P2WPKH input fails closed with the dedicated
        /// `SignatureSchemeMismatch` variant, NOT `UnsupportedScriptType`.
        #[test]
        fn finalize_scheme_mismatch_is_typed_error() {
            let unsigned = super::unsigned_one_input(BeaconInputScheme::P2wpkh);
            let schnorr = schnorr::Signature::from_slice(&[0u8; 64]).expect("64-byte parse");
            let sig = Sig::Schnorr(taproot::Signature {
                sig: schnorr,
                hash_ty: TapSighashType::Default,
            });
            let err = unsigned
                .finalize(&[sig])
                .expect_err("Schnorr sig on a P2WPKH input must be rejected");
            assert!(
                matches!(err, AnnounceError::SignatureSchemeMismatch { index: 0 }),
                "got {err:?}"
            );
        }

        // ---- Task 2: real-signature oracle over finalize's OUTPUT -----------

        /// finalize's assembled P2PKH input passes bitcoinconsensus `Script::verify`.
        #[test]
        fn finalize_p2pkh_verifies_under_bitcoinconsensus() {
            let secp = Secp256k1::new();
            let sk = test_secret_key();
            let addr = p2pkh_address(&secp, &sk);
            let value = 100_000u64;
            let prevouts = vec![Prevout {
                outpoint: outpoint(0),
                value,
                script_pubkey: addr.script_pubkey(),
            }];
            let unsigned = sample_update()
                .build_unsigned(&addr, &prevouts, 1_000, &change_address(&secp))
                .expect("build_unsigned");
            let input = &unsigned.inputs()[0];
            let msg = Message::from_slice(input.sighash.as_bytes()).expect("32-byte msg");
            let sig = Sig::Ecdsa {
                sig: ecdsa::Signature {
                    sig: secp.sign_ecdsa(&msg, &sk),
                    hash_ty: EcdsaSighashType::All,
                },
                pubkey: PublicKey::new(sk.public_key(&secp)),
            };
            let signed = unsigned.finalize(&[sig]).expect("finalize");
            assert!(
                !signed.as_tx().input[0].script_sig.is_empty(),
                "P2PKH finalize must populate script_sig"
            );
            let serialized = consensus::encode::serialize(signed.as_tx());
            addr.script_pubkey()
                .verify(0, Amount::from_sat(value), &serialized)
                .expect("finalize's P2PKH output must verify under bitcoinconsensus");
        }

        /// finalize's assembled P2WPKH witness `[sig, pubkey]` passes bitcoinconsensus.
        #[test]
        fn finalize_p2wpkh_verifies_under_bitcoinconsensus() {
            let secp = Secp256k1::new();
            let sk = test_secret_key();
            let addr = p2wpkh_address(&secp, &sk);
            let value = 100_000u64;
            let prevouts = vec![Prevout {
                outpoint: outpoint(0),
                value,
                script_pubkey: addr.script_pubkey(),
            }];
            let unsigned = sample_update()
                .build_unsigned(&addr, &prevouts, 1_000, &change_address(&secp))
                .expect("build_unsigned");
            let input = &unsigned.inputs()[0];
            let msg = Message::from_slice(input.sighash.as_bytes()).expect("32-byte msg");
            let sig = Sig::Ecdsa {
                sig: ecdsa::Signature {
                    sig: secp.sign_ecdsa(&msg, &sk),
                    hash_ty: EcdsaSighashType::All,
                },
                pubkey: PublicKey::new(sk.public_key(&secp)),
            };
            let signed = unsigned.finalize(&[sig]).expect("finalize");
            assert_eq!(
                signed.as_tx().input[0].witness.len(),
                2,
                "P2WPKH witness must be [sig, pubkey]"
            );
            let serialized = consensus::encode::serialize(signed.as_tx());
            addr.script_pubkey()
                .verify(0, Amount::from_sat(value), &serialized)
                .expect("finalize's P2WPKH output must verify under bitcoinconsensus");
        }

        /// finalize's assembled P2TR witness `[sig]` verifies as a direct BIP340
        /// Schnorr signature against the tweaked output key (the pinned
        /// bitcoinconsensus has no taproot support, so verify directly).
        #[test]
        fn finalize_p2tr_verifies_direct_schnorr() {
            let secp = Secp256k1::new();
            let sk = test_secret_key();
            let addr = p2tr_address(&secp, &sk);
            let value = 100_000u64;
            let prevouts = vec![Prevout {
                outpoint: outpoint(0),
                value,
                script_pubkey: addr.script_pubkey(),
            }];
            let unsigned = sample_update()
                .build_unsigned(&addr, &prevouts, 1_000, &change_address(&secp))
                .expect("build_unsigned");
            let input = &unsigned.inputs()[0];
            let msg = Message::from_slice(input.sighash.as_bytes()).expect("32-byte msg");
            let tweaked = beacon_taproot_tweak(&secp, &sk);
            let schnorr = secp.sign_schnorr_no_aux_rand(&msg, &tweaked);
            let sig = Sig::Schnorr(taproot::Signature {
                sig: schnorr,
                hash_ty: TapSighashType::Default,
            });
            let signed = unsigned.finalize(&[sig]).expect("finalize");
            let witness = signed.as_tx().input[0].witness.to_vec();
            assert_eq!(witness.len(), 1, "P2TR key-path witness must be [sig]");
            let (xonly, _) = tweaked.x_only_public_key();
            let got = schnorr::Signature::from_slice(&witness[0][..64]).expect("64-byte sig");
            assert!(
                secp.verify_schnorr(&got, &msg, &xonly).is_ok(),
                "finalize's P2TR signature must verify against the tweaked output key"
            );
        }

        // ---- Task 3: BIP341 known-answer taproot vector (PERMANENT) ---------

        /// BIP341 `wallet-test-vectors.json` `keyPathSpending[0].inputSpending[0]`
        /// (merkleRoot = None). Permanent KAT pinning the fund-moving P2TR
        /// tweaked-key + ownership comparison. MUST NOT be deleted or
        /// `#[ignore]`d.
        #[test]
        fn bip341_taproot_known_answer_vector() {
            let secp = Secp256k1::new();
            let d = SecretKey::from_slice(
                &hex::decode("6b973d88838f27366ed61c9ad6367663045cb456e28335c109e30717ae0c6baa")
                    .unwrap(),
            )
            .unwrap();
            // Secret/signing path: the tweaked keypair == (Q, d').
            let tweaked = beacon_taproot_tweak(&secp, &d);
            assert_eq!(
                hex::encode(tweaked.x_only_public_key().0.serialize()),
                "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343", // Q
            );
            assert_eq!(
                hex::encode(tweaked.secret_bytes()),
                "2405b971772ad26915c8dcdf10f238753a9b837e5f8e6a86fd7c0cce5b7296d9", // d'
            );
            // Ownership path: derived scriptPubKey == the vector's output script,
            // and the guard accepts the owning key.
            let internal = d.x_only_public_key(&secp).0;
            let spk = ScriptBuf::new_v1_p2tr(&secp, internal, None);
            assert_eq!(
                hex::encode(spk.as_bytes()),
                "512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343",
            );
            check_prevout_ownership(&secp, &d, 0, BeaconInputScheme::P2tr, &spk)
                .expect("owning key accepted");
            // Failure: a different key must NOT pass the guard for this scriptPubKey.
            let other = SecretKey::from_slice(&[0x11u8; 32]).unwrap();
            assert!(matches!(
                check_prevout_ownership(&secp, &other, 0, BeaconInputScheme::P2tr, &spk),
                Err(AnnounceError::KeyDoesNotOwnPrevout { index: 0 })
            ));
        }
    }
}
