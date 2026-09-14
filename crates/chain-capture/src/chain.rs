//! Chain operations for a minting session: funding, confirmation, and the one
//! place a block is produced.
//!
//! A minted scenario is re-minted on successively more durable chains — a local
//! regtest stack first, then a public test chain — and every chain regenerates
//! the fixtures, their txids, heights and block times. The two chain families
//! differ in exactly two operations: on a chain the operator controls, funding is
//! a wallet transfer and confirmation is a block mined on demand; on a chain that
//! mines itself, funding is a faucet transfer and confirmation is a poll. Both
//! live behind [`ChainOps`] so moving between them is an operator session against
//! an unchanged tool rather than a code change.
//!
//! The bitcoind JSON-RPC client rides the existing `BtcTransport` seam rather
//! than a second HTTP client, so the auth header, the request envelope, the error
//! mapping and the amount conversion are all unit-testable with no daemon
//! running and no network.

use base64::Engine as _;
use did_btcr2_client::{
    BtcTransport, EsploraUtxo, TransportError, UreqTransport, confirmed_total, fetch_utxos,
};
use esploda::bitcoin::Address;
use esploda::esplora::{Status, Transaction};
use onlyerror::Error;
use serde_json::{Value, json};
use std::time::Duration;

use crate::secret::Secret;

/// Blocks that must be mined before a coinbase output is spendable. Bitcoin
/// consensus, not a tuning knob: a freshly started regtest wallet has no
/// spendable balance until this many blocks are on top of its first coinbase.
const COINBASE_MATURITY_BLOCKS: u32 = 101;

/// Satoshis in one bitcoin. The JSON-RPC amount fields are denominated in BTC,
/// so every amount crossing that boundary is converted here and nowhere else.
const SATS_PER_BTC: u64 = 100_000_000;

/// How long a wait loop waits, and how many times.
///
/// A chain the tool mines answers within a second, so it polls fast and briefly;
/// a public chain has to wait for a human at a faucet and for real block
/// intervals, so it polls slowly and for about ten minutes. Both are bounded: an
/// unattended loop that never gives up is a wedged session with no diagnosis.
#[derive(Debug, Clone, Copy)]
struct Poll {
    /// Wait between attempts.
    interval: Duration,
    /// How many attempts before the named timeout.
    attempts: u32,
}

impl Poll {
    /// The loop for a chain whose blocks this tool produces.
    const fn on_demand() -> Self {
        Self {
            interval: Duration::from_secs(1),
            attempts: 60,
        }
    }

    /// The loop for a chain that mines itself.
    const fn self_mining() -> Self {
        Self {
            interval: Duration::from_secs(15),
            attempts: 40,
        }
    }

    /// The loop for waiting on a self-mining chain to settle several blocks
    /// past an announcement: block intervals rather than a single
    /// confirmation, so it is allowed about an hour.
    const fn settling() -> Self {
        Self {
            interval: Duration::from_secs(30),
            attempts: 120,
        }
    }

    /// The bound, rendered for a timeout message, so the operator is told how
    /// long the tool actually waited rather than being left to guess.
    fn budget(&self) -> String {
        let seconds = self.interval.as_secs() * u64::from(self.attempts);
        format!("{} attempts over ~{seconds}s", self.attempts)
    }
}

/// Chain-layer failures. No variant carries the `Authorization` header or the
/// request body: the credential belongs in a header and nowhere else, and an
/// error is the easiest place for it to escape into a log.
#[derive(Debug, Error)]
pub enum ChainError {
    /// bitcoind answered with a JSON-RPC error object.
    #[error("bitcoind rejected `{method}`: error {code}: {message}")]
    Rpc {
        /// The JSON-RPC method that was called.
        method: String,
        /// bitcoind's own error code.
        code: i64,
        /// bitcoind's own error message.
        message: String,
    },

    /// bitcoind answered with a non-2xx status and no JSON-RPC error object.
    #[error(
        "bitcoind answered HTTP {status} to `{method}` with no JSON-RPC error — check --bitcoind-url points at the node's RPC port and --bitcoind-auth is `user:password` for it"
    )]
    RpcHttp {
        /// The JSON-RPC method that was called.
        method: String,
        /// The HTTP status that came back.
        status: u16,
    },

    /// bitcoind's reply parsed as JSON but is not the shape the caller needs.
    #[error("bitcoind's reply to `{method}` is not the shape this tool expects: {detail}")]
    RpcResultShape {
        /// The JSON-RPC method that was called.
        method: String,
        /// What was expected, and what came back instead.
        detail: String,
    },

    /// The funding wait gave up.
    #[error(
        "funding timed out on {network}: {address} still holds less than {needed_sats} confirmed sats after {waited}"
    )]
    FundingTimeout {
        /// The chain being minted on.
        network: String,
        /// The address that was being funded.
        address: String,
        /// How many confirmed sats the address needed.
        needed_sats: u64,
        /// The bound that was exhausted.
        waited: String,
    },

    /// The confirmation wait gave up.
    #[error(
        "confirmation timed out on {network}: {txid} is still unconfirmed after {waited} — the transaction is broadcast, so re-running resumes rather than re-broadcasting"
    )]
    ConfirmationTimeout {
        /// The chain being minted on.
        network: String,
        /// The transaction that never confirmed.
        txid: String,
        /// The bound that was exhausted.
        waited: String,
    },

    /// The settlement wait gave up: the tip did not reach the height that
    /// gives the last announcement its confirmations.
    #[error(
        "settlement timed out on {network}: the tip is {tip}, still short of {height}, after {waited} — the announcements are on chain, so re-running resumes the wait rather than re-broadcasting"
    )]
    SettlementTimeout {
        /// The chain being minted on.
        network: String,
        /// The height the tip had to reach.
        height: u32,
        /// The tip that was last observed.
        tip: u32,
        /// The bound that was exhausted.
        waited: String,
    },

    /// A chain the tool must mine on was named without an RPC endpoint.
    #[error(
        "--network regtest needs --bitcoind-url and --bitcoind-auth — nothing else can produce a block on a chain started with autoMineMode: 0. For the shipped Polar export these are --bitcoind-url http://127.0.0.1:18443 --bitcoind-auth polaruser:polarpass (see RUNBOOK.md Part 3)."
    )]
    MissingBitcoindEndpoint,

    /// An Esplora read failed (a UTXO query or a transaction lookup).
    Client(#[from] did_btcr2_client::Error),

    /// The RPC request could not be built or executed.
    Transport(#[from] TransportError),

    /// A JSON body could not be built or read.
    Json(#[from] serde_json::Error),
}

/// The chain operations a minting session needs, abstracted over whether the
/// operator controls block production.
///
/// The first rung of the chain ladder is a local regtest chain this tool mines on
/// demand; later rungs are public chains that mine themselves. Both rungs are the
/// SAME tool invocation with a different `--network`, which is why this is a
/// trait from the start rather than when the second rung is climbed.
pub trait ChainOps {
    /// The network name, for messages.
    fn network(&self) -> &str;

    /// Whether this tool produces the chain's blocks.
    ///
    /// Names which rung of the ladder a session is on, and is what makes the
    /// backend chosen by [`ops_for`] observable — otherwise the choice is only
    /// visible in the timing of a wait loop.
    fn mines_on_demand(&self) -> bool;

    /// Ensure `address` holds at least `needed_sats` in CONFIRMED, spendable
    /// outputs.
    ///
    /// Announcement building selects confirmed outputs only, so an unmined
    /// transfer is not funding.
    fn ensure_funded(&self, address: &Address, needed_sats: u64) -> Result<(), ChainError>;

    /// Block until `txid` is confirmed. Returns `(block_height, block_time)`.
    fn await_confirmation(&self, txid: &str) -> Result<(u32, i64), ChainError>;

    /// Bring the chain tip to at least `height` and return the tip reached.
    ///
    /// An announcement confirmed at height `h` has `tip - h + 1`
    /// confirmations, and a resolver processes it only once that reaches its
    /// `minConf` (six by default). A fixture captured with the tip still in
    /// the last announcement's block would replay only under a lowered
    /// `minConf`, so a session settles the chain past its last announcement
    /// before the fixture is captured. On a chain this tool mines that is the
    /// missing blocks produced now; on a chain that mines itself it is a
    /// wait. Idempotent: a tip already at or past `height` is left alone, so
    /// a re-run of a completed session does not keep moving it.
    fn settle(&self, height: u32) -> Result<u32, ChainError>;
}

/// A minimal bitcoind JSON-RPC client over the existing transport seam.
///
/// Rides `BtcTransport` rather than a second HTTP client so the auth header, the
/// envelope, the error mapping and the amount conversion are all unit-testable
/// against a fake transport, with no daemon running.
pub struct BitcoindRpc<T: BtcTransport> {
    transport: T,
    url: String,
    /// `"Basic <base64(user:pass)>"`. NEVER logged: [`Secret`]'s own `Debug`
    /// renders it redacted, the manual `Debug` impl below does too, and no error
    /// variant carries it.
    ///
    /// The header has to live for the whole session — every RPC call re-sends
    /// it — so it is held rather than rebuilt, and held in the type that
    /// overwrites its bytes when the client is dropped. What that does NOT reach
    /// is the base64 `String` the encoder returns on the way in: overwriting a
    /// `String`'s buffer needs `unsafe`, which this crate forbids, so that one
    /// heap copy is freed intact. Stated rather than left for a reader to
    /// discover.
    auth: Secret,
}

// `Debug` is implemented BY HAND, not derived: a derived one would print the
// `auth` field, putting the node credentials into any `{:?}` and into any error
// or log line that happens to wrap this struct.
impl<T: BtcTransport> std::fmt::Debug for BitcoindRpc<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BitcoindRpc")
            .field("url", &self.url)
            .field("auth", &"<redacted>")
            .finish()
    }
}

impl<T: BtcTransport> BitcoindRpc<T> {
    /// Build a client for `url`, authenticating with `user_pass` (`user:password`).
    pub fn new(transport: T, url: String, user_pass: &Secret) -> Self {
        Self {
            transport,
            url,
            auth: Secret::from_exposed(&format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(user_pass.expose())
            )),
        }
    }

    /// Issue one JSON-RPC call.
    ///
    /// bitcoind answers an RPC-level error with a non-2xx status AND a JSON-RPC
    /// error object, so the body is inspected before the status: reading the
    /// status first would turn every "wallet already loaded" into an opaque HTTP
    /// failure. A non-2xx with no error object — an auth rejection, a proxy, a
    /// wrong port — falls through to the status-naming error.
    fn call(&self, method: &str, params: Value) -> Result<Value, ChainError> {
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "1.0",
            "id": "chain-capture",
            "method": method,
            "params": params,
        }))?;
        let request = http::Request::post(self.url.as_str())
            .header(http::header::AUTHORIZATION, self.auth.expose())
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(body)
            .map_err(|e| TransportError::Io(std::io::Error::other(e.to_string())))?;

        let response = self.transport.execute(request)?;
        let status = response.status().as_u16();
        let envelope: Option<Value> = serde_json::from_slice(response.body()).ok();

        if let Some(error) = envelope
            .as_ref()
            .and_then(|e| e.get("error"))
            .filter(|e| !e.is_null())
        {
            return Err(ChainError::Rpc {
                method: method.to_string(),
                code: error.get("code").and_then(Value::as_i64).unwrap_or(0),
                message: error
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("(no message)")
                    .to_string(),
            });
        }
        if !(200..300).contains(&status) {
            return Err(ChainError::RpcHttp {
                method: method.to_string(),
                status,
            });
        }
        let envelope = envelope.ok_or_else(|| ChainError::RpcResultShape {
            method: method.to_string(),
            detail: "the response body is not JSON".to_string(),
        })?;
        Ok(envelope.get("result").cloned().unwrap_or(Value::Null))
    }

    /// A shape failure for `method`, naming what was expected.
    fn shape(method: &str, expected: &str, got: &Value) -> ChainError {
        ChainError::RpcResultShape {
            method: method.to_string(),
            detail: format!("expected {expected}, got `{got}`"),
        }
    }

    /// The loaded wallet's spendable balance, in BTC.
    pub fn get_balance(&self) -> Result<f64, ChainError> {
        let result = self.call("getbalance", json!([]))?;
        result
            .as_f64()
            .ok_or_else(|| Self::shape("getbalance", "an amount in BTC", &result))
    }

    /// A fresh address from the loaded wallet, used as a mining destination.
    pub fn get_new_address(&self) -> Result<String, ChainError> {
        let result = self.call("getnewaddress", json!([]))?;
        result
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| Self::shape("getnewaddress", "an address", &result))
    }

    /// Load a wallet by name; `""` is the node's default wallet.
    ///
    /// An already-loaded (code -35) or already-existing (code -4) wallet is the
    /// state this call is trying to reach, so both are success. A session is
    /// resumable, so this runs on every invocation and must not fail the second
    /// time.
    pub fn load_wallet(&self, name: &str) -> Result<(), ChainError> {
        match self.call("loadwallet", json!([name])) {
            Ok(_) => Ok(()),
            Err(ChainError::Rpc { code, .. }) if code == -35 || code == -4 => Ok(()),
            Err(other) => Err(other),
        }
    }

    /// Send `sats` from the loaded wallet to `addr`, returning the txid.
    ///
    /// The RPC takes an amount in BTC as a JSON number, so the conversion happens
    /// here and nowhere else (see [`sats_to_btc`]).
    pub fn send_to_address(&self, addr: &str, sats: u64) -> Result<String, ChainError> {
        let result = self.call("sendtoaddress", json!([addr, sats_to_btc(sats)]))?;
        result
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| Self::shape("sendtoaddress", "a txid", &result))
    }

    /// Produce `n` blocks paying `addr`, returning their hashes.
    ///
    /// The ONLY place this tool produces a block. Mining moves the regtest tip,
    /// which is what a minting session is for; every committed chain fixture
    /// replays from its own file, so a moved tip invalidates nothing already
    /// captured. Re-capturing a vendor vector after mining needs a fresh unpack
    /// of the export (see `RUNBOOK.md`).
    pub fn generate_to_address(&self, n: u32, addr: &str) -> Result<Vec<String>, ChainError> {
        let result = self.call("generatetoaddress", json!([n, addr]))?;
        result
            .as_array()
            .map(|hashes| {
                hashes
                    .iter()
                    .filter_map(|h| h.as_str().map(str::to_string))
                    .collect()
            })
            .ok_or_else(|| Self::shape("generatetoaddress", "a list of block hashes", &result))
    }
}

/// Convert satoshis to the BTC amount the JSON-RPC amount fields carry.
///
/// Built from the integer parts rather than by dividing a float, so the decimal
/// text is exact for any whole number of satoshis; eight decimal places is
/// bitcoin's full precision, so nothing is lost.
fn sats_to_btc(sats: u64) -> f64 {
    format!("{}.{:08}", sats / SATS_PER_BTC, sats % SATS_PER_BTC)
        .parse()
        .expect("a decimal literal built from two integers parses as f64")
}

/// Convert a BTC amount from the JSON-RPC surface back to satoshis.
///
/// Saturating rather than wrapping, and non-finite or negative input becomes
/// zero: this feeds a "do we have enough?" comparison, where under-reporting
/// causes an extra mine and over-reporting causes an unfunded transaction.
fn btc_to_sats(btc: f64) -> u64 {
    if !btc.is_finite() || btc <= 0.0 {
        return 0;
    }
    let sats = (btc * SATS_PER_BTC as f64).round();
    if sats >= 2f64.powi(64) {
        u64::MAX
    } else {
        sats as u64
    }
}

/// Confirmed, spendable value at `address`.
fn confirmed_sats<T: BtcTransport>(
    reads: &T,
    esplora_base: &str,
    address: &Address,
) -> Result<u64, ChainError> {
    let utxos: Vec<EsploraUtxo> = fetch_utxos(reads, esplora_base, address)?;
    Ok(confirmed_total(&utxos))
}

/// The height of the chain tip as the Esplora index reports it.
fn tip_height<T: BtcTransport>(reads: &T, esplora_base: &str) -> Result<u32, ChainError> {
    let request = http::Request::get(format!("{esplora_base}/blocks/tip/height"))
        .body(Vec::new())
        .map_err(|e| TransportError::Io(std::io::Error::other(e.to_string())))?;
    let response = reads.execute(request)?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(TransportError::Status {
            status,
            body: String::from_utf8_lossy(response.body()).into_owned(),
        }
        .into());
    }
    let body = String::from_utf8_lossy(response.body());
    body.trim().parse().map_err(|_| {
        TransportError::Malformed(format!(
            "`/blocks/tip/height` answered `{}`, not a block height",
            body.trim()
        ))
        .into()
    })
}

/// Poll the Esplora index until its tip is at least `height`, returning the
/// tip reached or the named timeout. Shared by both chain families: on a
/// chain this tool mines the blocks already exist and only the index has to
/// catch up; on a chain that mines itself this IS the wait.
fn await_tip<T: BtcTransport>(
    reads: &T,
    esplora_base: &str,
    network: &str,
    height: u32,
    poll: &Poll,
) -> Result<u32, ChainError> {
    let mut last_tip = 0;
    for attempt in 0..poll.attempts {
        last_tip = tip_height(reads, esplora_base)?;
        if last_tip >= height {
            return Ok(last_tip);
        }
        if attempt + 1 < poll.attempts {
            std::thread::sleep(poll.interval);
        }
    }
    Err(ChainError::SettlementTimeout {
        network: network.to_string(),
        height,
        tip: last_tip,
        waited: poll.budget(),
    })
}

/// `(block_height, block_time)` for `txid`, or `None` while it is unconfirmed or
/// not yet indexed.
///
/// A 404 is `None` rather than an error: an endpoint indexes a newly broadcast
/// transaction asynchronously, so "not there yet" is an ordinary state of the
/// wait loop this feeds.
fn confirmation_of<T: BtcTransport>(
    reads: &T,
    esplora_base: &str,
    txid: &str,
) -> Result<Option<(u32, i64)>, ChainError> {
    let request = http::Request::get(format!("{esplora_base}/tx/{txid}"))
        .body(Vec::new())
        .map_err(|e| TransportError::Io(std::io::Error::other(e.to_string())))?;
    let response = reads.execute(request)?;
    let status = response.status().as_u16();
    if status == 404 {
        return Ok(None);
    }
    if !(200..300).contains(&status) {
        return Err(TransportError::Status {
            status,
            body: String::from_utf8_lossy(response.body()).into_owned(),
        }
        .into());
    }
    let tx: Transaction = serde_json::from_slice(response.body())?;
    Ok(match tx.status {
        Status::Confirmed {
            block_height,
            block_time,
            ..
        } => Some((block_height, block_time.timestamp())),
        Status::Unconfirmed => None,
    })
}

/// A chain the tool controls: fund from the node's wallet, confirm by mining.
pub struct RegtestOps<T: BtcTransport> {
    network: String,
    esplora_base: String,
    /// Esplora reads (`/address/{a}/utxo`, `/tx/{txid}`) go here.
    reads: T,
    rpc: BitcoindRpc<T>,
    poll: Poll,
}

impl<T: BtcTransport> RegtestOps<T> {
    /// Build the operator-controlled backend.
    pub fn new(network: String, esplora_base: String, reads: T, rpc: BitcoindRpc<T>) -> Self {
        Self {
            network,
            esplora_base,
            reads,
            rpc,
            poll: Poll::on_demand(),
        }
    }

    /// Shorten the wait loop so a timeout is reachable in a unit test.
    #[cfg(test)]
    fn with_poll(mut self, poll: Poll) -> Self {
        self.poll = poll;
        self
    }

    /// Mine one block to a fresh wallet address.
    fn mine_one(&self) -> Result<(), ChainError> {
        let addr = self.rpc.get_new_address()?;
        self.rpc.generate_to_address(1, &addr)?;
        Ok(())
    }
}

impl<T: BtcTransport> ChainOps for RegtestOps<T> {
    fn network(&self) -> &str {
        &self.network
    }

    fn mines_on_demand(&self) -> bool {
        true
    }

    fn ensure_funded(&self, address: &Address, needed_sats: u64) -> Result<(), ChainError> {
        if confirmed_sats(&self.reads, &self.esplora_base, address)? >= needed_sats {
            return Ok(());
        }

        // A cold node may have its default wallet on disk but not loaded.
        self.rpc.load_wallet("")?;
        if btc_to_sats(self.rpc.get_balance()?) < needed_sats {
            // A fresh chain's coinbase outputs are unspendable until maturity, so
            // the wallet has to mine past it before it can send anything.
            let addr = self.rpc.get_new_address()?;
            self.rpc
                .generate_to_address(COINBASE_MATURITY_BLOCKS, &addr)?;
        }
        self.rpc
            .send_to_address(&address.to_string(), needed_sats)?;
        self.mine_one()?;

        // The block exists, but the Esplora index catches up asynchronously: a
        // read taken straight after the mine can still show nothing.
        for attempt in 0..self.poll.attempts {
            if confirmed_sats(&self.reads, &self.esplora_base, address)? >= needed_sats {
                return Ok(());
            }
            if attempt + 1 < self.poll.attempts {
                std::thread::sleep(self.poll.interval);
            }
        }
        Err(ChainError::FundingTimeout {
            network: self.network.clone(),
            address: address.to_string(),
            needed_sats,
            waited: self.poll.budget(),
        })
    }

    fn await_confirmation(&self, txid: &str) -> Result<(u32, i64), ChainError> {
        self.mine_one()?;
        for attempt in 0..self.poll.attempts {
            if let Some(confirmed) = confirmation_of(&self.reads, &self.esplora_base, txid)? {
                return Ok(confirmed);
            }
            if attempt + 1 < self.poll.attempts {
                std::thread::sleep(self.poll.interval);
            }
        }
        Err(ChainError::ConfirmationTimeout {
            network: self.network.clone(),
            txid: txid.to_string(),
            waited: self.poll.budget(),
        })
    }

    fn settle(&self, height: u32) -> Result<u32, ChainError> {
        let tip = tip_height(&self.reads, &self.esplora_base)?;
        if tip >= height {
            return Ok(tip);
        }
        // Exactly the blocks that are missing, so a re-run that finds the tip
        // already past `height` produces none (the early return above) and a
        // partial catch-up produces only the remainder.
        let addr = self.rpc.get_new_address()?;
        self.rpc.generate_to_address(height - tip, &addr)?;
        // The blocks exist; the index catches up asynchronously.
        await_tip(
            &self.reads,
            &self.esplora_base,
            &self.network,
            height,
            &self.poll,
        )
    }
}

/// A chain that mines itself: fund from a faucet, confirm by polling.
pub struct PublicChainOps<T: BtcTransport> {
    network: String,
    esplora_base: String,
    reads: T,
    poll: Poll,
    /// The longer loop for settling several blocks past the last announcement.
    settle_poll: Poll,
}

impl<T: BtcTransport> PublicChainOps<T> {
    /// Build the self-mining backend.
    pub fn new(network: String, esplora_base: String, reads: T) -> Self {
        Self {
            network,
            esplora_base,
            reads,
            poll: Poll::self_mining(),
            settle_poll: Poll::settling(),
        }
    }

    /// Shorten both wait loops so a timeout is reachable in a unit test.
    #[cfg(test)]
    fn with_poll(mut self, poll: Poll) -> Self {
        self.poll = poll;
        self.settle_poll = poll;
        self
    }
}

impl<T: BtcTransport> ChainOps for PublicChainOps<T> {
    fn network(&self) -> &str {
        &self.network
    }

    fn mines_on_demand(&self) -> bool {
        false
    }

    fn ensure_funded(&self, address: &Address, needed_sats: u64) -> Result<(), ChainError> {
        let hint = faucet_url(&self.network)
            .map(|url| format!(" via {url}"))
            .unwrap_or_default();
        eprintln!(
            "fund {address} with at least {needed_sats} sats on {}{hint} — polling every {}s",
            self.network,
            self.poll.interval.as_secs()
        );
        for attempt in 0..self.poll.attempts {
            if confirmed_sats(&self.reads, &self.esplora_base, address)? >= needed_sats {
                return Ok(());
            }
            if attempt + 1 < self.poll.attempts {
                std::thread::sleep(self.poll.interval);
            }
        }
        Err(ChainError::FundingTimeout {
            network: self.network.clone(),
            address: address.to_string(),
            needed_sats,
            waited: self.poll.budget(),
        })
    }

    fn await_confirmation(&self, txid: &str) -> Result<(u32, i64), ChainError> {
        for attempt in 0..self.poll.attempts {
            if let Some(confirmed) = confirmation_of(&self.reads, &self.esplora_base, txid)? {
                return Ok(confirmed);
            }
            if attempt + 1 < self.poll.attempts {
                std::thread::sleep(self.poll.interval);
            }
        }
        Err(ChainError::ConfirmationTimeout {
            network: self.network.clone(),
            txid: txid.to_string(),
            waited: self.poll.budget(),
        })
    }

    fn settle(&self, height: u32) -> Result<u32, ChainError> {
        let tip = tip_height(&self.reads, &self.esplora_base)?;
        if tip >= height {
            return Ok(tip);
        }
        eprintln!(
            "waiting for {} to reach height {height} (tip {tip}) — polling every {}s",
            self.network,
            self.settle_poll.interval.as_secs()
        );
        await_tip(
            &self.reads,
            &self.esplora_base,
            &self.network,
            height,
            &self.settle_poll,
        )
    }
}

/// The faucet an operator funds a self-mining chain from, when this tool knows of
/// one.
///
/// A lookup, not a default: a chain with no entry gets no hint rather than
/// another chain's faucet, because sending a funding request to the wrong chain's
/// faucet wastes an operator session and produces no error anywhere.
pub fn faucet_url(network: &str) -> Option<&'static str> {
    match network {
        "mutinynet" => Some("https://faucet.mutinynet.com/"),
        _ => None,
    }
}

/// Choose the backend for a network.
///
/// `regtest` needs an RPC endpoint because nothing else will produce a block;
/// every other rung mines itself. The node credentials are NOT defaulted — the
/// runbook supplies them — because a default would pin one specific chain into
/// the tool, and each rung of the ladder must be an operator session against an
/// unchanged binary.
pub fn ops_for(
    network: &str,
    esplora_base: String,
    bitcoind_url: Option<String>,
    bitcoind_auth: Option<Secret>,
) -> Result<Box<dyn ChainOps>, ChainError> {
    if network == "regtest" {
        let (Some(url), Some(auth)) = (bitcoind_url, bitcoind_auth) else {
            return Err(ChainError::MissingBitcoindEndpoint);
        };
        let rpc = BitcoindRpc::new(UreqTransport::new(), url, &auth);
        return Ok(Box::new(RegtestOps::new(
            network.to_string(),
            esplora_base,
            UreqTransport::new(),
            rpc,
        )));
    }
    if bitcoind_url.is_some() || bitcoind_auth.is_some() {
        eprintln!(
            "note: --bitcoind-url and --bitcoind-auth are ignored on `{network}`, which produces its own blocks"
        );
    }
    Ok(Box::new(PublicChainOps::new(
        network.to_string(),
        esplora_base,
        UreqTransport::new(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::{BTreeMap, VecDeque};
    use std::rc::Rc;
    use std::str::FromStr as _;

    /// A 64-hex-ish placeholder txid, long enough to parse as one.
    const TXID: &str = "11111111111111111111111111111111111111111111111111111111111111ab";

    /// One request the fake saw, in the terms the assertions need.
    #[derive(Debug, Clone)]
    struct Seen {
        method: String,
        path: String,
        authorization: Option<String>,
        rpc_method: Option<String>,
        params: Value,
    }

    /// A stand-in for a bitcoind node and an Esplora index.
    ///
    /// Canned responses are keyed by `rpc:<method>` for a JSON-RPC POST and by the
    /// request path for a GET. A key with several queued responses yields them in
    /// order and then repeats the last one forever, which is what a wait loop
    /// needs: "empty, empty, then funded, and funded from then on".
    /// Queued `(status, body)` replies per key, shared with every clone of the
    /// fake so a client and its RPC half draw from one script.
    type CannedReplies = Rc<RefCell<BTreeMap<String, VecDeque<(u16, String)>>>>;

    #[derive(Clone, Default)]
    struct FakeChain {
        seen: Rc<RefCell<Vec<Seen>>>,
        canned: CannedReplies,
    }

    impl FakeChain {
        fn new() -> Self {
            Self::default()
        }

        fn push(&self, key: String, status: u16, body: String) {
            self.canned
                .borrow_mut()
                .entry(key)
                .or_default()
                .push_back((status, body));
        }

        /// Queue a successful JSON-RPC reply for `method`.
        fn rpc_ok(&self, method: &str, result: Value) -> &Self {
            self.push(
                format!("rpc:{method}"),
                200,
                json!({ "result": result, "error": null, "id": "chain-capture" }).to_string(),
            );
            self
        }

        /// Queue a JSON-RPC error reply for `method`. bitcoind answers these with
        /// HTTP 500, which is why the client reads the body before the status.
        fn rpc_err(&self, method: &str, code: i64, message: &str) -> &Self {
            self.push(
                format!("rpc:{method}"),
                500,
                json!({
                    "result": null,
                    "error": { "code": code, "message": message },
                    "id": "chain-capture",
                })
                .to_string(),
            );
            self
        }

        /// Queue a raw reply for `method`, bypassing the JSON-RPC envelope.
        fn rpc_raw(&self, method: &str, status: u16, body: &str) -> &Self {
            self.push(format!("rpc:{method}"), status, body.to_string());
            self
        }

        /// Queue a reply for a GET path.
        fn get(&self, path: &str, status: u16, body: Value) -> &Self {
            self.push(path.to_string(), status, body.to_string());
            self
        }

        /// Queue a `/address/{a}/utxo` reply holding one confirmed output.
        fn utxos(&self, address: &str, value: u64) -> &Self {
            self.get(
                &format!("/address/{address}/utxo"),
                200,
                json!([{
                    "txid": TXID,
                    "vout": 0,
                    "value": value,
                    "status": { "confirmed": true, "block_height": 101 },
                }]),
            )
        }

        /// Queue an empty `/address/{a}/utxo` reply.
        fn no_utxos(&self, address: &str) -> &Self {
            self.get(&format!("/address/{address}/utxo"), 200, json!([]))
        }

        /// Queue a `/tx/{txid}` reply, confirmed or not.
        fn tx(&self, txid: &str, confirmed: Option<(u32, i64)>) -> &Self {
            let status = match confirmed {
                Some((height, time)) => json!({
                    "confirmed": true,
                    "block_height": height,
                    "block_hash": "00".repeat(32),
                    "block_time": time,
                }),
                None => json!({
                    "confirmed": false,
                    "block_height": null,
                    "block_hash": null,
                    "block_time": null,
                }),
            };
            self.get(
                &format!("/tx/{txid}"),
                200,
                json!({
                    "txid": txid,
                    "version": 2,
                    "locktime": 0,
                    "vin": [],
                    "vout": [],
                    "size": 100,
                    "weight": 400,
                    "fee": 0,
                    "status": status,
                }),
            )
        }

        fn requests(&self) -> Vec<Seen> {
            self.seen.borrow().clone()
        }

        /// Every JSON-RPC method the fake was asked for, in order.
        fn rpc_calls(&self) -> Vec<String> {
            self.requests()
                .into_iter()
                .filter_map(|r| r.rpc_method)
                .collect()
        }

        fn next(&self, key: &str) -> Option<(u16, String)> {
            let mut canned = self.canned.borrow_mut();
            let queue = canned.get_mut(key)?;
            if queue.len() > 1 {
                queue.pop_front()
            } else {
                queue.front().cloned()
            }
        }
    }

    impl BtcTransport for FakeChain {
        fn execute(
            &self,
            req: http::Request<Vec<u8>>,
        ) -> Result<http::Response<Vec<u8>>, TransportError> {
            let path = req.uri().path().to_string();
            let authorization = req
                .headers()
                .get(http::header::AUTHORIZATION)
                .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned());
            let envelope: Value = serde_json::from_slice(req.body()).unwrap_or(Value::Null);
            let rpc_method = envelope
                .get("method")
                .and_then(Value::as_str)
                .map(str::to_string);
            let key = match &rpc_method {
                Some(method) => format!("rpc:{method}"),
                None => path.clone(),
            };
            self.seen.borrow_mut().push(Seen {
                method: req.method().to_string(),
                path,
                authorization,
                rpc_method,
                params: envelope.get("params").cloned().unwrap_or(Value::Null),
            });

            let (status, body) = self.next(&key).unwrap_or_else(|| {
                panic!("the fake chain has no canned response for `{key}`");
            });
            Ok(http::Response::builder()
                .status(status)
                .body(body.into_bytes())
                .expect("a valid status and body build a response"))
        }
    }

    /// A poll that finishes instantly, so a timeout is reachable in a unit test.
    fn instant_poll(attempts: u32) -> Poll {
        Poll {
            interval: Duration::from_millis(0),
            attempts,
        }
    }

    /// A regtest P2WPKH address to fund. Parsed, never composed, so no address
    /// literal in the tool derives from a test.
    fn regtest_address() -> Address {
        Address::from_str("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080")
            .expect("a valid bech32 address")
            .require_network(esploda::bitcoin::Network::Regtest)
            .expect("the address is regtest")
    }

    fn rpc(fake: FakeChain) -> BitcoindRpc<FakeChain> {
        BitcoindRpc::new(
            fake,
            "http://127.0.0.1:18443".to_string(),
            &Secret::from_exposed("user:secret"),
        )
    }

    #[test]
    fn rpc_call_sends_basic_auth_and_the_jsonrpc_envelope() {
        let fake = FakeChain::new();
        fake.rpc_ok("getbalance", json!(1.5));

        let client = rpc(fake.clone());
        assert_eq!(client.get_balance().expect("the call succeeds"), 1.5);

        let seen = fake.requests();
        assert_eq!(seen.len(), 1, "one call, one request: {seen:?}");
        assert_eq!(seen[0].method, "POST");
        assert_eq!(
            seen[0].path, "/",
            "the JSON-RPC call posts to the node URL as given, appending no path \
             of its own — unlike the Esplora half of this transport, which builds \
             /tx and /address/../utxo onto its base"
        );
        assert_eq!(
            seen[0].authorization.as_deref(),
            Some("Basic dXNlcjpzZWNyZXQ="),
            "the credential travels as HTTP basic auth"
        );
        assert_eq!(seen[0].rpc_method.as_deref(), Some("getbalance"));
        assert_eq!(seen[0].params, json!([]));
    }

    #[test]
    fn rpc_error_names_the_method_and_never_the_auth_header() {
        let fake = FakeChain::new();
        fake.rpc_err("getbalance", -18, "No wallet is loaded.");

        let client = rpc(fake);
        let error = client.get_balance().expect_err("an RPC error propagates");
        match &error {
            ChainError::Rpc {
                method,
                code,
                message,
            } => {
                assert_eq!(method, "getbalance");
                assert_eq!(*code, -18);
                assert_eq!(message, "No wallet is loaded.");
            }
            other => panic!("expected Rpc, got {other:?}"),
        }
        let rendered = format!("{error} {error:?}");
        assert!(
            !rendered.contains("secret") && !rendered.contains("dXNlcjpzZWNyZXQ="),
            "no error may carry the credential: {rendered}"
        );
    }

    #[test]
    fn rpc_non_2xx_without_a_jsonrpc_error_names_the_status() {
        let fake = FakeChain::new();
        fake.rpc_raw("getbalance", 401, "");

        let client = rpc(fake);
        let error = client
            .get_balance()
            .expect_err("an auth rejection is an error");
        match &error {
            ChainError::RpcHttp { method, status } => {
                assert_eq!(method, "getbalance");
                assert_eq!(*status, 401);
            }
            other => panic!("expected RpcHttp, got {other:?}"),
        }
        assert!(
            error.to_string().contains("401"),
            "the message names the status: {error}"
        );
    }

    #[test]
    fn debug_never_renders_the_password_or_the_auth_value() {
        let client = rpc(FakeChain::new());
        let rendered = format!("{client:?}");
        assert!(
            !rendered.contains("secret") && !rendered.contains("dXNlcjpzZWNyZXQ="),
            "Debug must not render the credential: {rendered}"
        );
        assert!(
            rendered.contains("redacted"),
            "Debug says the field exists and was withheld: {rendered}"
        );
        assert!(
            rendered.contains("127.0.0.1:18443"),
            "the endpoint is still visible: {rendered}"
        );
    }

    #[test]
    fn load_wallet_treats_already_loaded_as_success() {
        for code in [-35, -4] {
            let fake = FakeChain::new();
            fake.rpc_err("loadwallet", code, "Wallet is already loaded.");
            let client = rpc(fake);
            client
                .load_wallet("")
                .unwrap_or_else(|e| panic!("code {code} is the state we wanted, got: {e}"));
        }

        // An unrelated wallet failure is still an error.
        let fake = FakeChain::new();
        fake.rpc_err("loadwallet", -18, "Wallet file verification failed.");
        let client = rpc(fake);
        let error = client
            .load_wallet("")
            .expect_err("an unrelated wallet error propagates");
        assert!(
            matches!(error, ChainError::Rpc { code: -18, .. }),
            "{error}"
        );
    }

    #[test]
    fn send_to_address_converts_sats_to_a_btc_amount() {
        let fake = FakeChain::new();
        fake.rpc_ok("sendtoaddress", json!(TXID));

        let client = rpc(fake.clone());
        let txid = client
            .send_to_address("bcrt1qexample", 150_000)
            .expect("the send succeeds");
        assert_eq!(txid, TXID);

        let seen = fake.requests();
        assert_eq!(
            seen[0].params,
            json!(["bcrt1qexample", 0.0015]),
            "150_000 sats is 0.0015 BTC as a JSON number"
        );
        // The whole conversion, at the boundary it exists for.
        assert_eq!(sats_to_btc(1), 0.000_000_01);
        assert_eq!(sats_to_btc(SATS_PER_BTC), 1.0);
        assert_eq!(btc_to_sats(0.0015), 150_000);
    }

    #[test]
    fn generate_to_address_is_a_plain_rpc_call() {
        // Nothing stands between the caller and the RPC: no fixture tree is
        // consulted, no precondition on the chain's height is checked. The one
        // request sent is the generatetoaddress call itself.
        let fake = FakeChain::new();
        fake.rpc_ok("generatetoaddress", json!(["00".repeat(32)]));

        let client = rpc(fake.clone());
        let hashes = client
            .generate_to_address(1, "bcrt1qexample")
            .expect("mining is unconditional");
        assert_eq!(hashes, vec!["00".repeat(32)]);

        let seen = fake.requests();
        assert_eq!(seen.len(), 1, "one mine, one request: {seen:?}");
        assert_eq!(seen[0].rpc_method.as_deref(), Some("generatetoaddress"));
        assert_eq!(seen[0].params, json!([1, "bcrt1qexample"]));
    }

    #[test]
    fn generate_to_address_rejects_a_reply_that_is_not_a_hash_list() {
        let fake = FakeChain::new();
        fake.rpc_ok("generatetoaddress", json!("not a list"));

        let client = rpc(fake);
        let error = client
            .generate_to_address(1, "bcrt1qexample")
            .expect_err("a non-list reply is a shape error");
        assert!(
            matches!(&error, ChainError::RpcResultShape { method, .. } if method == "generatetoaddress"),
            "got {error:?}"
        );
    }

    #[test]
    fn ensure_funded_is_a_no_op_when_the_address_already_holds_enough() {
        let address = regtest_address();
        let fake = FakeChain::new();
        fake.utxos(&address.to_string(), 200_000);

        let ops = RegtestOps::new(
            "regtest".to_string(),
            "http://localhost:3000".to_string(),
            fake.clone(),
            rpc(fake.clone()),
        );
        ops.ensure_funded(&address, 150_000)
            .expect("an already-funded address needs nothing");

        assert!(
            fake.rpc_calls().is_empty(),
            "a funded address touches no wallet and produces no block: {:?}",
            fake.rpc_calls()
        );
    }

    #[test]
    fn ensure_funded_sends_mines_and_rereads_on_an_empty_address() {
        let address = regtest_address();
        let key = format!("/address/{address}/utxo");
        let fake = FakeChain::new();
        // Empty at first, empty again on the first re-read (the index lags), then
        // funded from then on.
        fake.get(&key, 200, json!([]));
        fake.get(&key, 200, json!([]));
        fake.utxos(&address.to_string(), 150_000);
        fake.rpc_ok("loadwallet", Value::Null);
        fake.rpc_ok("getbalance", json!(0.0));
        fake.rpc_ok("getnewaddress", json!("bcrt1qminer"));
        fake.rpc_ok("generatetoaddress", json!([]));
        fake.rpc_ok("sendtoaddress", json!(TXID));

        let ops = RegtestOps::new(
            "regtest".to_string(),
            "http://localhost:3000".to_string(),
            fake.clone(),
            rpc(fake.clone()),
        );
        ops.ensure_funded(&address, 150_000)
            .expect("an empty address is funded from the wallet");

        let calls = fake.rpc_calls();
        assert_eq!(
            calls,
            vec![
                "loadwallet",
                "getbalance",
                "getnewaddress",
                "generatetoaddress",
                "sendtoaddress",
                "getnewaddress",
                "generatetoaddress",
            ],
            "an empty wallet matures its coinbase, sends, then mines the transfer"
        );
        let mined: Vec<Value> = fake
            .requests()
            .into_iter()
            .filter(|r| r.rpc_method.as_deref() == Some("generatetoaddress"))
            .map(|r| r.params)
            .collect();
        assert_eq!(
            mined,
            vec![
                json!([COINBASE_MATURITY_BLOCKS, "bcrt1qminer"]),
                json!([1, "bcrt1qminer"]),
            ],
            "maturity first, then exactly one block for the transfer"
        );
    }

    #[test]
    fn ensure_funded_gives_up_with_a_named_timeout() {
        let address = regtest_address();
        let fake = FakeChain::new();
        fake.no_utxos(&address.to_string());
        fake.rpc_ok("loadwallet", Value::Null);
        fake.rpc_ok("getbalance", json!(1.0));
        fake.rpc_ok("getnewaddress", json!("bcrt1qminer"));
        fake.rpc_ok("generatetoaddress", json!([]));
        fake.rpc_ok("sendtoaddress", json!(TXID));

        let ops = RegtestOps::new(
            "regtest".to_string(),
            "http://localhost:3000".to_string(),
            fake.clone(),
            rpc(fake.clone()),
        )
        .with_poll(instant_poll(3));
        let error = ops
            .ensure_funded(&address, 150_000)
            .expect_err("an address that never funds times out");
        match &error {
            ChainError::FundingTimeout {
                network,
                address: named,
                needed_sats,
                ..
            } => {
                assert_eq!(network, "regtest");
                assert_eq!(named, &address.to_string());
                assert_eq!(*needed_sats, 150_000);
            }
            other => panic!("expected FundingTimeout, got {other:?}"),
        }
        // A funded wallet skips the maturity mine; only the transfer is mined.
        assert_eq!(
            fake.rpc_calls()
                .iter()
                .filter(|m| *m == "generatetoaddress")
                .count(),
            1,
            "a wallet with a balance mines once, for the transfer"
        );
    }

    #[test]
    fn await_confirmation_mines_then_polls_until_confirmed() {
        let fake = FakeChain::new();
        fake.rpc_ok("getnewaddress", json!("bcrt1qminer"));
        fake.rpc_ok("generatetoaddress", json!(["00".repeat(32)]));
        fake.tx(TXID, None);
        fake.tx(TXID, Some((213, 1_700_000_500)));

        let ops = RegtestOps::new(
            "regtest".to_string(),
            "http://localhost:3000".to_string(),
            fake.clone(),
            rpc(fake.clone()),
        )
        .with_poll(instant_poll(5));
        let (height, time) = ops
            .await_confirmation(TXID)
            .expect("the transaction confirms once a block is produced");
        assert_eq!((height, time), (213, 1_700_000_500));
        assert_eq!(
            fake.rpc_calls(),
            vec!["getnewaddress", "generatetoaddress"],
            "one block, produced once"
        );
    }

    /// Queue a `/blocks/tip/height` reply.
    fn tip(fake: &FakeChain, height: u32) {
        fake.get("/blocks/tip/height", 200, json!(height));
    }

    #[test]
    fn regtest_settle_mines_exactly_the_missing_blocks_and_waits_for_the_index() {
        let fake = FakeChain::new();
        // Tip 764, target 769: five blocks. The index then reports the old tip
        // once more before it catches up.
        tip(&fake, 764);
        tip(&fake, 764);
        tip(&fake, 769);
        fake.rpc_ok("getnewaddress", json!("bcrt1qminer"));
        fake.rpc_ok("generatetoaddress", json!(vec!["00".repeat(32); 5]));

        let ops = RegtestOps::new(
            "regtest".to_string(),
            "http://localhost:3000".to_string(),
            fake.clone(),
            rpc(fake.clone()),
        )
        .with_poll(instant_poll(5));
        assert_eq!(
            ops.settle(769).expect("the chain settles"),
            769,
            "the tip reached is reported"
        );
        assert_eq!(fake.rpc_calls(), vec!["getnewaddress", "generatetoaddress"]);
        let mined = fake
            .requests()
            .into_iter()
            .find(|r| r.rpc_method.as_deref() == Some("generatetoaddress"))
            .expect("a block was produced");
        assert_eq!(
            mined.params[0],
            json!(5),
            "exactly the missing blocks are produced: {}",
            mined.params
        );
    }

    #[test]
    fn regtest_settle_is_a_no_op_once_the_tip_is_past_the_height() {
        let fake = FakeChain::new();
        tip(&fake, 773);

        let ops = RegtestOps::new(
            "regtest".to_string(),
            "http://localhost:3000".to_string(),
            fake.clone(),
            rpc(fake.clone()),
        )
        .with_poll(instant_poll(5));
        assert_eq!(ops.settle(769).expect("nothing to do"), 773);
        assert!(
            fake.rpc_calls().is_empty(),
            "a settled chain is not mined on again: {:?}",
            fake.rpc_calls()
        );
    }

    #[test]
    fn public_chain_settle_waits_without_mining_and_times_out_by_name() {
        let fake = FakeChain::new();
        tip(&fake, 3_302_500);

        let ops = PublicChainOps::new(
            "mutinynet".to_string(),
            "http://esplora.test".to_string(),
            fake.clone(),
        )
        .with_poll(instant_poll(3));
        let error = ops
            .settle(3_302_505)
            .expect_err("a chain that stops producing blocks times out");
        match &error {
            ChainError::SettlementTimeout {
                network,
                height,
                tip,
                ..
            } => {
                assert_eq!(network, "mutinynet");
                assert_eq!(*height, 3_302_505);
                assert_eq!(*tip, 3_302_500);
            }
            other => panic!("expected SettlementTimeout, got {other:?}"),
        }
        assert!(
            fake.rpc_calls().is_empty(),
            "a self-mining chain is never mined on: {:?}",
            fake.rpc_calls()
        );
        assert!(
            error.to_string().contains("resumes"),
            "the message says a re-run is safe: {error}"
        );

        // And it returns as soon as the chain gets there on its own.
        let fake = FakeChain::new();
        tip(&fake, 3_302_500);
        tip(&fake, 3_302_505);
        let ops = PublicChainOps::new(
            "mutinynet".to_string(),
            "http://esplora.test".to_string(),
            fake.clone(),
        )
        .with_poll(instant_poll(3));
        assert_eq!(ops.settle(3_302_505).expect("the chain settles"), 3_302_505);
    }

    #[test]
    fn a_tip_that_is_not_a_height_is_a_malformed_response() {
        let fake = FakeChain::new();
        fake.get("/blocks/tip/height", 200, json!("<html>proxy</html>"));
        let error = tip_height(&fake, "http://esplora.test").expect_err("not a height");
        assert!(
            matches!(error, ChainError::Transport(TransportError::Malformed(_))),
            "got {error:?}"
        );
    }

    #[test]
    fn public_chain_ensure_funded_polls_without_mining_and_times_out() {
        let address = regtest_address();
        let fake = FakeChain::new();
        fake.no_utxos(&address.to_string());

        let ops = PublicChainOps::new(
            "mutinynet".to_string(),
            "http://esplora.test".to_string(),
            fake.clone(),
        )
        .with_poll(instant_poll(4));
        let error = ops
            .ensure_funded(&address, 150_000)
            .expect_err("a faucet that never pays times out");
        assert!(
            matches!(error, ChainError::FundingTimeout { ref network, .. } if network == "mutinynet"),
            "got {error:?}"
        );
        assert!(
            fake.rpc_calls().is_empty(),
            "a self-mining chain issues no JSON-RPC at all: {:?}",
            fake.rpc_calls()
        );
        assert_eq!(
            fake.requests().len(),
            4,
            "the poll is bounded by its attempt count"
        );
        assert!(!ops.mines_on_demand(), "this rung mines itself");
    }

    #[test]
    fn public_chain_await_confirmation_never_mines() {
        let fake = FakeChain::new();
        fake.tx(TXID, None);
        fake.tx(TXID, Some((3_302_500, 1_700_000_900)));

        let ops = PublicChainOps::new(
            "mutinynet".to_string(),
            "http://esplora.test".to_string(),
            fake.clone(),
        )
        .with_poll(instant_poll(5));
        assert_eq!(
            ops.await_confirmation(TXID)
                .expect("the transaction confirms on its own"),
            (3_302_500, 1_700_000_900)
        );
        assert!(
            fake.rpc_calls().is_empty(),
            "nothing was mined: {:?}",
            fake.rpc_calls()
        );
    }

    #[test]
    fn an_unindexed_transaction_is_not_a_failure() {
        let fake = FakeChain::new();
        fake.get(&format!("/tx/{TXID}"), 404, json!("Transaction not found"));
        assert_eq!(
            confirmation_of(&fake, "http://esplora.test", TXID)
                .expect("a 404 is an ordinary state of the wait loop"),
            None
        );
    }

    #[test]
    fn ops_for_regtest_requires_the_bitcoind_flags() {
        for (url, auth) in [
            (None, None),
            (Some("http://127.0.0.1:18443".to_string()), None),
            (None, Some(Secret::from_exposed("user:pass"))),
        ] {
            let error = ops_for("regtest", "http://localhost:3000".to_string(), url, auth)
                .err()
                .expect("regtest cannot mine without an RPC endpoint");
            assert!(
                matches!(error, ChainError::MissingBitcoindEndpoint),
                "got {error:?}"
            );
            let rendered = error.to_string();
            assert!(
                rendered.contains("--bitcoind-url") && rendered.contains("--bitcoind-auth"),
                "the message names both flags: {rendered}"
            );
        }
    }

    #[test]
    fn ops_for_a_self_mining_chain_yields_the_polling_backend() {
        let ops = ops_for(
            "mutinynet",
            "https://mutinynet.com/api".to_string(),
            None,
            None,
        )
        .expect("a self-mining chain needs no RPC endpoint");
        assert_eq!(ops.network(), "mutinynet");
        assert!(!ops.mines_on_demand(), "mutinynet produces its own blocks");

        // The bitcoind flags are accepted and ignored rather than refused.
        let ops = ops_for(
            "testnet4",
            "http://localhost:3002".to_string(),
            Some("http://127.0.0.1:18443".to_string()),
            Some(Secret::from_exposed("user:pass")),
        )
        .expect("an ignored flag is not a failure");
        assert_eq!(ops.network(), "testnet4");
        assert!(!ops.mines_on_demand());
    }

    #[test]
    fn faucet_hint_is_a_lookup_not_a_default() {
        assert_eq!(
            faucet_url("mutinynet"),
            Some("https://faucet.mutinynet.com/")
        );
        for unmapped in ["regtest", "testnet4", "signet", "mainnet"] {
            assert_eq!(
                faucet_url(unmapped),
                None,
                "`{unmapped}` gets no hint rather than another chain's faucet"
            );
        }
    }
}
