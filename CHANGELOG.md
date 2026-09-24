# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Versioning

This crate is pre-1.0 and tracks the in-progress did:btcr2 method spec.
During pre-1.0 the version is held; changes accumulate under **Unreleased**.
Semver discipline begins at the 1.0 cut, once the did:btcr2 spec stabilizes.

## [Unreleased]

### Added

- `ResolutionOptions::min_conf` (`resolutionOptions.minConf`, default 6): a
  beacon signal is processed only once its transaction has that many
  confirmations against `chain_tip_height`; the CLI takes `--min-conf <n>`.
- `Btcr2Error::InvalidOptions` (`https://www.w3.org/ns/did#INVALID_OPTIONS`):
  `versionId` and `versionTime` together, or an `esplora_url` that is absent
  or cannot form request URIs.
- `resolver::Error::MissingChainTip`: a confirmed signal met with no
  `chain_tip_height` supplied. A driver precondition, like
  `MissingBlockMediantime`; neither carries a spec problem-details body.
- The `did-btcr2-client` facade pages through Esplora's address history
  (`/txs/chain/{last_seen_txid}`) so the resolver sees a beacon's complete
  confirmed history, and fetches the chain tip only when the caller did not
  pin one.
- `chain-capture` settles the chain five blocks past the last announcement
  before capturing a minted fixture, and records the `/block/{hash}` header
  of every announcement's block.
- `Client::for_did(&did, network_override, esplora_url, transport)`: derives
  the Esplora endpoint from the DID's network; `Error::NetworkMismatch` when
  `--network` names another chain. `network_from_name` / `network_name` expose
  the name table.

### Changed

- On-wire DID prefix flipped from `did:btc1:` to `did:btcr2:` (no back-compat;
  the parser rejects the old `did:btc1:` prefix).
- `ResolutionOptions::esplora_url` is required for resolution; the built-in
  blockstream testnet fallback is gone.
- `versionTime` is compared against the announcing block's `mediantime` (equal
  applies, no tolerance); the resolver requests the block for every applicable
  update under a `versionTime` bound. With neither `versionId` nor
  `versionTime` there is no time cutoff at all.
- A `versionId` the history never reaches — the updates are exhausted, or the
  document is deactivated — is `NOT_FOUND` instead of the latest document.
- An unconfirmed announcement is skipped whether or not the sidecar holds its
  update; it is never an error.
- `didDocumentMetadata.confirmations` is `0` (not omitted) when the tip is
  known and no update was applied.
- Method-specific problem-details `type` URIs use
  `https://btcr2.dev/context/v1#…`, the same host as the document context.
- The external (`x1`) genesis document is hashed as shipped, then the
  `did:btcr2:_` placeholder is replaced by a literal text replacement
  (every occurrence, including inside longer strings).
- A document's `controller` may be a string or a set of strings, each a DID of
  any method.
- `resolver::Error` no longer converts into `Btcr2Error`; it implements
  `ProblemDetails` directly, and driver preconditions yield no body.
- The two minted chain fixtures are re-minted with settled tips (six
  confirmations on the last announcement) and carry their announcements'
  blocks; their replay tests run under the default `minConf` and their
  `versionTime` probes run. The clean scenario's third update is announced
  from the beacon its second update added, so its replay exercises the
  mid-walk beacon re-scan on real transactions.
- `Btcr2Error::NotFound`'s fixed title (problem-details `title`, leading clause
  of `Display`) is now "The DID document was not found"; the genesis-retrieval
  or `versionId` reason stays in `detail`.
- The CLI's `resolve`, `update`, and `deactivate` no longer default to testnet:
  the endpoint follows the DID; a contradicting `--network` is an error before
  any request. `create` still defaults to testnet.
- `Network::TestnetV4` converts to the bitcoin crate's `Testnet` address
  network (the two share address prefixes), so testnet4 DIDs build their
  beacons and parse testnet4 beacon addresses; it was an `InvalidNetwork(4)`
  error.

### Deprecated

### Removed

- `resolver::Error::UnconfirmedBeaconTx`.

### Fixed

- `SecretKey`: the `Vec<u8>` a key is parsed from and the signing keypair are
  scrubbed after use; the type documents a best-effort scrub rather than a
  guarantee.
- Resolver: the `versionTime` bound is evaluated on any tuple whose
  `targetVersionId` exceeds the current version (resolve.md "Process Next
  Update" step 4), not only on the next version. A skipped version announced
  after `versionTime` now resolves the document in effect instead of raising
  `LATE_PUBLISHING`.
- Resolver: the beacon set is re-checked after every applied update
  (resolve.md "Find Beacon Signals" precedes every "Process Next Update"), so
  an update announced from a beacon that an earlier update added is scanned
  before later updates from the original beacons are judged. Previously such a
  history raised `LATE_PUBLISHING`. A round can now arrive mid-batch; the
  driver's contract is unchanged.
- `did-btcr2-client`: the Esplora address-history pager rejects any repeated
  continuation key (a cycle of any length, not only an immediate self-repeat)
  and stops after `MAX_ADDRESS_PAGES` (1 000) pages; both are
  `TransportError::Malformed`, instead of looping on a server that re-serves
  pages or never ends its history.

### Security
