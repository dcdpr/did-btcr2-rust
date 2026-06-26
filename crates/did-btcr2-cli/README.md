# did-btcr2-cli

A command-line client for the **did:btcr2** Bitcoin DID method. The binary is
named `did-btcr2` and is a thin shell over the [`did-btcr2-client`](../did-btcr2-client)
facade: it parses subcommands, loads input (DIDs, JSON patches, secret keys),
and dispatches into the facade, which owns all operation composition — the
resolver state-machine loop, beacon funding, fee resolution, and broadcast. The
CLI itself carries no FSM pump, no UTXO/fee math, and no broadcast logic; the
sans-I/O core ([`did-btcr2`](../..)) makes no network calls, and all HTTP lives
behind the facade's transport seam.

This crate is `publish = false` — it is a workspace-local tool, run with
`cargo run`, not installed from crates.io.

## Status

Pre-1.0, tracking the in-progress
[did:btcr2 method specification](https://github.com/dcdpr/did-btcr2). Only the
**Singleton** beacon path is implemented (single-party, single beacon); the CAS
and Sparse Merkle Tree beacon paths are not. See the
[workspace CONFORMANCE.md](../../CONFORMANCE.md) for the full matrix.

## Commands

| Command | Effect |
|---|---|
| `create` | Mint a genesis did:btcr2 document + key offline and print them. No broadcast; no network calls. |
| `resolve <did>` | Resolve a DID and print the resolution result as JSON. Read-only; no broadcast. |
| `update <did> --patch <file>` | Apply an RFC-6902 JSON Patch to the document via a beacon-signal transaction. Broadcasts. |
| `deactivate <did>` | Deactivate the document via a beacon-signal transaction. Broadcasts. |

Run `cargo run -p did-btcr2-cli -- --help` for the authoritative flag list.

## Networks

`--network` selects a built-in Esplora endpoint; `--esplora-url` overrides it
verbatim (trailing slash trimmed):

| `--network` | Esplora base URL |
|---|---|
| `testnet` (default) | `https://blockstream.info/testnet/api` |
| `signet` | `https://blockstream.info/signet/api` |
| `mainnet` | `https://blockstream.info/api` |
| `mutinynet` | `https://mutinynet.com/api` |

## Supplying the secret key (`update` / `deactivate`)

A secret key MUST NOT be passed on the command line — argv is visible in shell
history and `ps`. There is no `--key <hex>` flag. The key is read from one of
three sources, in precedence order:

1. `--key-file <path>` — a file holding raw 32-byte lowercase hex
2. `--key-stdin` — the same hex on stdin
3. the `DIDBTCR2_KEY` environment variable

The **beacon key** (which funds and signs the announcement transaction) mirrors
this trio — `--beacon-key-file`, `--beacon-key-stdin`, `DIDBTCR2_BEACON_KEY` —
and defaults to the update key when no beacon-key source is given (the default
singleton beacons are spendable by the DID key).

`--key-stdin` cannot be combined with the interactive broadcast confirm (both
read stdin). Pass `--yes` to skip the prompt, or use `--key-file`.

## Fees and beacons (`update` / `deactivate`)

- `--fee <sats>` — absolute fee in satoshis.
- `--feerate <sat/vB>` — fee rate (single-input only).
- Neither flag — a built-in default of **1000 sats** absolute.
- `--beacon <type>` — which default beacon to fund: `P2PKH`, `P2WPKH` (default),
  or `P2TR`.
- `--change <addr>` — change address (defaults to the beacon address; must match
  the DID's network).
- `--dry-run` — build and print the transaction (txid + raw hex) without
  broadcasting.
- `--yes` — skip the `y/N` broadcast confirm prompt.

## Examples

> For a full end-to-end write lifecycle (create → fund → resolve → update →
> resolve → deactivate → resolve) on `mutinynet`, see **[RUNBOOK.md](./RUNBOOK.md)**.
> This README covers the read-only, copy-paste-reproducible `create`/`resolve`
> paths; `update`/`deactivate` need funded UTXOs and live in the RUNBOOK.

### Reproducible examples

Every `create`/`resolve` example below is anchored to one **fixed demo secret
key** so the commands reproduce byte-for-byte. `create` is deterministic: the
same secret key on the same `--network` always yields the same DID.

The fixed demo key (32-byte lowercase hex) is:

```
0000000000000000000000000000000000000000000000000000000000000001
```

> **⚠ SECURITY — this key is PUBLICLY KNOWN. Never use it for a real DID.**
> It is printed here verbatim, so **anyone** can derive its keys and control any
> DID created from it. It exists ONLY to make this documentation reproducible.
> For any real DID, mint a fresh secret with `create --generate` and store it
> yourself.

Write the demo key to a file (no trailing newline — `create` reads raw 32-byte
lowercase hex), then derive the DID:

```bash
printf '%s' 0000000000000000000000000000000000000000000000000000000000000001 > ./demo.hex
cargo run -p did-btcr2-cli -- create --key-file ./demo.hex --network testnet
```

The first line of stdout is exactly (real captured output):

```
did:btcr2:k1qvp8n0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xqmxnpr4
```

### The DID encodes its network — it must match `--network`

A `k1...` (key-based) identifier encodes its Bitcoin network in the bech32
payload, so the same key yields a *different* DID per network:

| `--network` | DID prefix | Fixed-key DID (this demo key) |
|---|---|---|
| `mainnet` | `k1qqp...` | `did:btcr2:k1qqp8n0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xqhmkf96` |
| `testnet` | `k1qvp...` | `did:btcr2:k1qvp8n0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xqmxnpr4` |
| `signet` | `k1qyp...` | `did:btcr2:k1qyp8n0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xqns4k8l` |
| `mutinynet` | `k1q5p...` | `did:btcr2:k1q5p8n0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xqr4e30t` |

A key-based DID resolves deterministically to its **genesis document** when no
beacon signals are found on-chain, so `resolve` returns the genesis document even
for a DID that has never been updated — **provided the endpoint's network matches
the DID's encoded network**. If it does not, Esplora rejects the derived beacon
address:

```
HTTP 400: Address on invalid network
```

Precise mismatch semantics: the failure is specifically about **mainnet-vs-testnet
address forms**. Resolving the mainnet DID above against a testnet endpoint (or
vice versa) fails with `HTTP 400: Address on invalid network`. Resolving the
**testnet** DID against `--network mutinynet` **succeeds**, because mutinynet is
signet-based and shares the `tb1...`/`m...` testnet address forms. Do not read
this as "any network mismatch fails" — only the mainnet/testnet address-form
split does.

### Help and version

```bash
cargo run -p did-btcr2-cli -- --help
cargo run -p did-btcr2-cli -- --version
```

### Create a DID (offline)

`create` mints a `did:btcr2` document and prints the DID identifier plus the
document as JSON. It makes **zero network calls** — no broadcast, and
`--esplora-url` does not apply. Beacon selection is not exposed: the default
singleton beacon set is emitted. `create` has two modes: key-based (default,
mints a `k1` DID) and external (`--intermediate-document`, mints an `x1` DID).

Generate a fresh key (the generated secret is printed once — store it, it
controls the DID):

```bash
cargo run -p did-btcr2-cli -- create --generate
```

This prints the `did:btcr2:...` identifier, the genesis document as
pretty-printed JSON, and the generated secret as raw 32-byte lowercase hex,
preceded by a "store this" warning on stderr.

Derive the DID from a secret key you already hold (no secret is echoed). Using
the fixed demo key from above:

```bash
cargo run -p did-btcr2-cli -- create --key-file ./demo.hex --network testnet
```

prints the DID and its genesis document as JSON. The DID line is:

```
did:btcr2:k1qvp8n0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xqmxnpr4
```

The key source is the same trio used by `update`/`deactivate`: `--key-file`,
`--key-stdin`, or the `DIDBTCR2_KEY` environment variable (file > stdin > env).
`--generate` and a key source are mutually exclusive; supplying neither is an
error.

#### Create an external (`x1`) DID

An external DID is minted from an externally-authored **intermediate document**
(a DID document whose identifier is the `did:btcr2:_` placeholder). This mode
consumes **no signing key** — `--intermediate-document` is mutually exclusive
with `--generate` and every key source. The optional `--sidecar-out` flag writes
a ready-to-use sidecar so the resulting DID can be resolved later:

```bash
cargo run -p did-btcr2-cli -- create \
  --intermediate-document ./intermediate.json \
  --sidecar-out ./sidecar.json \
  --network signet
```

This prints the `did:btcr2:x1...` identifier and the initial document as JSON,
plus a stderr note that the `x1` DID is **not deterministically resolvable** — it
must be resolved with `resolve --sidecar <file>`. With `--sidecar-out`, the
written file is `{"genesisDocument": <intermediate document>}`; feed it straight
into `resolve --sidecar` (see below). The `x1` genesis bytes are the hash of the
intermediate document, so the resolve-side re-derivation binds the two together.

### Resolve a DID (read-only)

Resolve the fixed-key **testnet** DID against the default (testnet) endpoint —
the DID's `k1qvp...` prefix matches, so this returns its genesis document:

```bash
# Default network (testnet)
cargo run -p did-btcr2-cli -- resolve \
  did:btcr2:k1qvp8n0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xqmxnpr4

# Same DID resolves against mutinynet too (mutinynet shares testnet address forms)
cargo run -p did-btcr2-cli -- resolve --network mutinynet \
  did:btcr2:k1qvp8n0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xqmxnpr4

# Point at a self-hosted Esplora instance (must serve the DID's network)
cargo run -p did-btcr2-cli -- resolve \
  --esplora-url https://node.example/api \
  did:btcr2:k1qvp8n0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xqmxnpr4
```

The output is the spec resolution triple as pretty-printed JSON. This is the
**real captured** genesis triple for the testnet DID (`versionId` is the string
`"1"`; note the trailing `didResolutionMetadata` field ordering):

```json
{
  "didDocument": {
    "@context": [
      "https://www.w3.org/ns/did/v1.1",
      "https://btcr2.dev/context/v1"
    ],
    "id": "did:btcr2:k1qvp8n0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xqmxnpr4",
    "verificationMethod": [
      {
        "controller": "did:btcr2:k1qvp8n0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xqmxnpr4",
        "id": "did:btcr2:k1qvp8n0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xqmxnpr4#initialKey",
        "publicKeyMultibase": "zQ3shVc2UkAfJCdc1TR8E66J85h48P43r93q8jGPkPpjF9Ef9",
        "type": "Multikey"
      }
    ],
    "//": "assertionMethod / authentication / capabilityDelegation / capabilityInvocation / service omitted for brevity"
  },
  "didDocumentMetadata": {
    "deactivated": false,
    "versionId": "1"
  },
  "didResolutionMetadata": {}
}
```

### Resolve with sidecar data

`resolve --sidecar <file>` supplies out-of-band data the resolver cannot fetch
from the chain. It covers two distinct flows:

1. **Update-payload sidecar** — for a DID whose updates were delivered
   out-of-band rather than as on-chain OP_RETURN signals:

   ```bash
   cargo run -p did-btcr2-cli -- resolve --sidecar ./sidecar.json \
     did:btcr2:k1qvp8n0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xqmxnpr4
   ```

2. **Genesis / external-creation sidecar** — for an `x1` DID minted with
   `create --intermediate-document`, whose genesis (intermediate) document is not
   published on-chain. The sidecar written by `create --sidecar-out` is consumed
   directly:

   ```bash
   # 1. mint the x1 DID and write its genesis sidecar
   cargo run -p did-btcr2-cli -- create \
     --intermediate-document ./intermediate.json \
     --sidecar-out ./sidecar.json --network signet
   # 2. resolve it back using that sidecar
   cargo run -p did-btcr2-cli -- resolve --sidecar ./sidecar.json <the-x1-did>
   ```

`--sidecar` is a *resolve-time* **input**. Note the distinction from create's
`--sidecar-out`, which is an **output**: `create` does not accept `--sidecar` (a
resolve input), but it does accept `--sidecar-out` to produce a genesis sidecar
for a later resolve. `create` still rejects `--esplora-url`. See
[RUNBOOK.md](./RUNBOOK.md) for both the on-chain-vs-sidecar update flow and the
`x1` external-creation lifecycle.

### Update a document

> **These `update`/`deactivate` commands are NOT copy-paste runnable here.**
> They require funded UTXOs at the DID's beacon address, and **even `--dry-run`
> performs funding GETs** against that address — with no UTXOs they fail. For a
> runnable, funded, end-to-end write walkthrough (with a faucet), see
> **[RUNBOOK.md](./RUNBOOK.md)**. The snippets below show the command shape only.

The patch is an RFC-6902 JSON Patch. For example, `patch.json` adding a
verification method to `assertionMethod`:

```json
[
  {
    "op": "add",
    "path": "/assertionMethod/-",
    "value": "did:btcr2:k1qvp8n0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xqmxnpr4#initialKey"
  }
]
```

Preview the transaction without broadcasting (still needs a funded beacon — the
funding GETs run regardless):

```bash
cargo run -p did-btcr2-cli -- update \
  did:btcr2:k1qvp8n0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xqmxnpr4 \
  --patch ./patch.json \
  --key-file ./demo.hex \
  --network signet \
  --dry-run
```

Broadcast for real (requires funded UTXOs at the beacon address):

```bash
cargo run -p did-btcr2-cli -- update \
  did:btcr2:k1qvp8n0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xqmxnpr4 \
  --patch ./patch.json \
  --key-file ./demo.hex \
  --network signet \
  --feerate 2.0 \
  --yes
```

Read the key from the environment instead of a file:

```bash
export DIDBTCR2_KEY=$(cat ./key.hex)
cargo run -p did-btcr2-cli -- update <did> --patch ./patch.json --network signet --dry-run
```

### Deactivate a document

Same key/fee/broadcast flags as `update`, with no `--patch` (the patch is
implicit):

```bash
# Preview
cargo run -p did-btcr2-cli -- deactivate <did> \
  --key-file ./key.hex --network signet --dry-run

# Broadcast
cargo run -p did-btcr2-cli -- deactivate <did> \
  --key-file ./key.hex --network signet --yes
```

## Behavior notes

- **Exit status & errors.** All errors print to stderr as `Error: <message>`
  with a `Caused by:` chain, and the process exits non-zero. The CLI does not
  panic on bad input, bad keys, or transport failures.
- **`--dry-run` issues zero `POST /tx`.** It performs the funding GETs and prints
  the txid and raw hex only.
- **Real writes broadcast the previewed transaction.** The summary you confirm
  and the bytes that are broadcast are identical — the transaction is not rebuilt
  after confirmation, so a UTXO change mid-flight cannot swap it out from under
  you.
- **`--vm <id>`** selects the verification method to sign with; it defaults to
  `<did>#initialKey`.
