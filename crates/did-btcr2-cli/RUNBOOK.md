# did-btcr2-cli RUNBOOK — full DID lifecycle on mutinynet

This runbook walks the complete `did:btcr2` lifecycle end-to-end on **mutinynet**
(a signet-based test network with a public faucet and ~30-second blocks):

```
create → fund beacon → resolve (genesis) → update → resolve → deactivate → resolve
```

For the command/flag reference and the read-only `create`/`resolve` examples, see
the **[README.md](./README.md)**.

## Real vs. SAMPLE output

- **READ-ONLY steps** (`create`, genesis `resolve`) show **REAL captured output**
  from running the CLI against the demo key. You can reproduce them verbatim.
- **WRITE / faucet steps** (`fund`, `update`, `deactivate`, and the resolves that
  depend on a broadcast) are **USER-run**. Their output here is **labeled
  `SAMPLE`** — illustrative shapes, not something this document executed. Do not
  treat SAMPLE txids/UTXOs as real. Nothing in this runbook was broadcast, funded,
  or spent on any live network.

## Fixed demo key — PUBLICLY KNOWN, never for a real DID

Every step below uses one fixed demo secret key so the read-only output
reproduces exactly. The key (32-byte lowercase hex) is:

```
0000000000000000000000000000000000000000000000000000000000000001
```

> **⚠ SECURITY — this key is PUBLICLY KNOWN.** It is printed here verbatim, so
> **anyone** can derive its keys and control any DID made from it. Use it ONLY to
> reproduce this documentation. For any real DID, mint a fresh secret with
> `create --generate` and keep it private.

Write it to a file (no trailing newline — `create` reads raw hex):

```bash
printf '%s' 0000000000000000000000000000000000000000000000000000000000000001 > ./demo.hex
```

All commands run from the workspace root (`did-btcr2-rust/`) via `cargo run`.

---

## Step 1 — Create the mutinynet DID (READ-ONLY, real output)

`create` is deterministic and makes zero network calls. The `k1q5p...` prefix is
the mutinynet network marker encoded in the DID.

```bash
cargo run -p did-btcr2-cli -- create --key-file ./demo.hex --network mutinynet
```

REAL captured output — DID line, then the genesis document (trimmed to the key
fields; the four verification-relationship arrays and the P2PKH/P2TR beacons are
elided for brevity):

```
did:btcr2:k1q5p8n0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xqr4e30t
```

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1.1",
    "https://btcr2.dev/context/v1"
  ],
  "id": "did:btcr2:k1q5p8n0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xqr4e30t",
  "verificationMethod": [
    {
      "controller": "did:btcr2:k1q5p8n0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xqr4e30t",
      "id": "did:btcr2:k1q5p8n0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xqr4e30t#initialKey",
      "publicKeyMultibase": "zQ3shVc2UkAfJCdc1TR8E66J85h48P43r93q8jGPkPpjF9Ef9",
      "type": "Multikey"
    }
  ],
  "service": [
    {
      "id": "did:btcr2:k1q5p8n0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xqr4e30t#initialP2WPKH",
      "serviceEndpoint": "bitcoin:tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
      "type": "SingletonBeacon"
    }
  ]
}
```

The default funded beacon is **P2WPKH** — its address is the
`#initialP2WPKH` service's `bitcoin:` endpoint above
(`tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx` for this demo key).

### On-chain vs. sidecar (context for step 5)

`resolve --sidecar <file>` is a resolve-time **input**. `create` does not accept
`--sidecar` (a resolve input), but it does accept `--sidecar-out` — an **output**
that writes a genesis sidecar for an external (`x1`) DID (see the `x1`
external-creation lifecycle below). The resolve-time `--sidecar` governs how
resolver inputs that are not on the chain reach the resolver:

- **on-chain (default):** the beacon transaction carries an OP_RETURN commitment;
  the resolver reads the update from the chain.
- **update sidecar:** the update payload is delivered out-of-band as a file,
  passed to `resolve --sidecar <file>`.
- **genesis sidecar:** an `x1` DID's genesis (intermediate) document is delivered
  out-of-band; the same `resolve --sidecar <file>` bridges it into the initial
  document and validates it against the `x1` genesis bytes.

Step 5 shows both paths for the update→resolve leg.

### `x1` external-creation lifecycle (create-external → sidecar-out → resolve)

An external DID is minted from an externally-authored intermediate document
(identifier `did:btcr2:_`) and consumes **no signing key**. Unlike a key-based
`k1` DID, an `x1` DID is **not deterministically resolvable** — resolving it
requires its genesis document as sidecar data.

```bash
# 1. mint the x1 DID from the intermediate document, writing a genesis sidecar
cargo run -p did-btcr2-cli -- create \
  --intermediate-document ./intermediate.json \
  --sidecar-out ./sidecar.json \
  --network signet
#    -> prints the did:btcr2:x1... DID + initial document; writes sidecar.json as
#       {"genesisDocument": <intermediate document>}

# 2. resolve the x1 DID back using that sidecar (offline for genesis: no beacon
#    signals are expected on the freshly minted genesis document)
cargo run -p did-btcr2-cli -- resolve --sidecar ./sidecar.json <the-x1-did>
```

`--intermediate-document` is mutually exclusive with `--generate` and every key
source (`--key-file`/`--key-stdin`/`DIDBTCR2_KEY`); combining them is an error and
no key is read. With no sidecar at all, resolving an `x1` DID errors (its genesis
document cannot be retrieved — the genesis-CAS path is not yet implemented).

#### `x1` on `regtest` — create → resolve round-trip against a local esplora

The did:btcr2 `x1` test vectors are authored on **regtest**, which has no hosted
Esplora endpoint. Mint the `x1` DID with `--network regtest`, then resolve it back
by pointing `--esplora-url` at your local esplora and feeding the genesis sidecar
(omitting `--esplora-url` errors with
`regtest has no default Esplora endpoint; pass --esplora-url`):

```bash
# 1. mint the x1 regtest DID + genesis sidecar (offline, zero network calls)
cargo run -p did-btcr2-cli -- create \
  --intermediate-document ./intermediate.json \
  --sidecar-out ./sidecar.json \
  --network regtest
# 2. resolve it back against a local esplora, using that genesis sidecar
cargo run -p did-btcr2-cli -- resolve --network regtest \
  --esplora-url http://<your-local-esplora>/api \
  --sidecar ./sidecar.json <the-x1-did>
```

---

## Step 2 — Fund the beacon address (USER step, faucet)

Write operations spend a UTXO at the beacon address, so it must be funded first.

The address is the `#initialP2WPKH` beacon endpoint from step 1
(`tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx` for this demo key). Send test coins
to it from the mutinynet faucet (<https://faucet.mutinynet.com/>).

> This is a manual step. The runbook does not fund anything.

SAMPLE resulting UTXO (illustrative — not a real UTXO):

```
SAMPLE  address: tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx
SAMPLE  funding txid: 0000000000000000000000000000000000000000000000000000000000000000:0
SAMPLE  value: 100000 sat
```

Wait for one confirmation (~30s on mutinynet) before the write steps.

---

## Step 3 — Resolve the genesis document (READ-ONLY, real output)

A key-based DID with no on-chain beacon signals resolves to its **genesis
document** at `versionId "1"`. This holds **before funding** — resolution reads
beacon signals, and an unfunded/unused beacon has none. Resolve the mutinynet DID
against the mutinynet endpoint:

```bash
cargo run -p did-btcr2-cli -- resolve --network mutinynet \
  did:btcr2:k1q5p8n0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xqr4e30t
```

REAL captured output (resolution triple, document trimmed to key fields;
`versionId` is the string `"1"`):

```json
{
  "didDocument": {
    "@context": [
      "https://www.w3.org/ns/did/v1.1",
      "https://btcr2.dev/context/v1"
    ],
    "id": "did:btcr2:k1q5p8n0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xqr4e30t",
    "//": "verificationMethod / service / relationship arrays omitted for brevity"
  },
  "didDocumentMetadata": {
    "deactivated": false,
    "versionId": "1"
  },
  "didResolutionMetadata": {}
}
```

---

## Step 4 — Update via a beacon signal (USER-run write, SAMPLE output)

Apply an RFC-6902 JSON Patch through a beacon-signal transaction. This spends the
funded UTXO from step 2 and broadcasts — it is user-run, and the output below is
SAMPLE. Even `--dry-run` performs the funding GETs, so it too needs a funded
beacon.

`patch.json` (add a value to `assertionMethod`):

```json
[
  {
    "op": "add",
    "path": "/assertionMethod/-",
    "value": "did:btcr2:k1q5p8n0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xqr4e30t#initialKey"
  }
]
```

Broadcast the update (`--yes` skips the confirm prompt):

```bash
cargo run -p did-btcr2-cli -- update \
  did:btcr2:k1q5p8n0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xqr4e30t \
  --patch ./patch.json \
  --key-file ./demo.hex \
  --network mutinynet \
  --yes
```

SAMPLE broadcast output (illustrative txid — not real):

```
SAMPLE  broadcast update beacon signal
SAMPLE  txid: 1111111111111111111111111111111111111111111111111111111111111111
```

---

## Step 5 — Resolve after update (both delivery paths)

### 5a. On-chain path (default) — USER-run, SAMPLE output

Once the step-4 transaction confirms, the OP_RETURN commitment is on-chain and a
plain `resolve` picks it up, advancing `versionId` to `"2"`:

```bash
cargo run -p did-btcr2-cli -- resolve --network mutinynet \
  did:btcr2:k1q5p8n0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xqr4e30t
```

SAMPLE output (depends on a real broadcast — not captured here):

```json
{
  "didDocument": {
    "id": "did:btcr2:k1q5p8n0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xqr4e30t",
    "//": "assertionMethod now includes the added entry from patch.json"
  },
  "didDocumentMetadata": {
    "deactivated": false,
    "versionId": "2"
  },
  "didResolutionMetadata": {}
}
```

### 5b. Sidecar path — USER-run, SAMPLE output

If the update payload was delivered out-of-band (as `sidecar.json`) instead of via
the on-chain OP_RETURN, pass it to `resolve --sidecar`:

```bash
cargo run -p did-btcr2-cli -- resolve --network mutinynet \
  --sidecar ./sidecar.json \
  did:btcr2:k1q5p8n0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xqr4e30t
```

SAMPLE output: the same resolved document and `"versionId": "2"` as 5a — the
difference is only *how the update payload reached the resolver* (out-of-band file
vs. on-chain), not the result.

---

## Step 6 — Deactivate, then resolve (USER-run write, SAMPLE output)

`deactivate` takes the same key/fee/broadcast flags as `update`, with no
`--patch`. It broadcasts a beacon signal marking the DID deactivated — user-run,
SAMPLE output:

```bash
cargo run -p did-btcr2-cli -- deactivate \
  did:btcr2:k1q5p8n0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xqr4e30t \
  --key-file ./demo.hex \
  --network mutinynet \
  --yes
```

SAMPLE broadcast output (illustrative txid — not real):

```
SAMPLE  broadcast deactivate beacon signal
SAMPLE  txid: 2222222222222222222222222222222222222222222222222222222222222222
```

Resolve once the deactivation confirms — `deactivated` flips to `true`:

```bash
cargo run -p did-btcr2-cli -- resolve --network mutinynet \
  did:btcr2:k1q5p8n0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xqr4e30t
```

SAMPLE output (depends on a real broadcast — not captured here):

```json
{
  "didDocument": {
    "id": "did:btcr2:k1q5p8n0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xqr4e30t"
  },
  "didDocumentMetadata": {
    "deactivated": true,
    "versionId": "3"
  },
  "didResolutionMetadata": {}
}
```

A deactivated DID is terminal — no further updates apply.

---

## Cleanup

```bash
rm -f ./demo.hex ./patch.json ./sidecar.json
```

See **[README.md](./README.md)** for the full command/flag reference.
