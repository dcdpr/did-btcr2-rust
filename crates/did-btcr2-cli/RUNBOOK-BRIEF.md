# did-btcr2-cli — live demo on mutinynet (brief)

Full `did:btcr2` lifecycle, live on mutinynet, with a freshly generated key you control:

```
create → fund beacon → resolve (genesis) → update → resolve (v2) → deactivate → resolve (v3)
```

mutinynet has ~30-second blocks and a public faucet, so the whole run takes a few minutes.
All commands run from the workspace root (`did-btcr2-rust/`). Example values come from one
real run — yours will differ.

Build once so the first demo command doesn't stall on a compile:

```bash
cargo build -p did-btcr2-cli
```

---

## Step 1 — Generate a fresh key and mint the DID

`create --generate` mints a new secp256k1 secret, prints the DID and genesis document, and
prints the secret once. Zero network calls.

```bash
cargo run -q -p did-btcr2-cli -- create --generate --network mutinynet
```

```
did:btcr2:k1q5p5vav8nftv4zfwqsmezyehsc6vqqelh6yfklhukv5ky2mkpsus94gxsswss
{ ...genesis document... }
```
```
store this secret — it controls the DID and is shown only once:      (stderr)
<64 hex chars — THIS controls the DID; keep it private>              (stdout)
```

> **⚠ This secret controls the DID.** Never paste it into a chat, a slide, or a shared terminal.

Save it as raw hex with **no trailing newline**:

```bash
printf '%s' <64 hex chars> > ./demo.hex
chmod 600 ./demo.hex
```

Re-derive the DID from the file (prints no secret) and capture the genesis document.
`create` is deterministic, so this yields the same DID as above:

```bash
GENESIS=$(cargo run -q -p did-btcr2-cli -- create --key-file ./demo.hex --network mutinynet)
DID=$(printf '%s\n' "$GENESIS" | head -1)
echo "$DID"
```

Read the **P2WPKH beacon address** off the document — the `serviceEndpoint` of the
`#initialP2WPKH` service, minus the `bitcoin:` prefix. This is the beacon that
`update`/`deactivate` fund and spend:

```bash
printf '%s\n' "$GENESIS"
BEACON=tb1q7cxg5r2srj5uuxaa46d2na96n6fuhnnqvrl9as   # <- your address, not this one
echo "$BEACON"
```

The `k1q5p…` prefix encodes the mutinynet network. The document also carries
`#initialP2PKH` and `#initialP2TR` beacons; this demo uses the default P2WPKH one.

---

## Step 2 — Fund the beacon address

Write operations spend a UTXO at the beacon address. Send from your mutinynet wallet or use
the faucet (<https://faucet.mutinynet.com/>). Default fee is 1000 sats — 100 000 sats is plenty.

```bash
echo "send test coins to: $BEACON"
```

Wait for one confirmation (~30s). Watch it on <https://mutinynet.com/>, or check the endpoint:

```bash
cargo run -q -p did-btcr2-cli -- resolve --network mutinynet "$DID" >/dev/null && echo "endpoint reachable"
```

---

## Step 3 — Resolve the genesis document (`versionId "1"`)

A key-based DID with no beacon signals resolves deterministically to its genesis document.
Funding an address is not a beacon signal, so this holds even after Step 2.

```bash
cargo run -q -p did-btcr2-cli -- resolve --network mutinynet "$DID"
```

```json
{
  "didDocument": { "id": "did:btcr2:k1q5p…", "//": "verificationMethod / service / relationship arrays" },
  "didDocumentMetadata": { "deactivated": false, "versionId": "1" },
  "didResolutionMetadata": {}
}
```

No chain writes yet — this document derives purely from the key, and anyone can reproduce it
from the DID alone.

---

## Step 4 — Update via a beacon signal (`versionId → "2"`)

Apply an RFC-6902 JSON Patch through a beacon-signal transaction. This spends the UTXO from
Step 2 and broadcasts for real.

Write a patch appending the DID's own key reference to `assertionMethod`:

```bash
cat > ./patch.json <<EOF
[
  { "op": "add", "path": "/assertionMethod/-", "value": "${DID}#initialKey" }
]
EOF
```

Broadcast it. `--sidecar-out` writes the update payload to a file, which Step 5 feeds back
to `resolve`:

```bash
cargo run -q -p did-btcr2-cli -- update "$DID" \
  --patch ./patch.json \
  --key-file ./demo.hex \
  --network mutinynet \
  --sidecar-out ./update-v2.sidecar.json \
  --yes
```

```
about to broadcast a beacon-signal transaction:
  txid:    <real txid>
  inputs:  1
  outputs: 2
  vsize:   … vB
broadcast txid: <real txid>
wrote sidecar: ./update-v2.sidecar.json
```

The update key doubles as the beacon key by default and change returns to the beacon address,
so no extra flags are needed. The sidecar file is written only after a successful broadcast.

---

## Step 5 — Resolve after the update confirms (`versionId "2"`)

The on-chain signal is only a 32-byte commitment, not the update itself — so `resolve` needs
the sidecar payload from Step 4 to reconstruct v2. Without it, a singleton update fails with
`MISSING_UPDATE_DATA`.

```bash
cargo run -q -p did-btcr2-cli -- resolve --sidecar ./update-v2.sidecar.json \
  --network mutinynet "$DID"
```

```json
{
  "didDocument": {
    "id": "did:btcr2:k1q5p…",
    "assertionMethod": [
      "did:btcr2:k1q5p…#initialKey",
      "did:btcr2:k1q5p…#initialKey"
    ],
    "//": "other fields omitted"
  },
  "didDocumentMetadata": { "deactivated": false, "versionId": "2" },
  "didResolutionMetadata": {}
}
```

The same DID now resolves to an updated document, proven by a real Bitcoin transaction.

---

## Step 6 — Deactivate, then resolve (`deactivated: true`, `versionId "3"`)

`deactivate` takes the same flags as `update` with no `--patch`, and spends the change UTXO
from Step 4 — no re-funding needed. Pass the Step-4 sidecar as input and a new output file so
the emitted sidecar carries the full chain (update + deactivation):

```bash
cargo run -q -p did-btcr2-cli -- deactivate "$DID" \
  --key-file ./demo.hex \
  --network mutinynet \
  --sidecar ./update-v2.sidecar.json \
  --sidecar-out ./deactivate-v3.sidecar.json \
  --yes
```

Once it confirms, resolve with the accumulated sidecar:

```bash
cargo run -q -p did-btcr2-cli -- resolve --sidecar ./deactivate-v3.sidecar.json \
  --network mutinynet "$DID"
```

```json
{
  "didDocument": { "id": "did:btcr2:k1q5p…" },
  "didDocumentMetadata": { "deactivated": true, "versionId": "3" },
  "didResolutionMetadata": {}
}
```

A deactivated DID is terminal — no further updates apply.

---

## Cleanup

```bash
rm -f ./demo.hex ./patch.json ./update-v2.sidecar.json ./deactivate-v3.sidecar.json
```

The DID and its history stay on mutinynet forever; deleting `demo.hex` just discards the
controlling key.

See **[RUNBOOK.md](./RUNBOOK.md)** for the annotated version of this walkthrough,
**[RUNBOOK-REPRODUCIBLE.md](./RUNBOOK-REPRODUCIBLE.md)** for the fixed-key reproducible run,
and **[README.md](./README.md)** for the full command/flag reference.
