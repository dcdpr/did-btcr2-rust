# did-btcr2-cli RUNBOOK — live demo (fresh key) on mutinynet

This runbook drives the **complete `did:btcr2` lifecycle live on mutinynet** using
a **freshly generated key that you control**, so the write steps produce **real,
owned on-chain transactions** you can show off:

```
create → fund beacon → resolve (genesis) → update → resolve (v2) → deactivate → resolve (v3)
```

mutinynet is a signet-based test network with a public faucet and ~30-second
blocks, so the whole lifecycle runs in a few minutes.

> **Want byte-for-byte reproducible output instead?** See
> **[RUNBOOK-REPRODUCIBLE.md](./RUNBOOK-REPRODUCIBLE.md)**, which pins every step
> to one fixed public demo key. That file is a stable reference; **this** file is
> for a live demo you actually broadcast.
>
> For the full flag/command reference and the read-only `create`/`resolve`
> examples, see **[README.md](./README.md)**.

## What is real here

Because the key is generated fresh, **your DID, beacon addresses, and txids will
differ on every run** — none of the example output below is reproducible, and it
is not meant to be. The example values are from one real run, shown only to
illustrate the *shape* of each step. When **you** run the write steps against
your funded wallet, those broadcasts are real.

> **⚠ Rehearse once before showing anyone.** `create` and `resolve` are exercised
> constantly, but the `update`/`deactivate` broadcast path is only covered by
> tests against an in-process fake transport — a live end-to-end broadcast is not
> part of CI. Do one full dress rehearsal (this whole runbook) with your funded
> wallet before demoing, so nothing surprises you on stage.

## Convention: capture values in shell variables

The DID and beacon address are long; capture them once so later steps are clean
copy-paste. All commands run from the workspace root (`did-btcr2-rust/`).

Optional: build once up front so `cargo run` doesn't interleave a compile into
your first demo command.

```bash
cargo build -p did-btcr2-cli
```

---

## Step 1 — Generate a fresh key and mint the DID (offline, instant)

`create --generate` mints a brand-new secp256k1 secret, prints the DID + genesis
document, and prints the secret **once**. It makes zero network calls.

```bash
cargo run -q -p did-btcr2-cli -- create --generate --network mutinynet
```

Example output (yours will differ). The DID is the first line; the genesis
document follows; the 64-hex-char secret is the last line, after a "store this
secret" note on stderr:

```
did:btcr2:k1q5p5vav8nftv4zfwqsmezyehsc6vqqelh6yfklhukv5ky2mkpsus94gxsswss
{ ...genesis document... }
```
```
store this secret — it controls the DID and is shown only once:      (stderr)
<64 hex chars — THIS controls the DID; keep it private>              (stdout)
```

> **⚠ This is YOUR real controlling secret.** Anyone who has it controls the DID.
> Store it privately; never paste it into a chat, a slide, or a shared terminal.

Save the secret to a file (raw hex, **no trailing newline** — the CLI reads raw
32-byte lowercase hex), replacing `<64 hex chars>` with the value just printed:

```bash
printf '%s' <64 hex chars> > ./demo.hex
chmod 600 ./demo.hex
```

Now re-derive the DID deterministically from that file (this prints **no**
secret) and capture the whole genesis document once. `create` is deterministic,
so this yields the same DID and document as step 1:

```bash
GENESIS=$(cargo run -q -p did-btcr2-cli -- create --key-file ./demo.hex --network mutinynet)
DID=$(printf '%s\n' "$GENESIS" | head -1)   # the DID is the first line
echo "$DID"
```

> **Capture the full output first (as above); don't pipe `create` straight into
> `head`.** `create … | head -1` prints the DID but then the CLI panics with
> `Broken pipe (os error 32)` when `head` closes the pipe early — a known Rust
> `println!` + SIGPIPE behavior, not corruption (`$DID` is still captured
> correctly). Capturing into `$GENESIS` first and slicing the variable sidesteps
> it entirely.

Read the **P2WPKH beacon address** off that captured document — it is the
`serviceEndpoint` of the `#initialP2WPKH` service (drop the `bitcoin:` prefix).
This is the default beacon that `update`/`deactivate` fund and spend:

```bash
printf '%s\n' "$GENESIS"   # in the "service" array, find the "#initialP2WPKH" entry, e.g.:
#   "serviceEndpoint": "bitcoin:tb1q7cxg5r2srj5uuxaa46d2na96n6fuhnnqvrl9as"
BEACON=tb1q7cxg5r2srj5uuxaa46d2na96n6fuhnnqvrl9as   # <- your address, not this one
echo "$BEACON"
```

The `k1q5p…` prefix marks the mutinynet network encoded in the DID. The
document also carries `#initialP2PKH` and `#initialP2TR` beacon addresses; this
demo funds the default **P2WPKH** one.

---

## Step 2 — Fund the beacon address (your wallet or the faucet)

Write operations spend a UTXO at the beacon address, so fund `$BEACON` first.
Either send from your mutinynet wallet, or use the faucet
(<https://faucet.mutinynet.com/>). The default fee is 1000 sats, so anything
comfortably above that is plenty — e.g. 100 000 sats.

```bash
echo "send test coins to: $BEACON"
```

Wait for **one confirmation** (~30s on mutinynet) before the write steps. You can
watch the address on the mutinynet explorer (<https://mutinynet.com/>) or with:

```bash
cargo run -q -p did-btcr2-cli -- resolve --network mutinynet "$DID" >/dev/null && echo "endpoint reachable"
```

---

## Step 3 — Resolve the genesis document (`versionId "1"`)

A key-based DID with no on-chain beacon signals resolves deterministically to its
**genesis document** at `versionId "1"`. This holds even after funding —
resolution reads *beacon signals* (updates), and simply funding an address is not
one.

```bash
cargo run -q -p did-btcr2-cli -- resolve --network mutinynet "$DID"
```

Example output (resolution triple; document trimmed here for brevity):

```json
{
  "didDocument": { "id": "did:btcr2:k1q5p…", "//": "verificationMethod / service / relationship arrays" },
  "didDocumentMetadata": { "deactivated": false, "versionId": "1" },
  "didResolutionMetadata": {}
}
```

Talking point: *no chain writes yet — this document is derived purely from the
key, off-chain, and anyone can reproduce it from the DID alone.*

---

## Step 4 — Update via a beacon signal (real broadcast, `versionId → "2"`)

Apply an RFC-6902 JSON Patch through a beacon-signal transaction. This spends the
funded UTXO from step 2 and **broadcasts for real**.

Write a patch that appends the DID's own key reference to `assertionMethod`
(`$DID` is expanded into the file):

```bash
cat > ./patch.json <<EOF
[
  { "op": "add", "path": "/assertionMethod/-", "value": "${DID}#initialKey" }
]
EOF
```

> This minimal patch just grows the `assertionMethod` array so the change is
> obvious on the next resolve — it is enough to demonstrate the on-chain update
> mechanism. In real use you would typically add a *new* verification method
> here; the machinery (sign → announce → resolve) is identical.

Broadcast the update. The CLI prints a transaction summary and prompts for
confirmation; drop `--yes` if you want to show that prompt live:

```bash
cargo run -q -p did-btcr2-cli -- update "$DID" \
  --patch ./patch.json \
  --key-file ./demo.hex \
  --network mutinynet \
  --yes
```

Example output (your txid will differ — this is a **real** broadcast):

```
about to broadcast a beacon-signal transaction:
  txid:    <real txid>
  inputs:  1
  outputs: 2
  vsize:   … vB
broadcast txid: <real txid>
```

The update key doubles as the beacon key by default (the default singleton
beacons are spendable by the DID key), and change returns to the beacon address —
so no extra flags are needed. Tip: `--dry-run` builds and prints the exact
transaction (txid + raw hex) **without** broadcasting, but it still performs the
funding lookups, so it too needs the beacon funded.

---

## Step 5 — Resolve after the update confirms (`versionId "2"`)

Once the step-4 transaction confirms (~30s), the OP_RETURN commitment is on-chain
and a plain `resolve` picks it up, advancing `versionId` to `"2"`:

```bash
cargo run -q -p did-btcr2-cli -- resolve --network mutinynet "$DID"
```

Example output — `assertionMethod` now carries the appended entry and the version
has advanced:

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

This is the money moment: **the same DID now resolves to an updated document,
and the update was proven by a real Bitcoin transaction on mutinynet.**

---

## Step 6 — Deactivate, then resolve (`deactivated: true`, `versionId "3"`)

`deactivate` takes the same key/fee/broadcast flags as `update` with no
`--patch`. It broadcasts a beacon signal marking the DID deactivated (this spends
the change UTXO left by step 4, so no re-funding is needed):

```bash
cargo run -q -p did-btcr2-cli -- deactivate "$DID" \
  --key-file ./demo.hex \
  --network mutinynet \
  --yes
```

Once it confirms, resolve once more — `deactivated` flips to `true`:

```bash
cargo run -q -p did-btcr2-cli -- resolve --network mutinynet "$DID"
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
rm -f ./demo.hex ./patch.json
```

The DID and its history remain on mutinynet forever (it is a public ledger);
deleting `demo.hex` just discards the controlling key so nobody — including you —
can update it further.

See **[README.md](./README.md)** for the full command/flag reference, and
**[RUNBOOK-REPRODUCIBLE.md](./RUNBOOK-REPRODUCIBLE.md)** for the fixed-key,
byte-for-byte reproducible version of this walkthrough (including the `x1`
external-creation lifecycle).
