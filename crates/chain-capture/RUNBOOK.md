# chain-capture RUNBOOK — one capture-and-mint session

`chain-capture` is a developer utility. It records the Esplora responses a real
`did:btcr2` resolve asks for — the per-address `/address/{a}/txs` bodies and the
chain tip — into `fixtures/chain/`, and it mints the two scenarios that no
upstream vector covers so there is real chain data to record in the first place.

**None of this is on the test path.** The fixtures it writes are replayed
offline, so `cargo test` never starts a container, never contacts a network and
never needs a key. This document is the only thing that does. It is run by a
human, by hand, when the fixtures need to be produced or reproduced.

Every command below runs from the **`did-btcr2-rust` workspace root** — the
directory holding `Cargo.toml`, `crates/`, `fixtures/` and `test-suite/`. When
this repository is checked out as a submodule of the development superproject,
that is `did-btcr2-rust/`; `cd` into it first.

Build once up front so a compile does not interleave with the first command:

```sh
cargo build -p chain-capture
```

You need: Docker with the `compose` plugin, `unzip`, `curl`, and roughly 300 MB
of free disk for the unpacked regtest chain.

---

## Session order (do not reorder)

1. **Part 1** — stand the Polar chain up and capture the **four** vendor regtest
   vectors. **Do not mine.** Leave the stack **running**.
2. **Part 2** — capture the **three** vendor mutinynet vectors. Independent of
   Polar, but do it in the same sitting.
3. **Part 3** — mint the **two** scenarios on the same running Polar chain.
   Mining is allowed from here, and only from here.
4. **Part 4** — tear the stack down, delete the unpacked chain, check what
   landed.

The reason is arithmetic, not preference. The four vendor regtest vectors state
`confirmations` **93**, **78**, **65** and **53**, and all four are measured
against **one frozen chain tip**. The Polar export ships `"autoMineMode": 0`
precisely so that chain does not drift on its own. Minting raises the tip, and
raising the tip breaks all four expectations at once.

`chain-capture` refuses to produce a block while any of those four fixtures is
missing, and names the ones that are outstanding, so getting this backwards
fails loudly rather than silently. But the refusal costs you a restart of the
whole session, so do it in order.

---

## Part 1 — regtest vendor vectors (frozen chain)

Captures four vectors:

| Vector | `confirmations` |
|---|---|
| `regtest/k1/qgppexmy` | 93 |
| `regtest/k1/qgpy0hmm` | 78 |
| `regtest/x1/q26jeds9` | 65 |
| `regtest/x1/qfl7se8f` | 53 |

### 1. Unpack the Polar export OUTSIDE the repository

~18 MB zipped, ~289 MB unpacked, 122 files. None of it is ever committed, so it
is unpacked to a scratch path rather than anywhere under the working tree.

```sh
unzip -l test-suite/regtest/did-btcr2.polar.zip | head -8
mkdir -p /tmp/btcr2-polar
unzip -q test-suite/regtest/did-btcr2.polar.zip -d /tmp/btcr2-polar
test -f /tmp/btcr2-polar/docker-compose.yml && echo 'compose file at archive root: OK'
```

The archive unpacks **flat**: `docker-compose.yml` and `export.json` sit at the
archive root, next to `volumes/bitcoind/backend1`, which carries the bitcoind
blocks and the electrs index. The listing step exists so that a future
re-packaging that nests everything one level deeper is caught here, instead of
as a confusing `docker compose` failure two steps later. If the listing shows a
single top-level directory, point the later `-f` paths inside it.

### 2. Raise bitcoind's maximum tip age BEFORE starting anything

**Required, not optional, and it gets more required every day.** Add one flag to
bitcoind's command in the unpacked compose file:

```sh
sed -i 's/ -blockfilterindex=1 -peerblockfilters=1/&\n      -maxtipage=999999999/' \
  /tmp/btcr2-polar/docker-compose.yml
grep -q 'maxtipage' /tmp/btcr2-polar/docker-compose.yml && echo 'maxtipage set: OK'
```

Bitcoin Core reports `initialblockdownload: true` for any chain whose tip is
older than `-maxtipage` (default 86400 seconds — one day), *regardless of whether
the chain is fully synced*. This chain's tip is frozen at a fixed date in the
past and recedes further every day, so on any machine it is permanently in
"initial block download" as far as the flag is concerned. electrs's startup loop
gates on exactly that flag: it logs

```
WARN waiting for bitcoind sync to finish: 758/758 blocks, verification progress: 100.000%
```

forever — announcing that sync is complete while refusing to serve — and never
opens its HTTP listener. Port 3000 accepts the TCP connection and immediately
resets it.

`-maxtipage` changes no chain state whatsoever: same tip, same block hash, same
heights, same `confirmations`. It only stops bitcoind from calling a
legitimately-old chain "syncing". Mining would also clear the flag, by giving the
tip a current timestamp — and would destroy all four vendor expectations. Do not
be tempted; see the warning at the end of this Part.

### 3. Start the containers

```sh
USERID=$(id -u) GROUPID=$(id -g) \
  docker compose -f /tmp/btcr2-polar/docker-compose.yml up -d
```

Two services come up: `polar-n1-backend1` (bitcoind 29.0, regtest, `-txindex=1`)
and `esplora-electrs`, which serves the Esplora HTTP API. The compose file passes
`USERID`/`GROUPID` through to bitcoind, which is what keeps the unpacked volume
readable by the container.

If you started the stack before applying step 2, apply it now and re-run the
`up -d` above — it recreates bitcoind with the new flag — then
`docker restart esplora-electrs`. The chain lives in a bind-mounted volume, so
recreating the container does not touch it.

### 4. Smoke-test BOTH endpoints before capturing

electrs needs a moment to open its index after a cold start, and bitcoind may
need to load its default wallet. Do not proceed until both answer.

```sh
curl -s http://localhost:3000/blocks/tip/height ; echo
curl -s --user polaruser:polarpass -H 'content-type: application/json' \
  --data '{"jsonrpc":"1.0","id":"rb","method":"getblockcount","params":[]}' \
  http://127.0.0.1:18443/ ; echo
```

- `http://localhost:3000` is the Esplora API (electrs), and the endpoint every
  capture and mint command below names.
- `http://127.0.0.1:18443` is bitcoind's JSON-RPC port. `polaruser:polarpass` is
  the export's own published credential on a throwaway chain — it is in the
  compose file and in the electrs `--cookie` argument.

**Both must report 758.** That is the frozen tip the four `confirmations`
expectations are measured against, and it is a property of the export, not of
your session — an unpacked-and-untouched chain reads 758 on every machine, every
time.

Any other number means this chain has been advanced since the vectors were
generated, and the four expectations below will not reproduce. Stop and find out
why rather than capturing against it: a captured fixture records the tip it saw,
so capturing from a moved chain files four fixtures that silently disagree with
the vendor vectors they claim to reproduce.

### 5. Capture

```sh
cargo run -q -p chain-capture -- \
  capture --network regtest --esplora-url http://localhost:3000
```

`regtest` has no default Esplora endpoint on purpose — there is no hosted one —
so `--esplora-url` is required and the tool says so if you forget it.

For each vector the tool resolves the DID **for real** through a recording
transport and then refuses to write unless every one of these holds:

- the resolved document, `versionId` and `deactivated` flag match the vector's
  own `resolve/output.json`;
- every update in the vector's sidecar is announced by an `OP_RETURN` push of
  its hash in the **last** output of a captured transaction;
- every matching announcement is confirmed, not sitting in the mempool;
- the captured tip reproduces the vector's stated `confirmations`.

Only then does it write `fixtures/chain/regtest/<k1|x1>/<short-id>.json`.

### 6. Read the summary

The session table goes to stderr, one row per vector: addresses captured, how
many of them came back empty (a captured state, not a failure), signals proved,
the confirmations check, and the fixture path. Below it: which vectors are
drivable now, each failure with its full cause chain, the frozen tip, and the
do-not-mine reminder.

A row reading `FAILED, nothing written` means exactly that — nothing was written
for that vector, and the other rows are unaffected.

### 7. Check what landed

```sh
git status --short fixtures/chain/
```

Exactly four new files. If any row failed, fix it and re-run the whole capture:
it is idempotent, and re-capturing a vector that already succeeded rewrites an
equivalent file.

### 8. Leave the stack running

Part 3 mints on this same chain. Teardown is Part 4, not now.

---

> ### ⚠ Do not mine during Part 1
>
> The upstream `test-suite/regtest/README.md` tells you to mine six blocks if
> electrs will not serve. **Do not do that here.** The four regtest vectors state
> `confirmations` 93 / 78 / 65 / 53 against one frozen tip; mining moves the tip
> and breaks every one of them simultaneously, and the vectors cannot be
> re-minted — nobody holds the keys that produced them.
>
> If electrs will not serve: tear the stack down, delete the unpacked directory,
> and unpack the zip again. Never advance the chain before Part 1's four
> fixtures exist. `chain-capture mint` refuses to produce a block until all four
> are written.

---

## Troubleshooting (Part 1)

**`curl: (56) Recv failure: Connection reset by peer` from port 3000.**
Two different faults produce this identical symptom. Read electrs's log before
deciding which one you have:

```sh
docker logs --tail 5 esplora-electrs
```

*If the log shows `waiting for bitcoind sync to finish: 758/758 blocks,
verification progress: 100.000%`* — repeating every five seconds, claiming
completion while refusing to serve — step 2 was skipped or did not take. This is
the stale-tip `initialblockdownload` latch, it is permanent, and no amount of
waiting or re-unpacking clears it. Apply step 2, re-run `up -d`, then
`docker restart esplora-electrs`. Confirm the flag is really in effect:

```sh
curl -s --user polaruser:polarpass -H 'content-type: application/json' \
  --data '{"jsonrpc":"1.0","id":"ibd","method":"getblockchaininfo","params":[]}' \
  http://127.0.0.1:18443/ | grep -o '"initialblockdownload":[a-z]*'
```

It must read `false`. While it reads `true`, electrs will never serve.

*If the log shows index or compaction activity* — that is the genuine cold
start. Wait and retry the smoke test; it can take a minute or two.

**Do not mine to fix either one.** That is the upstream README's advice, it does
clear the flag, and it destroys all four vendor expectations in the process.

**Port 3000 or 18443 is already in use.**
Stop the conflicting service and start the stack again. Do not remap the ports:
the fixture records the endpoint it was captured from, and every command in this
document names the documented URL. A remapped session would file fixtures
claiming an endpoint nobody else can reach.

**`up -d` fails on volume permissions, or bitcoind exits immediately.**
The compose file passes `USERID`/`GROUPID` through, so export them exactly as in
step 3 rather than running `docker compose` bare. If the unpacked tree is owned
by another uid:

```sh
sudo chown -R "$(id -u):$(id -g)" /tmp/btcr2-polar
```

then retry step 3.

**A row fails with a confirmations mismatch.**
The message names the vector, the expected value, what the capture yields, the
tip and the announcement's block height. Report all four vectors' numbers and
the tip. If all four are off by the **same** constant, the frozen chain has been
advanced relative to when the vectors were generated — that is an upstream
mismatch to raise, not something to work around. Do **not** pin a fabricated tip
to make the arithmetic come out: the tip is read from the chain, and a
back-derived tip would make the assertion circular and unable to fail.

**A row fails with a missing signal.**
That vector's sidecar update is not announced anywhere on this chain. Re-unpack
the export into a clean directory and retry the whole of Part 1 before
concluding anything about the resolver — a partially-synced electrs index
produces exactly this symptom.

**A row fails with an unconfirmed announcement.**
Distinct fault, distinct remedy: wait for the block, then re-run the capture. Do
not mine it yourself.

---

## Part 2 — mutinynet vendor vectors (live chain)

Captures three vectors: `mutinynet/k1/q5p6w9su`, `mutinynet/k1/q5pgeu9z` and
`mutinynet/x1/q5ugrf3w`.

### 1. Capture

Nothing to stand up. `https://mutinynet.com/api` is the default endpoint for the
`mutinynet` network, so no `--esplora-url` is needed:

```sh
cargo run -q -p chain-capture -- capture --network mutinynet
```

### 2. What is checked here, and what is not

These three vectors state `confirmations: null`, so no confirmations check runs
for them — the chain is still mining and the vectors never claimed a fixed
number. Everything else is unchanged: the resolve must reproduce each vector's
expected document, `versionId` and `deactivated` flag, and every sidecar update
must be announced by a confirmed `OP_RETURN` in a captured transaction.

### 3. Why this cannot wait

mutinynet is a live test network **that gets reset**. When it is, these three
vectors' chain data is gone permanently: nobody holds the transactions, nobody
holds the keys, and no one can re-capture them. Capture them in the same sitting
as everything else.

Note the asymmetry with what Part 3 produces. Our own minted scenarios survive a
reset, because Part 3 exists and can be run again on a fresh chain. The vendor
vectors' chain data cannot.

```sh
git status --short fixtures/chain/
```

Seven new files now: four under `fixtures/chain/regtest/`, three under
`fixtures/chain/mutinynet/`.

---

## Part 3 — mint the two scenarios on the Polar chain (first rung)

Everything broadcast in this part goes to the **local, disposable regtest chain
from Part 1**, and blocks are produced on demand by the tool. Nothing is
published publicly, there is no faucet on the critical path, and if a run goes
wrong the whole chain can be thrown away and re-unpacked. That is what makes
this the first rung: the same commands run against a public chain later, and the
differences are spelled out at the end of this part.

**Precondition: Part 1's four fixtures must already exist.** `chain-capture`
refuses to produce a block otherwise, names the vector ids that are still
outstanding, and refuses **before** any request reaches the node.

Two DIDs are minted, from **two separate keys**. A real on-chain fork aborts
resolution, so one DID cannot carry both a clean multi-update history and the
anomaly; the tool refuses to mint the fork on a DID a clean session already
claims.

### Scenario A — `clean-rotating-beacons`

Three updates, announced from three different derived beacons (P2WPKH, then
P2TR, then P2PKH), each confirmed in its own block, ending with the DID
deactivated on chain. Its version 2 update also adds a **fourth** beacon that is
never funded and never announces, so a replayed resolve issues a second round of
requests naming an address the first round did not.

#### 1. Generate a throwaway key, outside both repositories

```sh
mkdir -p ~/.btcr2-mint && chmod 700 ~/.btcr2-mint
head -c 32 /dev/urandom | xxd -p -c 32 > ~/.btcr2-mint/clean.hex
chmod 600 ~/.btcr2-mint/clean.hex
```

This key controls one minted DID and is used for nothing else, ever. Keeping it
and the state files outside both working trees is the primary control; the
`*.hex` and `*-state.json` entries in both `.gitignore` files are defence in
depth, for the operator who puts them in the working directory anyway.

#### 2. Run the scenario

```sh
cargo run -q -p chain-capture -- \
  mint --scenario clean --network regtest \
  --esplora-url http://localhost:3000 \
  --bitcoind-url http://127.0.0.1:18443 --bitcoind-auth polaruser:polarpass \
  --key-file ~/.btcr2-mint/clean.hex \
  --state-file ~/.btcr2-mint/clean-state.json --fee 1000
```

The first invocation prints the DID it derived from the key, its three beacon
addresses in document order (P2PKH, P2WPKH, P2TR), the funding plan for the ones
that will announce, and the address of the fourth beacon its version 2 update
adds — which is never funded and never announces. Then it funds, signs,
broadcasts, mines and waits, step by step.

The `--bitcoind-*` flags are what let it produce a block: the export ships
`"autoMineMode": 0`, so nothing else on this chain will. They are flags rather
than defaults so the same command shape works on every chain — a defaulted node
URL would be a hardcoded chain hiding in an argument parser, and would let the
tool reach a node the operator never named. Add `--yes` to skip the per-broadcast
confirmation prompt.

#### 3. Funding is automatic here

On regtest the tool sends each announcing beacon its funding from the node's own
wallet and mines the transfer, so there is nothing to do by hand. If the wallet
reports no spendable balance it first mines 101 blocks to mature a coinbase —
which is allowed only because Part 1 is already done.

#### 4. Cadence

Each step waits for **its own** confirmation before the next update is built and
signed, and on this chain that confirmation is one block mined on demand. The
three announcements therefore land at three heights the tool **chose** rather
than raced for, and the two height gaps are what give the replay something to
sequence. Expect the whole scenario to take seconds, not minutes.

#### 5. Resuming

Re-running the same command with the same `--state-file` continues where it
stopped. It never mints a second DID: a step already confirmed is skipped, and a
step that was broadcast but not yet confirmed is **waited for** by its recorded
txid rather than re-announced. The state file holds the DID, the beacon
addresses, the txids and the signed updates — all public chain data — and **no
key material**.

If the state file is lost mid-session, the DID is orphaned: its history is on
chain, the updates that produced it are not recoverable from anywhere else, and
the only way forward is a fresh key and a fresh DID.

A resume whose `--scenario`, `--network` or derived DID disagrees with the state
file is refused, naming the field, so a session cannot silently continue against
another chain or another key.

### Scenario B — `late-publishing-fork`

Two conflicting version 2 announcements from one beacon, both signed against the
retained genesis document, confirmed in different blocks.

```sh
mkdir -p ~/.btcr2-mint && chmod 700 ~/.btcr2-mint
head -c 32 /dev/urandom | xxd -p -c 32 > ~/.btcr2-mint/poisoned.hex
chmod 600 ~/.btcr2-mint/poisoned.hex

cargo run -q -p chain-capture -- \
  mint --scenario poisoned --network regtest \
  --esplora-url http://localhost:3000 \
  --bitcoind-url http://127.0.0.1:18443 --bitcoind-auth polaruser:polarpass \
  --key-file ~/.btcr2-mint/poisoned.hex \
  --state-file ~/.btcr2-mint/poisoned-state.json --fee 1000
```

Use a **different key file** from scenario A. If both scenarios are handed the
same key they derive the same DID, and the tool refuses — publishing a
conflicting announcement on the clean DID would abort its resolution and destroy
that scenario's coverage permanently.

The two announcements must land in **different blocks**: the resolver orders
signals by `(targetVersionId, block height)`, and two version 2 announcements in
one block have no defined order. On this chain the tool guarantees the
separation by mining between them. If it ever reports `SameBlock` anyway, the
recovery is to **delete the state file, generate a fresh key and restart the
scenario from genesis** — not to re-run branch B, which is already confirmed by
the time the heights are compared and would only add a third version 2
announcement.

### Fixture emission

Each scenario finishes by resolving its own DID through a recording transport
and writing a self-contained fixture:

- `fixtures/chain/minted/clean-rotating-beacons.json`
- `fixtures/chain/minted/late-publishing-fork.json`

The clean resolve must report `versionId` 4 with `deactivated: true`; the
poisoned resolve must **fail** with `LATE_PUBLISHING`. A scenario that does not
reach its own expectation writes nothing, and neither does one whose captured
bodies fail to announce every update it minted.

Each fixture carries its own sidecar, its own expectation, the signal provenance
and the chain it was minted on. No height, tip or confirmations number is baked
into the expectation, because every rung regenerates all three.

Re-running a completed scenario with its state file re-emits the fixture without
broadcasting anything, so a deleted or corrupted fixture is recoverable as long
as the state file survives.

### The minted DIDs

Record them here after the session, so anyone who encounters them knows what
they are:

- `clean-rotating-beacons`:
  `did:btcr2:k1qgpgek8c4hlam42zfrec303pmz38u8l6vtg24039r3w6qaeej92stxshy4wrf`
  — minted on the disposable Polar regtest chain at blocks 760 / 762 / 764,
  resolves to version 4 and is deactivated.
- `late-publishing-fork`:
  `did:btcr2:k1qgps3vxl9qffsj5z6u8a7m9dg5mgygucxwcfavty763wmme6p2jzf0gat27sv`
  — minted on the same chain at blocks 766 / 768, two conflicting version 2
  announcements from one beacon.

The second one is a **deliberately malformed DID history, published for
testing**. Resolving it raises the spec's late-publishing error, which is the
entire point of it; it is not a defect and it is not to be repaired.

### Climbing to a public chain

Re-running Part 3 on a higher rung is the same command with a different
`--network` and **without** the `--bitcoind-*` flags, because those chains mine
themselves:

```sh
cargo run -q -p chain-capture -- \
  mint --scenario clean --network mutinynet \
  --key-file ~/.btcr2-mint/clean-mutinynet.hex \
  --state-file ~/.btcr2-mint/clean-mutinynet-state.json --fee 1000
```

What changes:

- **Funding.** The tool prints the addresses to fund and the faucet URL where it
  knows one, then polls instead of mining. Fund every listed beacon in one visit;
  the plan is printed before anything is broadcast for exactly that reason.
- **Cadence.** A confirmation takes a block interval instead of a moment.
- **Permanence.** The broadcast prompt says so: on any chain but regtest a
  broadcast cannot be recalled.
- **Endpoints.** `mutinynet` has a default Esplora endpoint; `testnet4` does not,
  so a `testnet4` run needs `--esplora-url <url>` as well.

What does not change: fresh keys, new DIDs, the fixtures regenerated wholesale,
and **no test edit**. The replay reads the DID, the heights and the block times
out of the fixture, so moving chains is an operator session rather than a code
change.

---

## Part 4 — tear down and check what landed

```sh
docker compose -f /tmp/btcr2-polar/docker-compose.yml down
rm -rf /tmp/btcr2-polar
```

### What lands in the tree

**Nine** fixture files under `fixtures/chain/` — four regtest, three mutinynet,
two minted — each pretty-printed, so a re-capture produces a reviewable
line-oriented diff rather than one enormous line.

Nothing else from a session is committed: not the unpacked Polar directory, not
the key files, not the state files.

```sh
find fixtures/chain -name '*.json' | wc -l   # 9
git status --short                           # only fixtures/chain/ paths
```

If the second command shows a `.hex` or a `-state.json` file, it came from
working inside the tree instead of `~/.btcr2-mint`; both `.gitignore` files
already cover those names, so it should be invisible — if it is not, move the
file out of the tree rather than adding another ignore rule.

### One-way door

Re-capturing the vendor **regtest** vectors after Part 3 will FAIL the
confirmations check, because Part 3 moved the tip. That is the guard working, not
a bug. The remedy is to unpack the zip again into a clean directory and redo
Part 1 from step 1 on a fresh copy of the frozen chain.
