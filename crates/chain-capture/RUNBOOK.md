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

> **Run this on a machine you control, alone.** The Polar export publishes
> bitcoind's JSON-RPC on `18443` and the Esplora API on `3000` with **no host-IP
> prefix** (`'18443:18443'`, `'3000:3000'` in its `docker-compose.yml`), so
> Docker binds them on **all interfaces**, not loopback — the `127.0.0.1` in the
> commands below is where *you* reach them, not the limit of who can. The RPC
> credential is `polaruser:polarpass`, published in the export itself. For the
> duration of a session, anyone who can reach this host can spend the node's
> wallet and mine on the chain. That is acceptable on a single-user machine with
> a throwaway regtest chain and worthless coins; it is not acceptable on a shared
> host, a LAN you do not own, or anything reachable from the internet. If you
> must run it on such a host, prefix both published ports with `127.0.0.1:` in
> the unpacked compose file before `docker compose up`.

---

## Session order

1. **Part 1** — stand the Polar chain up and capture the **four** vendor regtest
   vectors. Leave the stack **running**.
2. **Part 2** — capture the **three** vendor mutinynet vectors. Independent of
   Polar, but do it in the same sitting.
3. **Part 3** — mint the scenarios. As written it is the first rung, on the
   same running Polar chain, and today only `poisoned` (Scenario B) is minted
   there: `clean` has climbed to mutinynet, and the committed
   `fixtures/chain/minted/clean-rotating-beacons.json` is that mutinynet
   capture. Scenario A's regtest command is kept as the recipe for a fresh
   first rung; run as written it writes over the mutinynet capture at the same
   path. To re-mint `clean` after a mutinynet reset, use the command under
   "Climbing to a public chain".
4. **Part 4** — tear the stack down, delete the unpacked chain, check what
   landed.

**Part 5** — capturing a set that carries `signals.json`, from any checkout of
the test suite into any output directory — is independent of the four parts
above and of Polar. It includes the live smoke recipe, which writes only to a
scratch directory.

The four vendor regtest captures were taken against the export's untouched tip
(758), and every committed capture replays from its own file — nothing in the
test suite reads a live chain. Part 1 comes before Part 3 when both are done in
one sitting only because re-capturing those four vectors after mining needs a
fresh unpack of the export: their stated `confirmations` (93, 78, 65, 53) are
measured against 758 and stop reproducing once the tip has moved. Those four
vectors are being regenerated upstream; when that regeneration is absorbed,
their captures are replaced, and Part 1 is re-run against whatever chain they
were minted on.

---

## Pacing and rate limits

Every `capture` session against a hosted indexer (mutinynet, signet,
testnet4) paces itself. Request starts are at least **500 ms** apart
across the whole session: the resolve, the tip check and the block fetches
share one clock, so a session never bursts. A regtest session is unpaced; the
indexer is your own container.

An HTTP 429 (rate limited) answer is retried, up to **5 attempts** in all, after
waiting 1, 2, 4 and 8 seconds. `Retry-After` is not read. The retry sits below
the recorder, so a 429 body never lands in a fixture. Any other non-2xx answer
and any network error are not retried; they fail the row as before.

A session that is still rate limited after the last attempt fails the row with
`HTTP 429 from <url> after 5 attempts` in its cause chain and writes nothing for
it. Wait a few minutes and re-run the same command; the capture is idempotent.

---

## Part 1 — regtest vendor vectors

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
the chain is fully synced*. This chain's tip carries a fixed date in the past
that recedes further every day, so on any machine it is permanently in
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
tip a current timestamp, but it moves the tip; use `-maxtipage` so the vendor
captures stay reproducible from the untouched export.

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
  compose file and in the electrs `--cookie` argument. Both ports are published
  on all interfaces, not just loopback; see the caution at the top of this
  document.

An untouched export reports 758 on both. A higher number means this copy has
been mined on (a previous Part 3, for instance); that is harmless for minting,
but the four vendor `confirmations` expectations will not reproduce from it —
unpack fresh before capturing them.

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

Only then does it write `fixtures/chain/regtest/<k1|x1>/<short-id>.json`. The
fixture also carries the `/block/{hash}` header of every block an announcement
confirmed in, fetched after the resolve, so a replay under a `versionTime`
bound can read the block's `mediantime`. Every committed capture predates this
and holds no blocks; re-capturing fills them in (see `TESTING.md`,
"`versionTime` probes need the announcements' blocks").

### 6. Read the summary

The session table goes to stderr, one row per vector: addresses captured, how
many of them came back empty (a captured state, not a failure), signals proved,
the confirmations check, and the fixture path. Below it: which vectors are
drivable now, each failure with its full cause chain, and the tip the
`confirmations` were measured against.

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

Prefer `-maxtipage` over mining to fix either one. The upstream README's advice
to mine six blocks does clear the flag, but mining moves the tip and the vendor
`confirmations` expectations stop reproducing from this copy of the export.

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
the tip. If all four are off by the **same** constant, this copy of the export
has been mined on — unpack fresh and retry. If a fresh unpack still disagrees,
that is an upstream mismatch to raise, not something to work around. Do **not** pin a fabricated tip
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

Two DIDs are minted, from **two separate keys**. A real on-chain fork aborts
resolution, so one DID cannot carry both a clean multi-update history and the
anomaly; the tool refuses to mint the fork on a DID a clean session already
claims.

### Scenario A — `clean-rotating-beacons`

Three updates, announced from three different beacons — the genesis P2WPKH,
then the P2WPKH beacon that the version 2 update **added**, then the genesis
P2PKH — each confirmed in its own block, ending with the DID deactivated on
chain. Announcing version 3 from a beacon that version 2 introduced, between
two announcements from genesis beacons, is the history a resolver only
sequences correctly if it scans the added beacon before it judges the next
tuple: a replayed resolve issues a second round of requests naming that
address, and the round carries a real announcement.

> **The committed `clean` capture is the mutinynet mint, not a regtest one**
> (see "The minted DIDs" and "Climbing to a public chain" at the end of this
> part). The steps below are the first-rung recipe, kept for a fresh regtest
> mint. The command in step 2 writes
> `fixtures/chain/minted/clean-rotating-beacons.json`; run as written it
> replaces the mutinynet capture at that path with a regtest one, and the
> fixture guard in `crates/did-btcr2-resolver-http/tests/fixtures.rs` fails
> until `crates/did-btcr2-resolver-http/FIXTURES.md` §7.2 and "The minted
> DIDs" below describe the new file. To re-mint `clean` after a mutinynet
> reset, use the mutinynet command under "Climbing to a public chain" instead;
> a new capture there needs the same two records.

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

Put the node's RPC credential in a file beside it, rather than on the command
line:

```sh
printf 'polaruser:polarpass' > ~/.btcr2-mint/bitcoind.auth
chmod 600 ~/.btcr2-mint/bitcoind.auth
```

`--bitcoind-auth <user:pass>` still works and is fine for a regtest stack whose
credential is a published fixture, but the value sits in `/proc/<pid>/cmdline`
for the life of the process — readable by any user on the machine — lands in
shell history, and shows up in `ps`. On every chain past this one, use
`--bitcoind-auth-file`. Naming both is refused rather than silently resolved.

#### 2. Run the scenario

```sh
cargo run -q -p chain-capture -- \
  mint --scenario clean --network regtest \
  --esplora-url http://localhost:3000 \
  --bitcoind-url http://127.0.0.1:18443 \
  --bitcoind-auth-file ~/.btcr2-mint/bitcoind.auth \
  --key-file ~/.btcr2-mint/clean.hex \
  --state-file ~/.btcr2-mint/clean-state.json --fee 1000
```

The first invocation prints the DID it derived from the key, its three genesis
beacon addresses in document order (P2PKH, P2WPKH, P2TR), and the funding plan
for the three that will announce — beacon 1, then beacon 3 (the P2WPKH address
the version 2 update adds, derived from the same key), then beacon 0. Then it
funds, signs, broadcasts, mines and waits, step by step; the version 3
announcement is signed with the added beacon's own derived key.

The `--bitcoind-*` flags are what let it produce a block: the export ships
`"autoMineMode": 0`, so nothing else on this chain will. They are flags rather
than defaults so the same command shape works on every chain — a defaulted node
URL would be a hardcoded chain hiding in an argument parser, and would let the
tool reach a node the operator never named. Add `--yes` to skip the per-broadcast
confirmation prompt.

#### 3. Funding is automatic here

On regtest the tool sends each announcing beacon its funding from the node's own
wallet and mines the transfer, so there is nothing to do by hand. If the wallet
reports no spendable balance it first mines 101 blocks to mature a coinbase.

#### 4. Cadence

Each step waits for **its own** confirmation before the next update is built and
signed, and on this chain that confirmation is one block mined on demand. The
three announcements therefore land at three heights the tool **chose** rather
than raced for, and the two height gaps are what give the replay something to
sequence. Expect the whole scenario to take seconds, not minutes.

#### 5. Settling

After the last step confirms, the tool brings the tip five blocks past it
(`SETTLEMENT_BLOCKS`), so the last announcement has six confirmations — the
resolver's default `minConf` — by the time the fixture is captured. On this
chain that is five blocks mined on demand; a re-run of a completed session
finds the tip already there and mines nothing. A fixture captured without this
step replays only with `minConf` lowered to one; both committed fixtures were
minted with it and replay under the default.

#### 6. Resuming

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
  --bitcoind-url http://127.0.0.1:18443 \
  --bitcoind-auth-file ~/.btcr2-mint/bitcoind.auth \
  --key-file ~/.btcr2-mint/poisoned.hex \
  --state-file ~/.btcr2-mint/poisoned-state.json --fee 1000
```

Use a **different key file** from scenario A. If both scenarios are handed the
same key they derive the same DID, and the tool refuses — publishing a
conflicting announcement on the clean DID would abort its resolution and destroy
that scenario's coverage permanently.

The session settles the chain five blocks past the second branch before it
proves the fork, exactly as scenario A does, and the proof runs under the
resolver's default `minConf`: what is proved is what the fixture's replay sees.

The two announcements must land in **different blocks**: the resolver orders
signals by `(targetVersionId, block height)`, and two version 2 announcements in
one block have no defined order. On this chain the tool guarantees the
separation by mining between them. If it ever reports `SameBlock` anyway, the
recovery is to **delete the state file, generate a fresh key and restart the
scenario from genesis** — not to re-run branch B, which is already confirmed by
the time the heights are compared and would only add a third version 2
announcement.

### Fixture emission

Each scenario finishes by resolving its own DID through a recording transport,
fetching the `/block/{hash}` header of every block its announcements confirmed
in (a replay under a `versionTime` bound compares against the block's
`mediantime`), and writing a self-contained fixture:

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
  `did:btcr2:k1q5pew2jcfvr5v9x6vhkz67gfuyfs4ggtqxuq5hlm8wg7ydy26205evgxxrhdk`
  — minted on mutinynet at blocks 3443744 / 3443745 / 3443746, captured at tip
  3443751, resolves to version 4 and is deactivated; the version 3 announcement
  (block 3443745) is on the P2WPKH beacon the version 2 update added. Replaced
  the regtest mint of
  `did:btcr2:k1qgp74wu5cs4lq3vzxsgez4hjl9g23kf88gzl4lu2wpttv4y225zzk5sz2xa24`
  (blocks 760 / 762 / 764, tip 769) on 2026-09-21. The transaction ids, the
  funding transactions and the key disposition are recorded in
  `crates/did-btcr2-resolver-http/FIXTURES.md` §7.2.
- `late-publishing-fork`:
  `did:btcr2:k1qgph42l3n43ktt53mp7tnaty6wkddyy34caxkmgzkrw7zt0ee7pmp8sxx05pd`
  — minted on the disposable Polar regtest chain at blocks 771 / 773, captured
  at tip 778, two conflicting version 2 announcements from one beacon.

Both were minted with the settling step, so each tip sits five blocks past the
last announcement and the replay tests run under the default `minConf`. The
fork is still the regtest mint: its heights follow from where the original
regtest clean session left that chain's tip (769), which is why they start at
771 although the clean fixture no longer carries those heights.

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
- **Cadence.** A confirmation takes a block interval instead of a moment, and
  settling five blocks past the last announcement is a wait of five intervals
  (the tool allows about an hour) rather than five blocks mined on demand.
- **Permanence.** The broadcast prompt says so: on any chain but regtest a
  broadcast cannot be recalled.
- **Endpoints.** `mutinynet`, `signet` and `testnet4` have default Esplora
  endpoints (`https://mutinynet.com/api`, `https://mempool.space/signet/api`,
  `https://mempool.space/testnet4/api`); `--esplora-url <url>` still overrides
  them. `regtest` has no default and always needs `--esplora-url`.
- **Pacing.** Requests to a hosted indexer are spaced and a rate-limited
  answer is retried; see "Pacing and rate limits".

What does not change: fresh keys, new DIDs, the fixtures regenerated wholesale,
and **no test edit**. The replay reads the DID, the heights and the block times
out of the fixture, so moving chains is an operator session rather than a code
change.

`clean` has climbed this rung: the command above ran on mutinynet on 2026-09-21
(the entry under "The minted DIDs"), asking 6 000 sats per announcing beacon
(`--fee` plus a 5 000 sat margin) and finishing in about five minutes. It is
the command to re-run after a mutinynet reset, under a fresh key and state
file; the new capture needs a new "The minted DIDs" entry and a new
`FIXTURES.md` §7.2 record, and the fixture guard fails until it has them.
`poisoned` is still the regtest mint.

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

### Re-capturing after Part 3

Re-capturing the vendor **regtest** vectors after Part 3 fails the confirmations
check, because Part 3 moved the tip the vectors' `confirmations` were measured
against. Unpack the zip again into a clean directory and redo Part 1 from step 1
on the untouched export.

---

## Part 5 — sets that carry signals.json

The regenerated test suite ships a `signals.json` in each set: a bare array of
the beacon signals the set was recorded against, every entry carrying the same
`recordedTip`. Such a set is captured from an explicit suite root:

```sh
cargo run -q -p chain-capture -- \
  capture --network <net> --suite-root <dir> --vector <net>/<k1|x1>/<id> [--out <dir>]
```

- `--suite-root <dir>` is a checkout of the test suite. The set is read from
  `<dir>/<net>/<k1|x1>/<id>/` and must carry `signals.json`; a set without one
  is refused, and is captured through the default `test-suite/` tree instead.
- `--vector` is required with `--suite-root`, and the id must have the form
  `<network>/<k1|x1>/<id>` with lowercase letters and digits in the last part.
  `--network` must name the directory the set is filed under.
- `--out <dir>` writes the fixture to `<dir>/<net>/<k1|x1>/<id>.json` instead of
  under `fixtures/chain/`. Without it, the fixture lands in the tree.
- The main `resolve/input.json` may omit `resolutionOptions.sidecar`; it is
  read as `{}`, as the conformance harness reads it for a set with
  `signals.json`.
- signet and testnet4 use their default endpoints, and every session is paced
  (see "Pacing and rate limits"). regtest needs `--esplora-url`.

### The pinned tip

The session first asks the endpoint for its tip. It then resolves the DID with
the chain tip pinned to the set's `recordedTip`, not the live tip, and writes
`tip_height = recordedTip` into the fixture. The replayed `confirmations` are
therefore the ones the set was recorded with, however far the chain has moved
since.

### What a capture checks

- **The outcome.** For a positive set, the resolved `didDocument`, `versionId`,
  `deactivated` flag and any stated `confirmations` must match the set's
  `resolve/output.json`. A negative set (its `resolve/output.json` carries
  `didResolutionMetadata.error`) is captured when the resolve fails with **any**
  specification error code. A resolve that succeeds, or that fails without a
  code, is refused. The capture does not compare the code: run the conformance
  harness on the new fixture afterwards, and it asserts the code.
- **The signals.** The announcements found at the captured beacon addresses
  must equal `signals.json` exactly: the same transactions, each with the
  recorded `blockHeight`, `blockHash` and `signalBytes`, no more and no fewer.
  This replaces the ordering checks that apply to a set without `signals.json`.

### Refusals, and what to do

Every refusal writes nothing for the set.

| Refusal | What to do |
|---|---|
| The live tip is below `recordedTip`. | The indexer is behind the chain the set was recorded on. Wait for it to catch up, or name another endpoint with `--esplora-url`. |
| An announcement (a transaction whose last output is `OP_RETURN` plus 32 bytes) is confirmed above `recordedTip`, or is unconfirmed. | The beacon has seen activity since the set was recorded, so the chain no longer matches the record. Report it upstream; there is nothing to retry. |
| An announcement differs from `signals.json`: an entry with no announcement on chain, an announcement with no entry, or a disagreeing height, block hash or signal bytes. | Check that `--network`, the endpoint and the suite checkout are the ones the set was recorded on, then re-run. If they are, report the set upstream. |
| `signals.json` repeats an `update` without `duplicate: true` on the later entry, or records one `txid` in two entries. | A malformed set. Report it upstream. |
| The set declares a CAS or SMT beacon, or an entry belongs to a cohort, including a cohort-only set with no `update/` directory. | Unsupported: the resolver cannot query those beacons yet, so there is nothing to capture. Skip the set. |
| The main `resolve/input.json` sets `versionId`, `versionTime` or `minConf` under `resolutionOptions`. | The capture resolves the main pair with only its sidecar and the recorded tip, while the conformance harness honours those options, so the two would check different resolves. The suite puts them in numbered `resolve/NN/` cases. Report the set upstream. |
| The resolve outcome does not match (see above). | Either the chain no longer carries what the set was recorded against, or the resolver disagrees with the set. Establish which before re-running. |

Any other transaction above `recordedTip`, such as someone paying the beacon
address, is **recorded and ignored**: anyone can pay a beacon address on a
public chain, and at the pinned tip the replay never counts it as a signal.

### Known limitation: negative sets with post-rotation signals

The capture records only the addresses the resolver requested. A resolve that
errors before a beacon rotation takes effect never requests the beacons that
rotation adds. A negative set whose `signals.json` names a signal on such a
beacon is therefore refused as a signal not on chain, even though the chain is
correct. No code handles this; such a set is out of scope for capture until a
set needs it. The regenerated late-publishing set is unaffected: both of its
signals sit on genesis beacons.

### Live smoke (scratch only)

One signet set and one testnet4 set, against the default mempool.space
endpoints, from a scratch checkout of the test suite into a scratch output
directory:

```sh
SCRATCH=$(mktemp -d)
git clone --filter=blob:none https://github.com/dcdpr/did-btcr2-test-suite "$SCRATCH/test-suite"
git -C "$SCRATCH/test-suite" checkout f234a6f3
cargo run -p chain-capture -- capture --network signet   --suite-root "$SCRATCH/test-suite" --vector signet/k1/qyp5h7kz   --out "$SCRATCH/out"
cargo run -p chain-capture -- capture --network testnet4 --suite-root "$SCRATCH/test-suite" --vector testnet4/k1/qspz5wep --out "$SCRATCH/out"
```

Nothing under `$SCRATCH` is committed; delete it when done. The smoke confirms
the endpoints and the pacing against the real indexers, not a fixture. A
resolution mismatch on signet may be the test suite's own open "Recreate Signet
Test Vectors" item rather than a fault in this tool; check that before
debugging.
