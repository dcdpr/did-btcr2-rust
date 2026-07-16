# 1. Beacon construct/sign split (construct-in-core, sign-at-caller)

- Status: accepted
- Date: 2026-07-15

## Context and Problem Statement

Announcing a singleton beacon signal used to be a single build-and-sign
operation, `Update::announce_singleton`, living in the sans-I/O method core. That
function built the unsigned announcement transaction *and* signed it, which forced
the caller to hand the raw beacon wallet key (`secp256k1::SecretKey`) into the core
crate. A non-zeroizing fund-moving secret then flowed through the method crate for
the whole duration of the build: the beacon key had no unambiguous owner and no
key-lifetime discipline inside the core.

This contradicts the crate's sans-I/O contract. The core is meant to emit
*artifacts* and let the caller supply *secrets and I/O*; a beacon secret that
enters the core to sign a transaction is precisely the kind of secret custody the
sans-I/O boundary is supposed to keep out. The question is where the construct /
sign / finalize / broadcast responsibilities should live so that the beacon key
never needs to be owned by the method crate.

## Decision Drivers

- Sans-I/O: the core emits artifacts; the caller (the wallet) supplies secrets and
  performs I/O.
- Remove the beacon-key-in-core custody path (the non-zeroization gap) by
  construction, not by adding zeroization to a key the core should never hold.
- Keep the fund-moving, finicky Bitcoin bits (taproot tweak, prevout-ownership
  cross-check, witness assembly, the OP_RETURN signal invariant) in the tested
  method crate, even when the signing operation itself moves to the wallet.

## Considered Options

- **A — Keep build-and-sign in the core.** Rejected: it structurally requires the
  beacon secret to enter the method crate, which is the exact problem.
- **B — Construct-in-core / sign-at-caller (CHOSEN).** The core builds the unsigned
  transaction plus the per-input sighashes and takes no beacon key; the wallet
  signs; the core assembles and re-validates the broadcastable transaction.
- **Emit a BIP174 PSBT instead of a bespoke handback — NOT YET.** A PSBT is the
  standard construct-vs-sign artifact, but against the pinned rust-bitcoin 0.30.2 it
  would make the crate *less* usable for the only signing path this stack supports.
  In 0.30.2, `Psbt::sign()` dispatches only to ECDSA (`bip32_sign_ecdsa`) and is
  BIP32/xprv-oriented — it issues only `KeyRequest::Bip32`, and a raw
  `PublicKey → PrivateKey` map answers `NotSupported`. There is no taproot key-path
  signing branch, and there is no finalizer (`final_script_sig` /
  `final_script_witness` are bare input fields; real finalization needs the
  `miniscript` crate). Our default beacon is a P2TR key-path output signed with a
  raw wallet key, so `Psbt::sign()` would not touch it. Emitting a PSBT today would
  also pre-commit a cross-implementation interop shape while that seam is still an
  open question. PSBT friendliness becomes real only after a rust-bitcoin bump
  (0.32+ taproot PSBT signing) and for consumers already in the PSBT /
  hardware-signer world. To keep that door open, the bespoke unsigned-tx handback
  carries each input's prevout `value` and `script_pubkey`, so a non-breaking
  `From<UnsignedBeaconTx> for Psbt` adapter stays a clean later addition after the
  rust-bitcoin bump.

## Decision Outcome

Chosen option: **B, construct-in-core / sign-at-caller.** The beacon announcement
is produced by a four-stage flow:

1. `build_unsigned` (core) — builds the unsigned announcement transaction and
   precomputes the per-input sighashes, taking **no** beacon key.
2. `sign_beacon_tx` (wallet) — a pure, transport-free signing function that owns the
   beacon secret and produces one signature per input.
3. `finalize` (core) — assembles the per-scheme witness / script_sig from the
   returned signatures and re-asserts the `SignedBeaconTx` OP_RETURN invariant.
4. `broadcast` (wallet) — POSTs the finalized transaction; unchanged.

The BIP341 key-path taproot tweak modifies the *secret* key (`d' = d + H(P)`), so it
must run where the beacon key lives — wallet-side, inside `sign_beacon_tx`. But the
two finicky, fund-moving pieces stay in the tested method crate as core-defined
**pure helpers** that the wallet calls: `beacon_taproot_tweak` (the no-merkle-root
key-path tweak) and `check_prevout_ownership` (the cross-check that derives the
expected script per scheme — P2PKH / P2WPKH key-hash, and the P2TR **tweaked**
output key — and compares it to the funding prevout's `script_pubkey`, returning
`KeyDoesNotOwnPrevout` when the key does not own the prevout). Keeping the tweaked-key
comparison in the crate that hand-checked it is what prevents the fund-moving bit
from drifting into a wallet reimplementation; a permanent BIP341 known-answer vector
pins it.

`announce_singleton` is **replaced outright** — there is no `#[deprecated]`
transition. Keeping a build-and-sign variant would retain the exact
beacon-key-in-core path (and its non-zeroization gap) this change exists to remove;
the crate is pre-1.0 with no near-term published release, so a clean replacement is
preferred over a compatibility shim.

## Consequences

- **Positive — the beacon secret is never held by the core.** The build API
  (`build_unsigned` / `finalize`) takes no key at all. The two pure helpers receive
  `&SecretKey` only as a call-time parameter, executed wallet-side, and drop it
  immediately; no key is retained in core state. Precisely: the beacon secret is
  never *stored*, *owned*, or *persisted* by the method crate. (It is *not* claimed
  that the secret never enters the crate — the helper parameters would make that
  false; the accurate statement is that the core never holds or owns the key.)
- **Positive — the fund-moving logic stays tested in-crate.** The taproot tweak, the
  tweaked-key ownership guard, the per-scheme witness assembly, and the OP_RETURN
  signal invariant all remain in the method crate, pinned by a permanent BIP341
  known-answer vector and a fail-closed ownership test.
- **Positive — the PSBT adapter stays a non-breaking later addition.** Because each
  handback input carries `value` + `script_pubkey`, a `From<UnsignedBeaconTx> for
  Psbt` can be added without an API break once a rust-bitcoin bump makes taproot PSBT
  signing real.
- **Follow-up — the cross-implementation interop seam is deferred.** Whether sibling
  implementations sign in-core or accept an unsigned-tx handback is still open; the
  bespoke handback is an internal Rust convention for now, not a committed
  cross-impl wire shape.
