# did-btcr2-resolver-http DEPLOY — what the service needs, and one throwaway droplet

> See also: `CONFORMANCE.md` (the assertion ledger the deployed binary is measured against),
> `FIXTURES.md` (the two mainnet fixtures and their custody), `w3c/localConfig.cjs` (the suite
> config for §9), `src/main.rs` (`--help`), and the runner check at
> <https://github.com/danpape/btcr2-shakedown/blob/main/.github/workflows/shakedown.yml>.

This file is two things. §1 is the handoff note for whoever runs the service on real
infrastructure: what it needs, and nothing more. Everything after §1 is the copy-paste record of a
shakedown on a throwaway DigitalOcean droplet, written after the droplet was up so it records
what was actually done, and kept so the exercise is reproducible.

**The droplet described below is a best-effort development endpoint with no uptime commitment.**
It exists to prove the host boundary (TLS termination, percent-encoded DIDs through a proxy,
cold-start latency, reachability from GitHub-hosted runners); nothing about it is production.

## 1. What the service needs

Exactly this, and nothing more:

- **One static binary**, `did-btcr2-resolver-http`, built on a developer machine
  (`x86_64-unknown-linux-musl`; see §3) and copied to the host. No toolchain, no git, no
  container runtime, no deploy key on the host.
- **One systemd unit** (§5) running it as an unprivileged user with `Restart=on-failure`.
- **Loopback only:** `--bind 127.0.0.1:8080`. The binary speaks plain HTTP and is never exposed
  directly.
- **A TLS-terminating reverse proxy in front** that forwards the request URI byte-for-byte —
  the path must reach the binary without re-decoding. The binding percent-decodes the DID path
  segment exactly once. The test that matters is the binary's own log: after a request for
  `…/identifiers/did%3Abtcr2%3A…` the journal must show `did%3Abtcr2%3A` (still encoded); a proxy
  that decodes — with or without re-encoding afterwards — shows `did:btcr2:` there instead. The
  double-encoded `did%253A…` → 400 probe in §7 is a secondary check only: it catches a proxy that
  decodes and forwards raw, but not one that decodes and re-encodes. Caddy's default
  `reverse_proxy` passes the URI unchanged (§6).
  > **If you front it with nginx:** `proxy_pass` with a URI part (`proxy_pass http://127.0.0.1:8080/;`)
  > re-normalises the path and re-encodes it. Use `proxy_pass http://127.0.0.1:8080;` with no
  > trailing URI, or `$request_uri`, and re-run the §7 journal check before trusting it.
- **Outbound HTTPS** to the Esplora endpoint of every network the host serves — for this
  shakedown `https://mutinynet.com/api` (the built-in default for mutinynet); mainnet needs no
  flag: the built-in default is `https://blockstream.info/api` (`crates/did-btcr2-client/src/url.rs`),
  overridable with `--esplora-url mainnet=<url>`. TLS roots are
  compiled in (`webpki-roots`), so the host needs no CA bundle for that.
  > **The hosted mutinynet Esplora rate-limits.** `mutinynet.com/api` (nginx behind Cloudflare)
  > answers HTTP 429 after roughly eight uncached calls in about 1.5 s, with no `Retry-After`.
  > One valid resolution is four Esplora calls, so back-to-back resolutions surface as fast
  > `500 INTERNAL_ERROR` responses, not timeouts. The binary's own response cache (next bullet)
  > absorbs a *sequential* client's repeated requests for one DID — the W3C run in §9 costs one
  > or two resolutions per DID because mocha runs its rows one at a time. It does not coalesce
  > in-flight misses: N concurrent first requests for one DID (a parallel client, a proxy retry
  > storm) each reach Esplora, N × 4 calls, and the last result to arrive is the one kept. Nor
  > does it help a stream of distinct DIDs. For either, a private Esplora instance is the
  > remaining option. Mainnet `blockstream.info` showed no such limit (200 for 12 back-to-back
  > address calls).
- **One small in-memory cache, otherwise no state:** successful resolution results are kept for
  60 s, keyed by DID and `versionId`/`versionTime`/`minConf` (never by `Accept`), at most 1024
  entries — expired entries are evicted first, then the oldest. Errors are never cached, so a
  transient Esplora fault is never pinned. `noCache=false` — the DID Resolution default, caching
  allowed — is accepted and changes nothing; `noCache=true` is answered `501 FEATURE_NOT_SUPPORTED`
  rather than honoured (the binary does not implement the option; nothing more is meant by it);
  any other `noCache` value is a `400 INVALID_OPTIONS`. A `POST` (next bullet) is never served
  from the cache and never stored in it: a result computed from a caller's sidecar must not
  answer a later `GET` that supplied none.
  The cache is a latency and Esplora-quota optimisation for a *sequential* client, not a
  control: an empty-body `POST`, or a `GET` with a `minConf` value not yet seen, reaches
  Esplora every time, so a caller who wants to skip the cache already can. The rate-limit
  note above stands on that footing — the cache lowers the Esplora call count for the
  well-behaved case and bounds nothing.
  No database, no writable filesystem beyond the journal. The cache is process memory only, so
  the process is still safe to restart at any time; the cost of a restart is one resolution per
  DID.
- **`POST` with sidecar data:** `POST /1.0/identifiers/{did}` takes the resolution options as
  one JSON object in the body (DID Resolution §12.1) — `{"sidecar": {…}, "versionId": 2}`;
  `versionId` and `minConf` are accepted as a JSON number or as a string of decimal digits
  (`"2"`), `versionTime` as a string, `noCache` as a boolean; `Accept` stays in the header — so
  a caller can hand the resolver the off-chain update payload a Singleton beacon leaves off the
  chain. The `Content-Type` must be absent, `application/json` or any `*/*+json`, else a
  bodiless `415` decided on the headers before any body byte is read — a refused media type is
  `415` whatever its size. The body of a `POST` that passes is read to at most 1 MiB (fixed;
  past it a bodiless `413`); a body on a `GET` is not read. A query string on a `POST` is a
  `400 INVALID_OPTIONS`. Every other method on the resolver path answers `405` with
  `Allow: GET, POST`. The binary's limit bounds honest bodies only: the shell library drains a
  `Content-Length` remainder the client never sent with one allocation sized by the declaration
  and sets no socket read timeout, so the host bounds the declared length (a header matcher —
  Caddy's `request_body max_size` does not check it) and the body read time in Caddy (§6)
  before a request reaches the binary. See §10.
- **Liveness:** `GET /health` or `HEAD /health` → `200`, body `{"status":"ok"}` (`HEAD` returns the
  headers only), without touching Esplora. Point an uptime poller or `curl -I` at
  `https://<host>/health`; the proxy's own upstream health checks are unnecessary.
- **Logs:** one JSON object per request on stderr, fields in this order: `method`, `path` (the
  raw request-target), `did` (the decoded DID when the path parsed as one, else `null`),
  `accept`, `status`, `latency_ms`, `cache`, `network`, `body_bytes` (bytes of request body the
  shell read; `0` for a bodiless request, for every method but `POST`, and for a `POST` refused
  on its `Content-Type`), `sidecar_updates`
  (the length of the sidecar's `updates` array when a `POST` carried one and reached the
  resolver, else `null`). `/health` requests are logged in the
  same shape (`did` and `network` `null`, `cache` `n/a`); the error chain behind a 500 follows
  on its own line. Under systemd that is `journalctl -u did-btcr2-resolver-http`; the
  encoded-target pass-through check above reads the `path` field.
  - `method`, `path` and `accept` are client text and are escaped **twice**: first with Rust's
    `char::escape_default` (so a control character or a non-ASCII character cannot reach a
    terminal even through a consumer that unescapes the JSON), then by the JSON encoding. In
    the raw line a `"` in the request-target therefore reads `\\\"` and `é` reads `\\u{e9}`;
    after JSON-decoding the field, the value is still the Rust escape text (`\"`, `\u{e9}`,
    `\u{1b}`). A consumer comparing `path` against what the client sent must unescape it once
    more. For a well-formed request — percent-encoded ASCII — the two forms coincide and the
    field reads as sent.
  - `cache` is `hit`, `miss`, `bypass`, or `n/a`. `bypass` is every `POST` that reached the
    resolver: neither read from nor written to the cache. `n/a` has two readings: the request never reached the
    resolver (a rejected request, `/health`, a handler panic), or the resolver that served it
    has no cache. The shipped binary always wraps the resolver in its cache, so in this
    deployment `n/a` means the former; only a build that serves the bare resolver would give
    the latter, and it would then show `n/a` on every request.

## 2. Where commands run

`# laptop` blocks run from the `did-btcr2-rust` workspace root; `# droplet` blocks run over SSH
as root. Capture the values once:

```sh
# laptop
IP=<droplet IPv4>
HOST=$(printf '%s' "$IP" | tr . -).sslip.io      # or .nip.io if sslip.io is down
DID=<a never-anchored mutinynet k1 DID — mint one, see §7>
```

## 3. Build the binary (laptop)

Build from the workspace root, where `rust-toolchain.toml` pins the toolchain (1.94.0); the musl
target is added to that toolchain, not to the default one. The musl build linked cleanly on the
first attempt (`ring` and `secp256k1-sys` compiled with `musl-gcc`; `file` reports
`static-pie linked`, `ldd` reports `statically linked`), so the gnu fallback below was never
used and the droplet's glibc version does not matter.

```sh
# laptop, one-time
rustup target add --toolchain 1.94.0 x86_64-unknown-linux-musl
sudo apt install -y musl-tools
```
```sh
# laptop
cargo --version                                   # 1.94.0 — the pin applies from here
cargo build --release -p did-btcr2-resolver-http --target x86_64-unknown-linux-musl
file target/x86_64-unknown-linux-musl/release/did-btcr2-resolver-http   # "static-pie linked"
```
Fallback (only if the musl build fails inside `ring` or `secp256k1-sys`; "target may not be
installed" means the `rustup target add` above went to the wrong toolchain, not a musl failure):
```sh
# laptop
cargo build --release -p did-btcr2-resolver-http
ldd target/release/did-btcr2-resolver-http     # libc, libm, libgcc_s only — no libssl
```
If you ship the gnu binary, the host's glibc must be at least as new as the build machine's
(Ubuntu 24.04 ships 2.39), and every `target/x86_64-unknown-linux-musl/release/` path below
becomes `target/release/`.

## 4. Create the droplet

Provisioned with doctl (`doctl auth init` is the prerequisite; `doctl compute ssh-key list`
gives the key id):

```sh
# laptop
doctl compute droplet create btcr2-shakedown --region sfo3 --size s-1vcpu-1gb --image ubuntu-24-04-x64 --ssh-keys <key id> --tag-name btcr2-shakedown --wait
doctl compute droplet get btcr2-shakedown --format PublicIPv4 --no-header    # this is $IP
```
`s-1vcpu-1gb` is the smallest slug and is ample: the binary idles in a few MB and one
resolution is four outbound HTTP calls. sshd answered about a minute after `--wait` returned.
Then the base system:

```sh
# droplet
apt-get update && apt-get install -y ufw curl
ufw allow OpenSSH && ufw allow 80/tcp && ufw allow 443/tcp && ufw --force enable
useradd --system --home /nonexistent --shell /usr/sbin/nologin btcr2
```
> **`ufw allow OpenSSH` must come before `ufw --force enable`** or the session you are in is
> the last one you get (DigitalOcean's console is the recovery path).

DigitalOcean's first-boot `unattended-upgrades` holds the dpkg lock for about 20 s after sshd
comes up; if the first `apt-get install` exits 100, wait and re-run it.

Verification line: `ufw status verbose` shows 22, 80, 443 and `Default: deny (incoming)`.

## 5. Install the binary and the unit

```sh
# laptop
scp target/x86_64-unknown-linux-musl/release/did-btcr2-resolver-http root@$IP:/usr/local/bin/did-btcr2-resolver-http.new
ssh root@$IP 'install -m 0755 /usr/local/bin/did-btcr2-resolver-http.new /usr/local/bin/did-btcr2-resolver-http && rm /usr/local/bin/did-btcr2-resolver-http.new'
```
Verification line: `sha256sum` on the droplet copy equals `sha256sum` on the laptop copy, and
`/usr/local/bin/did-btcr2-resolver-http --version` prints the crate version.

`/etc/systemd/system/did-btcr2-resolver-http.service`:
```ini
[Unit]
Description=did:btcr2 DID Resolution HTTP GET/POST binding (loopback; TLS via Caddy)
After=network-online.target
Wants=network-online.target

[Service]
User=btcr2
Group=btcr2
ExecStart=/usr/local/bin/did-btcr2-resolver-http --bind 127.0.0.1:8080
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
```
```sh
# droplet
systemctl daemon-reload && systemctl enable --now did-btcr2-resolver-http
curl -s http://127.0.0.1:8080/health     # {"status":"ok"}
```
Verification line: `ss -ltn` lists `127.0.0.1:8080` and no `0.0.0.0:8080`; the journal shows
`listening on 127.0.0.1:8080`.

## 6. Caddy

Use Caddy's own apt repository (the Ubuntu 24.04 package is 2.6.2, from 2022):
```sh
# droplet
apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg /etc/apt/sources.list.d/caddy-stable.list
apt-get update && apt-get install -y caddy
caddy version     # v2.11.x (the shakedown got v2.11.4)
```
`/etc/caddy/Caddyfile`:
```caddyfile
{
	servers {
		timeouts {
			read_body 30s
		}
	}
}

<HOST> {
	@declared_oversize header_regexp Content-Length ^[0-9]{8,}$
	respond @declared_oversize 413
	request_body {
		max_size 1MiB
	}
	reverse_proxy 127.0.0.1:8080
}
```
The three bounds are the proxy's job, not the binary's. The binary reads at most 1 MiB of an
honest `POST` body and answers `413` past it, but the shell library it runs on drains a
`Content-Length` remainder the client never sent with one allocation sized by the declaration —
a request declaring terabytes and sending a few kilobytes makes the process allocate that much
and abort after the response is written, on any method — and it sets no read timeout on the
socket, so a client that dribbles a body holds a handler thread for as long as it likes.

Each line covers one of those, and none covers the others:

- `request_body max_size 1MiB` bounds the bytes Caddy actually reads: an honest body one byte
  past 1 MiB is `413` from Caddy. It does **not** look at the declared `Content-Length` — Caddy
  v2.11.4 wraps the body in Go's `http.MaxBytesReader` and nothing else
  (`modules/caddyhttp/requestbody/requestbody.go`), so a request that declares terabytes and
  sends 2 KiB passes straight through it to the binary, which then aborts. The first
  installation of this file carried only `max_size` and was proven that way: the lying-length
  `POST` got no response, and the journal showed `memory allocation of 99999999997952 bytes
  failed` followed by the unit's restart.
- `@declared_oversize` / `respond … 413` is the guard on the declared length: a `Content-Length`
  of eight or more digits (10 000 000 and up) is answered `413` by the matcher before the
  request reaches `reverse_proxy`, so the binary never sees it. §10's last row shows this `413`.
  The gap between the two lines — a lying length from 1 MiB + 1 up to 9 999 999 — still reaches
  the binary; its drop-drain then allocates under 10 MB — a wasted allocation and a worker
  held until `read_body` closes the upstream side, not an abort. A request with no
  `Content-Length` (chunked) is not matched and is bounded by `max_size` alone.
- `read_body 30s` ends a slow body.

A deployment without Caddy in front, or with a proxy that forwards the declared length, is
exposed to all three.
```sh
# droplet
caddy validate --config /etc/caddy/Caddyfile
systemctl reload caddy
journalctl -u caddy | grep 'certificate obtained successfully'    # wait for this before testing
```
Both 80 and 443 must be open: Caddy picks HTTP-01 or TLS-ALPN-01 at random. If Let's Encrypt
rate-limits `sslip.io` (it is not on the Public Suffix List, so every user shares one bucket),
switch the hostname to `nip.io`. With no `email` global option in the Caddyfile, Let's Encrypt
is the only issuer Caddy configures — there is no ZeroSSL fallback. `sslip.io` and `nip.io`
are volunteer DNS services — fine for a throwaway, wrong for the real host. The shakedown got
its Let's Encrypt certificate three seconds after the reload.

> **Expect scanners within a minute of issuance.** Certificate Transparency logs publish the
> new name, and the shakedown journal showed about forty probes (`/.env`, `/.git/config`,
> `/graphql`, `/actuator/env`, …) from unrelated hosts shortly after the certificate arrived.
> The binary answers all of them 404 and holds no state or secrets, so this is noise, but each
> probe is one journal line.

## 7. Verify from the laptop

Mint a fresh DID and discard its secret (a fresh key means beacon addresses nobody has ever
paid, so the DID is never anchored and resolves to its genesis document; keep only the first
line — the secret is the last):
```sh
# laptop
DID=$(cargo run -q -p did-btcr2-cli -- create --generate --network mutinynet 2>/dev/null | head -1)
```
The eight requests and what each proves:
```sh
# laptop
H='Accept: application/did-resolution'
ENC=$(printf %s "$DID" | sed 's/:/%3A/g'); DBL=$(printf %s "$DID" | sed 's/:/%253A/g')
curl -sS -i -H "$H" "https://$HOST/1.0/identifiers/$DID"            # 200
curl -sS -i -H "$H" "https://$HOST/1.0/identifiers/$ENC"            # 200, same didDocument
curl -sS -i -H "$H" "https://$HOST/1.0/identifiers/$DBL"            # 400 INVALID_DID (secondary probe)
curl -sS -i -H "$H" "https://$HOST/1.0/identifiers/not-a-did"       # 400 INVALID_DID
curl -sS -i -H "$H" "https://$HOST/1.0/identifiers/did:example:abc" # 501 METHOD_NOT_SUPPORTED
curl -sS -i -H 'Accept: text/plain' "https://$HOST/1.0/identifiers/$DID"  # 406 — Accept survived the proxy
curl -sS -i          "https://$HOST/health"                          # 200 {"status":"ok"}
curl -sS -i -X POST  "https://$HOST/health"                          # 405, Allow: GET, HEAD
```
With the cache, the second request is served from memory (`"cache":"hit"` in the journal);
against a network whose Esplora rate-limits, only the first of the two touches it. Then on the droplet,
`journalctl -u did-btcr2-resolver-http | grep identifiers` is the
pass-through evidence: the second request's `path` field must read `…did%3Abtcr2%3A…` (encoded, as
sent) with `"status":200`, and the third `…did%253Abtcr2%253A…` with `"status":400`. The journal line is primary; the 400 alone
does not tell a decode-and-re-encode proxy from a pass-through one.

Latency, for the record (`curl -w '%{time_total}'` on the valid request; cold = first request
after `systemctl restart did-btcr2-resolver-http`, warm = median of five spaced 3 s apart —
immediate repeats hit the Esplora rate limit): 0.42 s cold, 0.35 s warm against the conformance
suite's 15 s per-test timeout. One valid request is four sequential Esplora calls, each with a
30 s client timeout; the numbers above are almost entirely those round-trips.

## 8. Runner check

The workflow at <https://github.com/danpape/btcr2-shakedown/blob/main/.github/workflows/shakedown.yml>
runs the same rows from a GitHub-hosted runner (with a 3 s pause between the two valid
resolutions, for the Esplora rate limit in §1):
```sh
# laptop
gh workflow run shakedown --repo danpape/btcr2-shakedown -f host="$HOST" -f did="$DID"
gh run watch --repo danpape/btcr2-shakedown && gh run view --repo danpape/btcr2-shakedown --log
```

## 9. Validate a deployment with the W3C suite

The real `w3c/did-resolution-test-suite` (vendored at `w3c-resolution-suite/`, pin `2649fdf7`) runs
against a host from a `localConfig.cjs` at the suite root. The committed config points at the
shakedown host and names the two mainnet fixtures in `FIXTURES.md`; with it present only that
implementation runs. The suite is a submodule — the copy below is never committed inside it.

```sh
# laptop, from the did-btcr2-rust workspace root
npm --prefix w3c-resolution-suite ci
cp crates/did-btcr2-resolver-http/w3c/localConfig.cjs w3c-resolution-suite/localConfig.cjs
npm --prefix w3c-resolution-suite test -- --reporter spec
```
`-- --reporter spec` is not optional: the suite's `.mocharc.yaml` selects `mocha-w3c-interop-reporter`,
which writes an HTML report and never prints a `N passing` summary; the flag overrides it. The exit
code is the gate (non-zero on any failing row); the spec transcript is the evidence to keep. If you
`tee` the transcript to a file, read mocha's exit code from `${PIPESTATUS[0]}` (bash) or
`${pipestatus[1]}` (zsh), not `$?`.
Expected: `30 passing`, no `failing`, no `pending` — 17 rows from `tests/4-did-resolution.js` and 13
from `tests/10-bindings.js`. The `deactivated`, `derefUrls` and `serviceDerefUrls` rows are not
generated because the config leaves them empty (a deactivation needs an on-chain update; DID URL
dereferencing is not implemented). Any red is a defect to fix before the host is registered anywhere.
The journal during a run shows a `"cache":"miss"` for the first request of the valid DID (another if
the run straddles the 60 s TTL) followed by `"cache":"hit"` lines; the `notFound` DID is a `miss`
every time (errors are never cached).

The same run from a GitHub-hosted runner:
<https://github.com/danpape/btcr2-shakedown/blob/main/.github/workflows/mocha.yml> checks the suite
out at the pin, drops in the same config, and runs `npm test -- --reporter spec`; the job's conclusion
is the gate. Mocha prints no colour on the runner, but `gh run view --log` prefixes every line with
`<job>\t<step>\t<timestamp> ` — strip that before comparing titles with a laptop transcript:
```sh
# laptop
gh workflow run mocha --repo danpape/btcr2-shakedown
gh run watch --repo danpape/btcr2-shakedown && gh run view --repo danpape/btcr2-shakedown --log
```

## 10. POST with sidecar: show an updated and a deactivated DID

The GET binding resolves with no sidecar, so a DID whose Singleton beacon has announced an
update answers `500 MISSING_UPDATE_DATA`: the on-chain signal is a 32-byte commitment and the
update itself is off-chain. `POST` carries that update in the body (§1). Two mutinynet DIDs are
kept for this (records in `FIXTURES.md` §7): one updated to version 2 by the
`did-btcr2-cli/RUNBOOK.md` flow, whose sidecar is committed at `demo/updated-v2.sidecar.json`
beside this file, and one minted by `chain-capture mint --scenario clean`, three updates ending in
deactivation, whose sidecar is inside `fixtures/chain/minted/clean-rotating-beacons.json` (not
committed twice — the `jq` line extracts it).

```sh
# laptop, from the did-btcr2-rust workspace root
H='Accept: application/did-resolution'; J='Content-Type: application/json'
UPDATED_DID=<FIXTURES.md §7.1>; DEACTIVATED_DID=<FIXTURES.md §7.2>
jq -c '{sidecar: .}' crates/did-btcr2-resolver-http/demo/updated-v2.sidecar.json > /tmp/updated.body
jq -c '{sidecar: ., versionId: 1}' crates/did-btcr2-resolver-http/demo/updated-v2.sidecar.json > /tmp/updated-v1.body
jq -c '{sidecar: .sidecar}' fixtures/chain/minted/clean-rotating-beacons.json > /tmp/deactivated.body
head -c 2048 /dev/zero > /tmp/2k.bin
curl -sS -i -H "$H" "https://$HOST/1.0/identifiers/$UPDATED_DID"                                                        # 500 MISSING_UPDATE_DATA — GET cannot show it
sleep 3
curl -sS -i -H "$H" -H "$J" --data-binary @/tmp/updated.body "https://$HOST/1.0/identifiers/$UPDATED_DID"               # 200, versionId "2", assertionMethod has two entries
sleep 3
curl -sS -i -H "$H" -H "$J" --data-binary @/tmp/updated-v1.body "https://$HOST/1.0/identifiers/$UPDATED_DID"            # 200, versionId "1" — the genesis document
sleep 3
curl -sS -i -H "$H" -H "$J" --data-binary @/tmp/deactivated.body "https://$HOST/1.0/identifiers/$DEACTIVATED_DID"       # 410, deactivated true, versionId "4"
curl -sS -i -H "$H" -H "$J" --data-binary @/tmp/updated.body "https://$HOST/1.0/identifiers/$UPDATED_DID?versionId=1"   # 400 INVALID_OPTIONS — options go in the body
curl -sS -i -H "$H" -H 'Content-Type: text/plain' --data 'x' "https://$HOST/1.0/identifiers/$UPDATED_DID"               # 415, no body
curl -sS -o /dev/null -w '%{http_code}\n' --max-time 20 --http1.1 -X POST -H "$J" -H 'Content-Length: 100000000000000' --data-binary @/tmp/2k.bin "https://$HOST/1.0/identifiers/$UPDATED_DID"   # 413 from Caddy's declared-length guard (§6); the binary never sees the request
```

`-H "$J"` is on every JSON row because curl's default `Content-Type` for `--data` is
`application/x-www-form-urlencoded`, which the binary answers `415`; `--data-binary` sends `jq`'s
output byte for byte. The last row goes to the host only — never send a declared-but-unsent
`Content-Length` to a bare binary (§6: the shell library aborts on it).

The `sleep 3` between the resolving rows: every `POST` is uncached, and a mutinynet resolution
that applies updates costs more Esplora calls than the four of §7's genesis-only request; the
hosted endpoint rate-limits (§1).

Journal evidence (`journalctl -u did-btcr2-resolver-http | grep identifiers` on the droplet):
each `POST` line carries `"cache":"bypass"`, a non-zero `"body_bytes"` and
`"sidecar_updates":1` (the updated DID) or `3` (the deactivated one); the `GET` line carries
`"cache":"miss"` and `"status":500`; the `415` and `400` lines carry `"cache":"n/a"` and
`"sidecar_updates":null`; the last row leaves no journal line at all — Caddy answered it. One
line in the ten-field order, the DID and the two measured values elided:
```
{"method":"POST","path":"/1.0/identifiers/did:btcr2:k1…","did":"did:btcr2:k1…","accept":"application/did-resolution","status":200,"latency_ms":…,"cache":"bypass","network":"mutinynet","body_bytes":…,"sidecar_updates":1}
```

**Why a query string is refused (the `400` row):** the specification's own second `POST`
example carries a query string (`…/did:example:1234?service=files&relativeRef=/resume.pdf`),
but that request is a DID URL *dereference* — `service` and `relativeRef` are the DID URL's
parameters, not resolution options — and this host does not dereference (a `GET` with that
query is already `400 INVALID_OPTIONS`, unknown option). A `POST` answers exactly as the `GET`
does; the resolution options of a `POST` live in the body only.

**What a sidecar that does not verify answers:** a `genesisDocument` whose hash does not match
an `x1` DID → `400 INVALID_DID`; an update that is missing for a signal, or present but failing
proof or hash verification → `500` with the did:btcr2 error type kept verbatim
(`…MISSING_UPDATE_DATA` / `…INVALID_DID_UPDATE` under `https://btcr2.dev/`). That `500` is the
DID Resolution §12.1 catch-all for error types the specification does not map and is the
conformant answer today; the mapping of did:btcr2 method errors onto DID Resolution statuses is
open upstream (`w3c/did-resolution` PR #358) and is not this binary's to invent.

**After a mutinynet reset:** mutinynet is periodically reset. The update's signal is then gone
from the chain, the resolver never consults the sidecar's updates, and the `POST` answers `200`
with `versionId "1"` — the genesis document — for the updated DID, and `200` (not `410`) for the
deactivated one. That is not an error and there is nothing to fix on the host: re-mint the two
DIDs (`FIXTURES.md` §7 records the commands) and update the records.

## Redeploy

```sh
# laptop
cargo build --release -p did-btcr2-resolver-http --target x86_64-unknown-linux-musl
sha256sum target/x86_64-unknown-linux-musl/release/did-btcr2-resolver-http     # record it; compare on the droplet after install
scp target/x86_64-unknown-linux-musl/release/did-btcr2-resolver-http root@$IP:/usr/local/bin/did-btcr2-resolver-http.new
ssh root@$IP 'install -m 0755 /usr/local/bin/did-btcr2-resolver-http.new /usr/local/bin/did-btcr2-resolver-http && rm /usr/local/bin/did-btcr2-resolver-http.new && systemctl restart did-btcr2-resolver-http'
curl -sS "https://$HOST/health"
```
(Copy to `.new` then `install`: writing over a running executable fails with `Text file busy`.)

## Cleanup

The droplet is left running as the development endpoint; `doctl compute droplet delete
btcr2-shakedown` (or the console) removes it, and the sslip.io name needs no un-pointing.

**Two tracked files name the host** — `w3c/localConfig.cjs` (`id` and `endpoint`) and
`FIXTURES.md` (the two `curl` lines). This is deliberate: the config is what the §9 run copies
into the suite, and `tests/fixtures.rs` compiles it in to guard the fixture identifiers, so the
address is in that test binary too. When the droplet is destroyed, DigitalOcean reassigns its IP
and the sslip.io name resolves to whoever gets it next; nothing local fails. **Destroying the
droplet therefore includes editing both files** in the same change: point them at the
replacement host, or remove the URLs if there is none (`tests/fixtures.rs` only asserts the
endpoint's shape, so it needs no edit for a host move). The scratch repo `danpape/btcr2-shakedown`
holds its own copy of `localConfig.cjs` for the `mocha.yml` job and needs the same update.
`DEPLOY.md` §10 and `FIXTURES.md` §7 use `$HOST`; only the two files already listed name it.
