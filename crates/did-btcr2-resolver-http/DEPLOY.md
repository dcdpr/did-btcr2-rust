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
  > absorbs a test suite's repeated requests for one DID — the W3C run in §9 costs one or two
  > resolutions per DID — but it does not help a stream of distinct DIDs; for that, a private
  > Esplora instance is the remaining option. Mainnet `blockstream.info` showed no such limit
  > (200 for 12 back-to-back address calls).
- **One small in-memory cache, otherwise no state:** successful resolution results are kept for
  60 s, keyed by DID and `versionId`/`versionTime`/`minConf` (never by `Accept`), at most 1024
  entries — expired entries are evicted first, then the oldest. Errors are never cached, so a
  transient Esplora fault is never pinned; `noCache=true` is answered `501 FEATURE_NOT_SUPPORTED`
  rather than honoured (an anonymous cache bypass would be a lever against the Esplora quota).
  No database, no writable filesystem beyond the journal. The cache is process memory only, so
  the process is still safe to restart at any time; the cost of a restart is one resolution per
  DID.
- **Liveness:** `GET /health` or `HEAD /health` → `200`, body `{"status":"ok"}` (`HEAD` returns the
  headers only), without touching Esplora. Point an uptime poller or `curl -I` at
  `https://<host>/health`; the proxy's own upstream health checks are unnecessary.
- **Logs:** one JSON object per request on stderr, fields in this order: `method`, `path` (the
  raw request-target, escaped), `did` (the decoded DID when the path parsed as one, else `null`),
  `accept`, `status`, `latency_ms`, `cache` (`hit`, `miss`, or `n/a` when the resolver was not
  reached), `network`. `/health` requests are logged in the same shape (`did` and `network`
  `null`, `cache` `n/a`); the error chain behind a 500 follows on its own line. Under systemd
  that is `journalctl -u did-btcr2-resolver-http`; the encoded-target pass-through check above
  reads the `path` field.

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
Description=did:btcr2 DID Resolution HTTP GET binding (loopback; TLS via Caddy)
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
<HOST> {
	reverse_proxy 127.0.0.1:8080
}
```
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

Nothing lands in the tree but this file. The droplet is left running as the development
endpoint; `doctl compute droplet delete btcr2-shakedown` (or the console) removes it, and the
sslip.io name needs no un-pointing.
