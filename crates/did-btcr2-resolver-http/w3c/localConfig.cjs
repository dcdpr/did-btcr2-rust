// Local implementation config for w3c/did-resolution-test-suite at 2649fdf7.
//
// Copy this file to w3c-resolution-suite/localConfig.cjs (the suite is a git
// submodule; the copy is never committed there) and run
// `npm test -- --reporter spec` from that directory (the flag overrides the
// suite's .mocharc.yaml interop reporter, which prints no summary). With the
// file present, vc-test-suite-implementations runs only the implementations
// listed here (testAllImplementations defaults to false).
//
// `notFound` is a bare DID string, not the README's array: at this pin
// tests/10-bindings.js:38 reads it as a scalar and line 231 builds
// `${endpoint}/${notFoundDid}`; the array form would request
// `/1.0/identifiers/[object Object]`. Upstream PR #18 switches the read to the
// array form — flip this entry when the pin moves.
//
// The other optional `supportedDids` entries (the 410 DID, DID URL
// dereferencing, service redirects) are omitted on purpose: their rows are
// not generated (10-bindings.js:37-43). Both fixtures are documented in
// FIXTURES.md.
module.exports = {
  "implementations": [{
    "name": "dcdpr",
    "implementation": "did-btcr2-resolver-http",
    "didResolvers": [{
      "id": "https://143-198-140-182.sslip.io",
      "endpoint": "https://143-198-140-182.sslip.io/1.0/identifiers",
      "tags": ["did-resolution"],
      "supportedDids": {
        "valid": [
          {"did": "did:btcr2:k1qqphzydl2apenfzenkm8lcs4cnxz4nryeetpvhqwlgs6k0ul8p95u8q5tzlsv", "resolutionOptions": {}}
        ],
        "notFound": "did:btcr2:x1qp98pkkg4mp3e4k2yj9a5z5uu4x8jxkr0cqcvkt0s58k7fe87uh3v63tlqq"
      }
    }]
  }]
};
