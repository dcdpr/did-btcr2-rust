//! `did-btcr2-resolver-http` — serve the W3C DID Resolution GET binding for
//! `did:btcr2` over plain HTTP. One process serves every network: the Esplora
//! endpoint is derived from each DID's own network, with `--esplora-url`
//! overrides for networks that have no hosted default (regtest, testnet4,
//! custom). Successful results are cached in memory for 60 s per DID and
//! option set, and every request is logged as one JSON object on stderr; TLS
//! belongs to a fronting proxy. `/health` (GET or HEAD) is a liveness route
//! for the supervisor, the proxy and uptime pollers: it answers without
//! touching Esplora.

#![forbid(unsafe_code)]

use did_btcr2_resolver_http::{CACHE_CAPACITY, CACHE_TTL, CachingResolver, ClientResolver, serve};
use error_iter::ErrorIter as _;
use onlyargs::{CliError, OnlyArgs, traits::*};
use onlyerror::Error;
use std::collections::HashMap;
use std::ffi::OsString;
use std::num::NonZeroUsize;
use std::process::ExitCode;
use std::sync::Arc;

/// The keys `--esplora-url` accepts: the `did_btcr2_client::network_name`
/// outputs, which is also how the resolver looks an override up.
const NETWORK_NAMES: [&str; 7] = [
    "mainnet",
    "signet",
    "regtest",
    "testnet",
    "testnet4",
    "mutinynet",
    "custom",
];

/// The help text, as a value so a test can assert what it tells an operator.
const HELP_TEXT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    " v",
    env!("CARGO_PKG_VERSION"),
    "\n",
    "Serve the DID Resolution HTTP GET binding for did:btcr2.\n",
    "\n",
    "Usage:\n",
    "  did-btcr2-resolver-http [flags]\n",
    "\n",
    "Flags:\n",
    "  --bind <addr>                  Listen address (default 127.0.0.1:8080)\n",
    "  --esplora-url <network>=<url>  Esplora base URL for a network; repeatable.\n",
    "                                 Networks: mainnet, signet, regtest, testnet, testnet4, mutinynet, custom.\n",
    "                                 mainnet, signet, testnet and mutinynet have hosted defaults; regtest,\n",
    "                                 testnet4 and custom need an override or answer 501. Every custom\n",
    "                                 network shares the one `custom` override.\n",
    "  --threads <n>                  Request-handler threads (default 4; must be > 0)\n",
    "  -h, --help                     Show this help\n",
    "  -V, --version                  Show the version\n",
    "\n",
    "Endpoint: GET /1.0/identifiers/{did}[?versionId=|versionTime=|minConf=]\n",
    "Health:   GET|HEAD /health -> 200 {\"status\":\"ok\"} (liveness only; no Esplora probe)\n",
    "Cache:    successful results for 60 s, keyed by DID + versionId/versionTime/minConf (not Accept);\n",
    "          errors are never cached; noCache=true answers 501 FEATURE_NOT_SUPPORTED\n",
    "Log:      one JSON object per request on stderr: method, path, did, accept, status, latency_ms, cache, network\n",
);

/// The parsed command line.
#[derive(Debug)]
struct Args {
    /// `--bind <addr>`: the listen address.
    bind: String,
    /// `--threads <n>`: request-handler workers.
    threads: NonZeroUsize,
    /// `--esplora-url <network>=<url>` entries, keyed by network name.
    esplora_urls: HashMap<String, String>,
}

impl OnlyArgs for Args {
    const VERSION: &'static str = onlyargs::impl_version!();

    fn help() -> ! {
        println!("{HELP_TEXT}");
        std::process::exit(0);
    }

    fn parse(args: Vec<OsString>) -> Result<Self, CliError> {
        let mut args = args.into_iter();
        let mut bind: Option<String> = None;
        let mut threads: Option<NonZeroUsize> = None;
        let mut raw_urls: Vec<String> = Vec::new();
        while let Some(arg) = args.next() {
            match arg.to_str() {
                Some(p @ "--bind") => bind = Some(args.next().parse_str(p)?),
                // `NonZeroUsize` rejects `0` at the flag: zero workers would
                // accept connections and never answer them.
                Some(p @ "--threads") => {
                    threads = Some(args.next().parse_int::<NonZeroUsize, _>(p)?);
                }
                Some(p @ "--esplora-url") => raw_urls.push(args.next().parse_str(p)?),
                Some("--help") | Some("-h") => Self::help(),
                Some("--version") | Some("-V") => Self::version(),
                _ => return Err(CliError::Unknown(arg)),
            }
        }
        Ok(Self {
            bind: bind.unwrap_or_else(|| "127.0.0.1:8080".to_string()),
            threads: threads.unwrap_or(NonZeroUsize::new(4).expect("4 is non-zero")),
            esplora_urls: parse_overrides(raw_urls)?,
        })
    }
}

/// `<network>=<url>` entries -> a map keyed by network name. A malformed,
/// unknown-network, duplicated or URL-less entry is a typed error naming the
/// flag, so a typo cannot silently resolve against the wrong backend.
fn parse_overrides(entries: Vec<String>) -> Result<HashMap<String, String>, CliError> {
    let mut overrides = HashMap::new();
    for entry in entries {
        let Some((network, url)) = entry.split_once('=') else {
            return Err(CliError::MissingRequired(format!(
                "--esplora-url expects <network>=<url>, got `{entry}`"
            )));
        };
        if !NETWORK_NAMES.contains(&network) {
            return Err(CliError::MissingRequired(format!(
                "--esplora-url: unknown network `{network}`; expected one of {}",
                NETWORK_NAMES.join(", ")
            )));
        }
        if url.is_empty() {
            return Err(CliError::MissingRequired(format!(
                "--esplora-url: empty URL for `{network}`"
            )));
        }
        if overrides
            .insert(network.to_string(), url.to_string())
            .is_some()
        {
            return Err(CliError::MissingRequired(format!(
                "--esplora-url: network `{network}` given more than once"
            )));
        }
    }
    Ok(overrides)
}

/// Top-level error: argument parsing and the bind failure funnel to stderr
/// plus a nonzero exit; operator input never panics.
#[derive(Debug, Error)]
enum RunError {
    /// Argument parsing error.
    Cli(#[from] CliError),

    /// The listener could not be bound. `tiny_http` reports the cause as a
    /// boxed `dyn Error`, which `onlyerror` cannot chain as a source, so the
    /// cause is rendered into the message.
    #[error("bind {addr}: {reason}")]
    Bind {
        /// The address that was requested.
        addr: String,
        /// Why the bind failed.
        reason: String,
    },
}

fn run() -> Result<(), RunError> {
    let args: Args = onlyargs::parse()?;
    let server = tiny_http::Server::http(&args.bind).map_err(|e| RunError::Bind {
        addr: args.bind.clone(),
        reason: e.to_string(),
    })?;
    eprintln!("listening on {}", server.server_addr());
    let workers = serve(
        Arc::new(server),
        args.threads,
        CachingResolver::new(
            ClientResolver::new(args.esplora_urls),
            CACHE_TTL,
            CACHE_CAPACITY,
        ),
    );
    for worker in workers {
        if worker.join().is_err() {
            eprintln!("a worker panicked");
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error}");
            for source in error.sources().skip(1) {
                eprintln!("  Caused by: {source}");
            }
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args_from_strings(strings: &[&str]) -> Vec<OsString> {
        strings.iter().map(OsString::from).collect()
    }

    #[test]
    fn defaults_are_loopback_8080_and_four_threads() {
        let parsed = Args::parse(args_from_strings(&[])).expect("no flags is valid");
        assert_eq!(parsed.bind, "127.0.0.1:8080");
        assert_eq!(parsed.threads, NonZeroUsize::new(4).expect("4"));
        assert!(parsed.esplora_urls.is_empty());
    }

    #[test]
    fn flags_parse_into_bind_threads_and_overrides() {
        let parsed = Args::parse(args_from_strings(&[
            "--bind",
            "0.0.0.0:9000",
            "--threads",
            "8",
            "--esplora-url",
            "regtest=http://localhost:3000",
            "--esplora-url",
            "testnet4=http://h:1",
        ]))
        .expect("every flag is valid");
        assert_eq!(parsed.bind, "0.0.0.0:9000");
        assert_eq!(parsed.threads, NonZeroUsize::new(8).expect("8"));
        assert_eq!(parsed.esplora_urls.len(), 2);
        assert_eq!(
            parsed.esplora_urls.get("regtest").map(String::as_str),
            Some("http://localhost:3000")
        );
        assert_eq!(
            parsed.esplora_urls.get("testnet4").map(String::as_str),
            Some("http://h:1")
        );
    }

    #[test]
    fn threads_zero_is_rejected_at_the_flag() {
        let error = Args::parse(args_from_strings(&["--threads", "0"]))
            .expect_err("zero workers would never answer");
        assert!(
            matches!(error, CliError::ParseIntError(ref flag, _, _) if flag == "--threads"),
            "{error:?}"
        );
    }

    #[test]
    fn esplora_url_without_equals_is_rejected() {
        let error = Args::parse(args_from_strings(&["--esplora-url", "http://no-equals"]))
            .expect_err("an entry without `=` names no network");
        assert!(
            matches!(error, CliError::MissingRequired(ref m)
                if m.contains("--esplora-url") && m.contains("<network>=<url>")),
            "{error:?}"
        );
    }

    #[test]
    fn esplora_url_unknown_network_is_rejected() {
        let error = Args::parse(args_from_strings(&["--esplora-url", "bogus=http://h"]))
            .expect_err("an unknown network name is a typo, not a new network");
        assert!(
            matches!(error, CliError::MissingRequired(ref m)
                if m.contains("bogus") && m.contains("mainnet")),
            "{error:?}"
        );
    }

    #[test]
    fn esplora_url_duplicate_network_is_rejected() {
        let error = Args::parse(args_from_strings(&[
            "--esplora-url",
            "regtest=http://a",
            "--esplora-url",
            "regtest=http://b",
        ]))
        .expect_err("a network named twice is ambiguous");
        assert!(
            matches!(error, CliError::MissingRequired(ref m)
                if m.contains("regtest") && m.contains("more than once")),
            "{error:?}"
        );
    }

    #[test]
    fn esplora_url_empty_url_is_rejected() {
        let error = Args::parse(args_from_strings(&["--esplora-url", "regtest="]))
            .expect_err("an empty URL configures nothing");
        assert!(
            matches!(error, CliError::MissingRequired(ref m) if m.contains("empty")),
            "{error:?}"
        );
    }

    #[test]
    fn unknown_flag_is_rejected() {
        let error = Args::parse(args_from_strings(&["--frobnicate"]))
            .expect_err("an unknown flag is an error, not ignored");
        assert!(matches!(error, CliError::Unknown(_)), "{error:?}");
    }

    #[test]
    fn help_text_documents_the_networks_and_the_custom_sharing() {
        assert!(HELP_TEXT.contains("--bind"));
        assert!(HELP_TEXT.contains("--esplora-url <network>=<url>"));
        assert!(HELP_TEXT.contains("--threads"));
        assert!(HELP_TEXT.contains("Health:   GET|HEAD /health -> 200"));
        for network in NETWORK_NAMES {
            assert!(HELP_TEXT.contains(network), "help names {network}");
        }
        assert!(HELP_TEXT.contains("Every custom\n"));
        assert!(HELP_TEXT.contains("network shares the one `custom` override"));
        assert!(HELP_TEXT.contains("Cache:    successful results for 60 s"));
        assert!(HELP_TEXT.contains("noCache=true answers 501 FEATURE_NOT_SUPPORTED"));
        assert!(HELP_TEXT.contains(
            "Log:      one JSON object per request on stderr: method, path, did, accept, status, latency_ms, cache, network"
        ));
    }
}
