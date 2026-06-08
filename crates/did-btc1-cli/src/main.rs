//! `did-btc1` — command-line client for the `did:btc1` DID method.
//!
//! This binary owns all HTTP and drives the sans-I/O resolver FSM from the
//! `did-btc1` library to completion. The library never makes network calls
//! the CLI fetches the chain tip and the beacon transactions and feeds
//! the typed responses back into the FSM.

use did_btc1::resolver::ResolverState;
use did_btc1::{Document, ResolutionOptions, ResolutionResult, document::SidecarData};
use error_iter::ErrorIter as _;
use onlyargs::{CliError, OnlyArgs, traits::*};
use onlyerror::Error;
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::File;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

/// CLI subcommands. One variant today (`resolve`); a future `update` /
/// `deactivate` is one variant here plus one match arm in `run()` (req-5).
#[derive(Debug)]
enum Command {
    Resolve {
        did: String,
        network: Option<String>,
        esplora_url: Option<String>,
        sidecar: Option<PathBuf>,
    },
}

/// Parsed command-line arguments. `resolve`'s options are subcommand-scoped
/// so there are no global config flags.
#[derive(Debug)]
struct Args {
    command: Command,
}

/// Top-level CLI error. Every fallible operation in the resolve path — arg
/// parsing, the DID parse, HTTP (tip GET + beacon requests), JSON
/// (de)serialization, and the library's `resolve`/FSM-step calls — flows
/// through here to stderr + a nonzero exit; the CLI never panics on
/// these.
#[derive(Debug, Error)]
enum CliRunError {
    /// Argument parsing error.
    Cli(#[from] CliError),

    /// Invalid DID identifier.
    DidParse(#[from] did_btc1::identifier::Error),

    /// Error constructing the resolver or applying an update.
    Document(#[from] did_btc1::document::Error),

    /// Error stepping the resolver FSM.
    Resolver(#[from] did_btc1::resolver::Error),

    /// HTTP transport error (tip GET or a beacon request).
    Http(#[from] ureq::Error),

    /// JSON (de)serialization error (sidecar parse or output build).
    Json(#[from] serde_json::Error),

    /// I/O error (opening the sidecar file).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Unknown `--network` value.
    #[error("Unknown network '{0}'. Expected testnet, signet, mainnet, or mutinynet")]
    UnknownNetwork(String),
}

impl OnlyArgs for Args {
    const VERSION: &'static str = onlyargs::impl_version!();

    fn help() -> ! {
        let help_text = concat!(
            env!("CARGO_PKG_NAME"),
            " v",
            env!("CARGO_PKG_VERSION"),
            "\n",
            "Command-line client for the did:btc1 DID method.\n\n",
            "Usage:\n  did-btc1 [flags] <command> [command args]\n",
            "\nFlags:\n",
            "  -h --help     Show this help message.\n",
            "  -V --version  Show the application version.\n",
            "\nCommands:\n",
            "  resolve <did>                Resolve a did:btc1 identifier and print the\n",
            "                               DID resolution result as JSON.\n",
            "    --network <net>             Network to resolve against: testnet (default),\n",
            "                                signet, mainnet, or mutinynet.\n",
            "    --esplora-url <url>         Esplora base URL override (no trailing slash).\n",
            "                                Takes precedence over --network.\n",
            "    --sidecar <file>            Path to a sidecar data JSON file.\n",
        );
        println!("{help_text}");
        std::process::exit(0);
    }

    fn parse(args: Vec<OsString>) -> Result<Self, CliError> {
        let mut positional_args = Vec::new();
        let mut args = args.into_iter();
        // Scan leading global flags until the first non-flag token (the
        // subcommand), which — with the rest of the iterator — is handed to the
        // per-subcommand parser below. The loop currently exits on its first
        // continuing token because the only global flags (`--help`/`--version`)
        // diverge; it is kept in loop form so future value-taking global flags
        // (req-5) slot in as additional arms without restructuring.
        #[allow(clippy::never_loop)]
        while let Some(arg) = args.next() {
            match arg.to_str() {
                Some("--help") | Some("-h") => Self::help(),
                Some("--version") | Some("-V") => Self::version(),
                Some("--") => break,
                Some(s) if !s.starts_with('-') => {
                    positional_args.push(arg);
                    positional_args.extend(args);
                    break;
                }
                _ => return Err(CliError::Unknown(arg)),
            }
        }

        if positional_args.is_empty() {
            return Err(CliError::MissingRequired(String::from(
                "A command is required ('resolve')",
            )));
        }

        let subcommand = positional_args[0].to_string_lossy().to_string();
        let mut sub_args = positional_args.into_iter().skip(1);

        let command = match subcommand.as_ref() {
            "resolve" => {
                let mut did: Option<String> = None;
                let mut network: Option<String> = None;
                let mut esplora_url: Option<String> = None;
                let mut sidecar: Option<PathBuf> = None;
                while let Some(arg) = sub_args.next() {
                    match arg.to_str() {
                        Some(p @ "--network") => {
                            network = Some(sub_args.next().parse_str(p)?);
                        }
                        Some(p @ "--esplora-url") => {
                            esplora_url = Some(sub_args.next().parse_str(p)?);
                        }
                        Some(p @ "--sidecar") => {
                            sidecar = Some(sub_args.next().parse_path(p)?);
                        }
                        Some(s) if !s.starts_with('-') => {
                            if did.is_some() {
                                return Err(CliError::Unknown(arg));
                            }
                            did = Some(s.to_string());
                        }
                        _ => return Err(CliError::Unknown(arg)),
                    }
                }
                Command::Resolve {
                    did: did.ok_or_else(|| CliError::MissingRequired("did".to_string()))?,
                    network,
                    esplora_url,
                    sidecar,
                }
            }
            _ => {
                return Err(CliError::MissingRequired(String::from(
                    "Unknown command. Expected 'resolve'",
                )));
            }
        };

        Ok(Self { command })
    }
}

/// Map a `--network` value to its confirmed Esplora base URL (no trailing
/// slash). All four URLs were live-checked (each `/blocks/tip/height` returned
/// a bare integer over https); every arm uses a verified URL.
fn network_base_url(network: &str) -> Option<&'static str> {
    match network {
        "testnet" => Some("https://blockstream.info/testnet/api"),
        "signet" => Some("https://blockstream.info/signet/api"),
        "mainnet" => Some("https://blockstream.info/api"),
        "mutinynet" => Some("https://mutinynet.com/api"),
        _ => None,
    }
}

/// Resolve the Esplora base URL from the CLI flags. `--esplora-url` wins
/// verbatim; otherwise `--network` maps to a confirmed URL; the default is
/// `testnet`. An unrecognized `--network` is a clean error, not a silent
/// fallback.
fn resolve_base_url(
    network: Option<&str>,
    esplora_url: Option<String>,
) -> Result<String, CliRunError> {
    if let Some(mut url) = esplora_url {
        // Normalize a user-supplied trailing slash: consumers concatenate with a
        // leading slash (`{base}/blocks/tip/height`, `{rpc_host}/address/...`),
        // so a trailing slash here would yield a `//` in the path.
        if url.ends_with('/') {
            url.pop();
        }
        return Ok(url);
    }
    let net = network.unwrap_or("testnet");
    network_base_url(net)
        .map(str::to_string)
        .ok_or_else(|| CliRunError::UnknownNetwork(net.to_string()))
}

/// Build a configured HTTP agent. The User-Agent is REQUIRED — the mutinynet
/// endpoint returns 403 to UA-less requests — and a 30s global timeout bounds a
/// slow or hostile server.
fn build_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .user_agent(concat!(
            env!("CARGO_PKG_NAME"),
            "/",
            env!("CARGO_PKG_VERSION")
        ))
        .build()
        .into()
}

/// Build the spec-key resolution JSON triple.
///
/// `Document` / `ResolutionResult` / `ResolutionMetadata` do NOT implement
/// `Serialize`, so this uses `serde_json::json!` at the build site rather than
/// a derived wrapper struct. `result.document.as_ref()` yields the
/// `&serde_json::Value` for the document; `document_metadata` derives
/// `Serialize` and already carries the correct inner spec keys.
fn build_resolution_json(result: &ResolutionResult) -> serde_json::Value {
    serde_json::json!({
        "didResolutionMetadata": {},
        "didDocument": result.document.as_ref(),
        "didDocumentMetadata": result.document_metadata,
    })
}

/// Run the resolve subcommand: own the chain-tip GET, drive the sans-I/O FSM to
/// completion (issuing the beacon requests it asks for), and return the spec
/// resolution triple.
fn resolve(
    did_str: &str,
    network: Option<&str>,
    esplora_url: Option<String>,
    sidecar: Option<PathBuf>,
) -> Result<ResolutionResult, CliRunError> {
    let base = resolve_base_url(network, esplora_url)?;
    let agent = build_agent();

    // Chain-tip GET — one of the two HTTP calls the CLI owns. The
    // `/blocks/tip/height` body is a bare integer. This is a HARD,
    // `?`-propagated fetch by deliberate choice: a transient tip failure aborts
    // the resolve (stderr + nonzero exit) rather than degrading to
    // `chain_tip_height: None`, because `confirmations` depends on a reliable
    // tip and a partial/None tip would silently weaken confirmation reporting.
    let tip: u32 = agent
        .get(format!("{base}/blocks/tip/height"))
        .call()?
        .body_mut()
        .read_json::<u32>()?;

    // Optional sidecar data. `SidecarData` has a manual `Deserialize`
    // that rebuilds the lookup table on any serde path.
    let sidecar_data = match sidecar {
        Some(path) => {
            let file = File::open(path)?;
            Some(serde_json::from_reader::<_, SidecarData>(file)?)
        }
        None => None,
    };

    let did: did_btc1::identifier::Did = did_str.parse()?;
    let opts = ResolutionOptions {
        esplora_url: Some(base),
        chain_tip_height: Some(tip),
        sidecar_data,
        ..Default::default()
    };

    // Drive the sans-I/O resolver FSM. The library returns the beacon requests
    // to issue; the CLI runs them and feeds the typed responses back.
    let mut fsm = Document::resolve(&did, opts)?;
    let result = loop {
        match fsm.resolve()? {
            ResolverState::Requests(next_state, beacons) => {
                let mut responses = HashMap::new();
                for (beacon_type, requests) in beacons {
                    for req in requests {
                        let mut resp = agent.run(req)?;
                        let entry: &mut Vec<_> = responses.entry(beacon_type).or_default();
                        entry.extend(resp.body_mut().read_json::<Vec<_>>()?);
                    }
                }
                fsm = next_state.process_responses(responses);
            }
            ResolverState::Resolved(result) => break result,
        }
    };

    Ok(result)
}

fn run() -> Result<(), CliRunError> {
    let args: Args = onlyargs::parse()?;
    match args.command {
        Command::Resolve {
            did,
            network,
            esplora_url,
            sidecar,
        } => {
            let result = resolve(&did, network.as_deref(), esplora_url, sidecar)?;
            let out = build_resolution_json(&result);
            println!("{}", serde_json::to_string_pretty(&out)?);
            Ok(())
        }
    }
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
    use std::ffi::OsString;

    const SAMPLE_DID: &str =
        "did:btc1:k1qqpuwwde82nennsavvf0lqfnlvx7frrgzs57lchr02q8mz49qzaaxmqphnvcx";

    fn args_from_strings(strings: &[&str]) -> Vec<OsString> {
        strings.iter().map(OsString::from).collect()
    }

    #[test]
    fn test_parse_resolve_command() {
        let parsed = Args::parse(args_from_strings(&["resolve", SAMPLE_DID])).unwrap();
        assert!(matches!(parsed.command, Command::Resolve { .. }));
        let Command::Resolve { did, .. } = parsed.command;
        assert_eq!(did, SAMPLE_DID);
    }

    #[test]
    fn test_parse_network() {
        let parsed = Args::parse(args_from_strings(&[
            "resolve",
            "--network",
            "signet",
            SAMPLE_DID,
        ]))
        .unwrap();
        let Command::Resolve { network, .. } = parsed.command;
        assert_eq!(network, Some("signet".to_string()));
    }

    #[test]
    fn test_parse_esplora_url_override() {
        let parsed = Args::parse(args_from_strings(&[
            "resolve",
            "--esplora-url",
            "https://node.example/api",
            SAMPLE_DID,
        ]))
        .unwrap();
        let Command::Resolve { esplora_url, .. } = parsed.command;
        assert_eq!(esplora_url, Some("https://node.example/api".to_string()));
    }

    #[test]
    fn test_parse_sidecar() {
        let parsed = Args::parse(args_from_strings(&[
            "resolve",
            "--sidecar",
            "/tmp/s.json",
            SAMPLE_DID,
        ]))
        .unwrap();
        let Command::Resolve { sidecar, .. } = parsed.command;
        assert_eq!(sidecar, Some(PathBuf::from("/tmp/s.json")));
    }

    #[test]
    fn test_parse_sidecar_absent_is_none() {
        let parsed = Args::parse(args_from_strings(&["resolve", SAMPLE_DID])).unwrap();
        let Command::Resolve { sidecar, .. } = parsed.command;
        assert_eq!(sidecar, None);
    }

    #[test]
    fn test_parse_no_command() {
        assert!(matches!(
            Args::parse(args_from_strings(&[])).unwrap_err(),
            CliError::MissingRequired(_)
        ));
    }

    #[test]
    fn test_parse_unknown_flag() {
        assert!(matches!(
            Args::parse(args_from_strings(&["resolve", "--bogus", SAMPLE_DID])).unwrap_err(),
            CliError::Unknown(_)
        ));
    }

    #[test]
    fn test_resolve_base_url_default_is_testnet() {
        assert_eq!(
            resolve_base_url(None, None).unwrap(),
            "https://blockstream.info/testnet/api"
        );
    }

    #[test]
    fn test_resolve_base_url_all_networks_confirmed() {
        assert_eq!(
            resolve_base_url(Some("signet"), None).unwrap(),
            "https://blockstream.info/signet/api"
        );
        assert_eq!(
            resolve_base_url(Some("mainnet"), None).unwrap(),
            "https://blockstream.info/api"
        );
        assert_eq!(
            resolve_base_url(Some("mutinynet"), None).unwrap(),
            "https://mutinynet.com/api"
        );
    }

    #[test]
    fn test_resolve_base_url_esplora_override_wins() {
        assert_eq!(
            resolve_base_url(
                Some("mainnet"),
                Some("https://node.example/api".to_string())
            )
            .unwrap(),
            "https://node.example/api"
        );
    }

    #[test]
    fn test_resolve_base_url_esplora_override_trailing_slash_trimmed() {
        assert_eq!(
            resolve_base_url(None, Some("https://node.example/api/".to_string())).unwrap(),
            "https://node.example/api"
        );
    }

    #[test]
    fn test_resolve_base_url_unknown_network_errors() {
        assert!(matches!(
            resolve_base_url(Some("regtest"), None).unwrap_err(),
            CliRunError::UnknownNetwork(_)
        ));
    }

    /// Live integration test, env-var driven. SKIPS CLEANLY when
    /// `DIDBTC1_LIVE_DID` is unset/empty — it passes trivially and asserts
    /// nothing in that case, so default `cargo test` (and even `--ignored`
    /// with the env var unset) stays offline-green. When a DID IS supplied it
    /// runs the real resolve path against the network in `DIDBTC1_LIVE_NETWORK`
    /// (default `testnet`) and asserts the JSON carries the three spec keys.
    ///
    /// Run with: `DIDBTC1_LIVE_DID=did:btc1:... cargo test -p did-btc1-cli -- --ignored`
    #[test]
    #[ignore]
    fn live_resolve_emits_spec_keys() {
        let did = match std::env::var("DIDBTC1_LIVE_DID") {
            Ok(d) if !d.is_empty() => d,
            _ => return,
        };
        let network =
            std::env::var("DIDBTC1_LIVE_NETWORK").unwrap_or_else(|_| "testnet".to_string());

        let result = resolve(&did, Some(&network), None, None)
            .expect("live resolve should succeed for the supplied DID");
        let out = build_resolution_json(&result);

        let obj = out.as_object().expect("resolution JSON must be an object");
        assert!(obj.contains_key("didResolutionMetadata"));
        assert!(obj.contains_key("didDocument"));
        assert!(obj.contains_key("didDocumentMetadata"));
    }
}
