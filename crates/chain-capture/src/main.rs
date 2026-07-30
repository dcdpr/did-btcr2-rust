#![forbid(unsafe_code)]
//! `chain-capture` — developer utility that records beacon-address transactions
//! from a Bitcoin chain into local fixtures, and mints the scenarios those
//! fixtures describe.
//!
//! Two subcommands:
//!
//! - `capture` records the Esplora responses a resolve needs (per-address
//!   `/address/{a}/txs` bodies plus the chain tip) into
//!   `did-btcr2-rust/fixtures/chain/`, so the resolver's on-chain path can be
//!   replayed offline at test time.
//! - `mint` publishes a scenario — a DID with a chain of updates, or a
//!   deliberately conflicting pair of announcements — so there is real chain
//!   data to capture in the first place.
//!
//! Every subcommand takes `--network` explicitly. Nothing here defaults to a
//! chain: the minted scenarios are re-minted on successively more durable
//! chains (regtest, then a public test chain), and each move regenerates the
//! fixtures, their txids, heights and block times. A defaulted network would be
//! a hardcoded chain hiding in an argument parser.
//!
//! All HTTP goes through `did_btcr2_client::UreqTransport`, which already
//! carries the User-Agent public Esplora endpoints require and a global
//! timeout. This crate holds no HTTP client of its own.

mod capture;
mod fixture;
mod record;
mod targets;
mod validate;

use error_iter::ErrorIter as _;
use onlyargs::{CliError, OnlyArgs, traits::*};
use onlyerror::Error;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

/// Subcommands. `capture` reads a chain into fixtures; `mint` writes a scenario
/// onto a chain. Each variant is one match arm in [`run`].
#[derive(Debug)]
enum Command {
    /// Record beacon-address transaction bodies and the chain tip into fixtures.
    Capture {
        /// Chain to capture from: `regtest`, `mutinynet`, `testnet4`, `signet`.
        network: String,
        /// Esplora base URL override (no trailing slash). Required for a chain
        /// with no public endpoint, such as a local regtest stack.
        esplora_url: Option<String>,
        /// Capture a single vector (e.g. `regtest/k1/qgppexmy`) instead of every
        /// drivable one.
        vector: Option<String>,
    },
    /// Publish a scenario onto a chain, then record it.
    Mint {
        /// Which scenario to mint: `clean` (a multi-update chain ending in a
        /// deactivation) or `poisoned` (two conflicting announcements).
        scenario: String,
        /// Chain to mint on: `regtest`, `mutinynet`, `testnet4`, `signet`.
        network: String,
        /// Esplora base URL override (no trailing slash).
        esplora_url: Option<String>,
        /// bitcoind JSON-RPC endpoint. Required for a chain the tool must mine
        /// on (regtest); unused on a chain that mines itself.
        bitcoind_url: Option<String>,
        /// `user:password` for that endpoint's HTTP basic auth.
        bitcoind_auth: Option<String>,
        /// Secret key file (raw 32-byte lowercase hex) controlling the minted
        /// DIDs.
        key_file: PathBuf,
        /// Minting progress file, so an interrupted session resumes instead of
        /// re-announcing.
        state_file: PathBuf,
        /// Absolute fee in satoshis for each announcement transaction.
        fee: u64,
        /// Skip the broadcast confirm prompt.
        yes: bool,
    },
}

/// Parsed command-line arguments. Options are subcommand-scoped; there are no
/// global config flags.
#[derive(Debug)]
struct Args {
    command: Command,
}

/// Top-level error. Argument parsing, JSON (de)serialization, file I/O and every
/// facade call funnel through here to stderr plus a nonzero exit; operator input
/// never panics.
#[derive(Debug, Error)]
enum CaptureRunError {
    /// Argument parsing error.
    Cli(#[from] CliError),

    /// JSON (de)serialization error (fixture body or scenario state).
    Json(#[from] serde_json::Error),

    /// I/O error (reading a key/state file, writing a fixture).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// An error from the `did-btcr2-client` facade (transport, funding,
    /// broadcast, or a core composition error).
    Client(#[from] did_btcr2_client::Error),

    /// The capture session failed.
    Capture(#[from] capture::CaptureError),

    /// A subcommand whose body has not been written yet. A deliberately visible
    /// stub: the arm exists, parses its full flag set, and refuses to pretend it
    /// did the work.
    #[error("subcommand `{0}` lands in a later step of this phase")]
    NotImplemented(String),
}

impl OnlyArgs for Args {
    const VERSION: &'static str = onlyargs::impl_version!();

    fn help() -> ! {
        let help_text = concat!(
            env!("CARGO_PKG_NAME"),
            " v",
            env!("CARGO_PKG_VERSION"),
            "\n",
            "Capture chain fixtures for did:btcr2 replay tests, and mint the\n",
            "scenarios those fixtures record.\n\n",
            "Usage:\n  chain-capture [flags] <command> [command args]\n",
            "\nFlags:\n",
            "  -h --help     Show this help message.\n",
            "  -V --version  Show the application version.\n",
            "\nCommands:\n",
            "  capture                      Record per-address transaction bodies and the\n",
            "                               chain tip into fixtures/chain/.\n",
            "    --network <net>             REQUIRED. regtest | mutinynet | testnet4 |\n",
            "                                signet. There is no default: every chain\n",
            "                                produces different txids, heights and block\n",
            "                                times, so the chain is never implied.\n",
            "    --esplora-url <url>         Esplora base URL (no trailing slash). Required\n",
            "                                for a chain with no public endpoint (regtest).\n",
            "    --vector <id>               Capture one vector (e.g. regtest/k1/qgppexmy)\n",
            "                                instead of every drivable one.\n",
            "\n",
            "  mint                         Publish a scenario onto a chain so there is real\n",
            "                               chain data to capture.\n",
            "    --scenario <name>           REQUIRED. clean | poisoned.\n",
            "    --network <net>             REQUIRED. Same values as capture; no default.\n",
            "    --esplora-url <url>         Esplora base URL (no trailing slash).\n",
            "    --bitcoind-url <url>        bitcoind JSON-RPC endpoint. Required on a chain\n",
            "                                the tool must mine on (regtest).\n",
            "    --bitcoind-auth <user:pass> HTTP basic auth for that endpoint.\n",
            "    --key-file <file>           REQUIRED. Secret key controlling the minted\n",
            "                                DIDs (raw 32-byte lowercase hex).\n",
            "    --state-file <file>         REQUIRED. Minting progress, so an interrupted\n",
            "                                session resumes instead of re-announcing.\n",
            "    --fee <sats>                Absolute fee per announcement (default 1000).\n",
            "    --yes                       Skip the broadcast confirm prompt.\n",
        );
        println!("{help_text}");
        std::process::exit(0);
    }

    fn parse(args: Vec<OsString>) -> Result<Self, CliError> {
        let mut positional_args = Vec::new();
        let mut args = args.into_iter();
        // Scan leading global flags until the first non-flag token (the
        // subcommand), which — with the rest of the iterator — is handed to the
        // per-subcommand parser below.
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
                "A command is required ('capture' or 'mint')",
            )));
        }

        let subcommand = positional_args[0].to_string_lossy().to_string();
        let sub_args = positional_args.into_iter().skip(1);

        let command = match subcommand.as_ref() {
            "capture" => parse_capture(sub_args)?,
            "mint" => parse_mint(sub_args)?,
            _ => {
                return Err(CliError::MissingRequired(String::from(
                    "Unknown command. Expected 'capture' or 'mint'",
                )));
            }
        };

        Ok(Self { command })
    }
}

/// The `--network` value is required on every subcommand, with no default.
///
/// The minted scenarios move from a local regtest chain to successively more
/// durable public chains, and each move regenerates every fixture — txids,
/// heights, block times and address HRPs all change. A defaulted network would
/// silently pin one chain into the tool.
fn require_network(network: Option<String>) -> Result<String, CliError> {
    network.ok_or_else(|| {
        CliError::MissingRequired(String::from(
            "--network is required (regtest | mutinynet | testnet4 | signet)",
        ))
    })
}

/// Parse the `capture` subcommand.
fn parse_capture(mut sub_args: impl Iterator<Item = OsString>) -> Result<Command, CliError> {
    let mut network: Option<String> = None;
    let mut esplora_url: Option<String> = None;
    let mut vector: Option<String> = None;
    while let Some(arg) = sub_args.next() {
        match arg.to_str() {
            Some(p @ "--network") => network = Some(sub_args.next().parse_str(p)?),
            Some(p @ "--esplora-url") => esplora_url = Some(sub_args.next().parse_str(p)?),
            Some(p @ "--vector") => vector = Some(sub_args.next().parse_str(p)?),
            _ => return Err(CliError::Unknown(arg)),
        }
    }
    Ok(Command::Capture {
        network: require_network(network)?,
        esplora_url,
        vector,
    })
}

/// The absolute fee, in satoshis, used for an announcement when `--fee` is
/// absent. Matches the CLI's own default for the small single-input announce tx.
const DEFAULT_FEE_SATS: u64 = 1_000;

/// Parse the `mint` subcommand.
fn parse_mint(mut sub_args: impl Iterator<Item = OsString>) -> Result<Command, CliError> {
    let mut scenario: Option<String> = None;
    let mut network: Option<String> = None;
    let mut esplora_url: Option<String> = None;
    let mut bitcoind_url: Option<String> = None;
    let mut bitcoind_auth: Option<String> = None;
    let mut key_file: Option<PathBuf> = None;
    let mut state_file: Option<PathBuf> = None;
    let mut fee = DEFAULT_FEE_SATS;
    let mut yes = false;
    while let Some(arg) = sub_args.next() {
        match arg.to_str() {
            Some(p @ "--scenario") => scenario = Some(sub_args.next().parse_str(p)?),
            Some(p @ "--network") => network = Some(sub_args.next().parse_str(p)?),
            Some(p @ "--esplora-url") => esplora_url = Some(sub_args.next().parse_str(p)?),
            Some(p @ "--bitcoind-url") => bitcoind_url = Some(sub_args.next().parse_str(p)?),
            Some(p @ "--bitcoind-auth") => bitcoind_auth = Some(sub_args.next().parse_str(p)?),
            Some(p @ "--key-file") => key_file = Some(sub_args.next().parse_path(p)?),
            Some(p @ "--state-file") => state_file = Some(sub_args.next().parse_path(p)?),
            Some(p @ "--fee") => fee = sub_args.next().parse_int::<u64, _>(p)?,
            Some("--yes") => yes = true,
            _ => return Err(CliError::Unknown(arg)),
        }
    }
    Ok(Command::Mint {
        scenario: scenario.ok_or_else(|| {
            CliError::MissingRequired(String::from("--scenario (clean | poisoned)"))
        })?,
        network: require_network(network)?,
        esplora_url,
        bitcoind_url,
        bitcoind_auth,
        key_file: key_file
            .ok_or_else(|| CliError::MissingRequired(String::from("--key-file <path>")))?,
        state_file: state_file
            .ok_or_else(|| CliError::MissingRequired(String::from("--state-file <path>")))?,
        fee,
        yes,
    })
}

/// Describe a parsed command for the stub error, so an operator can see the
/// tool understood their flags even though the body is not written yet.
///
/// `--bitcoind-auth` is reported as present/absent and NEVER echoed: the
/// credential belongs in an `Authorization` header, not in this tool's output or
/// in anything it persists.
fn describe(command: &Command) -> String {
    match command {
        Command::Capture {
            network,
            esplora_url,
            vector,
        } => format!(
            "capture (network={network}, esplora-url={}, vector={})",
            esplora_url.as_deref().unwrap_or("<default>"),
            vector.as_deref().unwrap_or("<all>"),
        ),
        Command::Mint {
            scenario,
            network,
            esplora_url,
            bitcoind_url,
            bitcoind_auth,
            key_file,
            state_file,
            fee,
            yes,
        } => format!(
            "mint (scenario={scenario}, network={network}, esplora-url={}, \
             bitcoind-url={}, bitcoind-auth={}, key-file={}, state-file={}, \
             fee={fee}, yes={yes})",
            esplora_url.as_deref().unwrap_or("<default>"),
            bitcoind_url.as_deref().unwrap_or("<unset>"),
            if bitcoind_auth.is_some() {
                "<set>"
            } else {
                "<unset>"
            },
            key_file.display(),
            state_file.display(),
        ),
    }
}

fn run() -> Result<(), CaptureRunError> {
    let args: Args = onlyargs::parse()?;

    match args.command {
        Command::Capture {
            network,
            esplora_url,
            vector,
        } => Ok(capture::run(&network, esplora_url, vector)?),
        // Still a visible stub: the flags parse and are reported back, and the
        // tool refuses rather than pretending to have minted anything. A later
        // step of this phase replaces this arm with its body.
        ref command @ Command::Mint { .. } => {
            Err(CaptureRunError::NotImplemented(describe(command)))
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

    fn args_from_strings(strings: &[&str]) -> Vec<OsString> {
        strings.iter().map(OsString::from).collect()
    }

    #[test]
    fn test_parse_capture_command() {
        let parsed = Args::parse(args_from_strings(&[
            "capture",
            "--network",
            "regtest",
            "--esplora-url",
            "http://localhost:3000",
        ]))
        .expect("a capture with an explicit network parses");
        let Command::Capture {
            network,
            esplora_url,
            vector,
        } = parsed.command
        else {
            panic!("expected Capture");
        };
        assert_eq!(network, "regtest");
        assert_eq!(esplora_url, Some("http://localhost:3000".to_string()));
        assert_eq!(vector, None);
    }

    #[test]
    fn test_parse_capture_vector() {
        let parsed = Args::parse(args_from_strings(&[
            "capture",
            "--network",
            "mutinynet",
            "--vector",
            "mutinynet/k1/q5p6w9su",
        ]))
        .expect("a capture with a vector id parses");
        let Command::Capture {
            network, vector, ..
        } = parsed.command
        else {
            panic!("expected Capture");
        };
        assert_eq!(network, "mutinynet");
        assert_eq!(vector, Some("mutinynet/k1/q5p6w9su".to_string()));
    }

    #[test]
    fn test_capture_without_network_is_an_error() {
        let error = Args::parse(args_from_strings(&["capture"]))
            .expect_err("capture must not default a chain");
        assert!(
            matches!(error, CliError::MissingRequired(ref m) if m.contains("--network")),
            "the missing-network error must name the flag: {error}"
        );
        assert!(
            error.to_string().contains("--network"),
            "the displayed error must name the flag: {error}"
        );
    }

    #[test]
    fn test_parse_mint_command_defaults() {
        let parsed = Args::parse(args_from_strings(&[
            "mint",
            "--scenario",
            "clean",
            "--network",
            "regtest",
            "--key-file",
            "k.hex",
            "--state-file",
            "s.json",
            "--bitcoind-url",
            "http://127.0.0.1:18443",
            "--bitcoind-auth",
            "polaruser:polarpass",
        ]))
        .expect("a fully-specified mint parses");
        let Command::Mint {
            scenario,
            network,
            esplora_url,
            bitcoind_url,
            bitcoind_auth,
            key_file,
            state_file,
            fee,
            yes,
        } = parsed.command
        else {
            panic!("expected Mint");
        };
        assert_eq!(scenario, "clean");
        assert_eq!(network, "regtest");
        assert_eq!(esplora_url, None);
        assert_eq!(bitcoind_url, Some("http://127.0.0.1:18443".to_string()));
        assert_eq!(bitcoind_auth, Some("polaruser:polarpass".to_string()));
        assert_eq!(key_file, PathBuf::from("k.hex"));
        assert_eq!(state_file, PathBuf::from("s.json"));
        assert_eq!(fee, 1000);
        assert!(!yes);
    }

    #[test]
    fn test_parse_mint_fee_and_yes() {
        let parsed = Args::parse(args_from_strings(&[
            "mint",
            "--scenario",
            "poisoned",
            "--network",
            "regtest",
            "--key-file",
            "k.hex",
            "--state-file",
            "s.json",
            "--fee",
            "2500",
            "--yes",
        ]))
        .expect("an explicit fee and --yes parse");
        let Command::Mint {
            scenario, fee, yes, ..
        } = parsed.command
        else {
            panic!("expected Mint");
        };
        assert_eq!(scenario, "poisoned");
        assert_eq!(fee, 2500);
        assert!(yes);
    }

    #[test]
    fn test_mint_without_network_is_an_error() {
        let error = Args::parse(args_from_strings(&[
            "mint",
            "--scenario",
            "clean",
            "--key-file",
            "k.hex",
            "--state-file",
            "s.json",
        ]))
        .expect_err("mint must not default a chain");
        assert!(
            matches!(error, CliError::MissingRequired(ref m) if m.contains("--network")),
            "the missing-network error must name the flag: {error}"
        );
    }

    #[test]
    fn test_mint_without_key_file_is_an_error() {
        let error = Args::parse(args_from_strings(&[
            "mint",
            "--scenario",
            "clean",
            "--network",
            "regtest",
            "--state-file",
            "s.json",
        ]))
        .expect_err("mint requires a key file");
        assert!(
            matches!(error, CliError::MissingRequired(ref m) if m.contains("--key-file")),
            "the missing-key-file error must name the flag: {error}"
        );
    }

    #[test]
    fn test_describe_never_echoes_the_bitcoind_credential() {
        let parsed = Args::parse(args_from_strings(&[
            "mint",
            "--scenario",
            "clean",
            "--network",
            "regtest",
            "--key-file",
            "k.hex",
            "--state-file",
            "s.json",
            "--bitcoind-auth",
            "polaruser:polarpass",
        ]))
        .expect("a mint with auth parses");
        let described = describe(&parsed.command);
        assert!(
            !described.contains("polarpass") && !described.contains("polaruser"),
            "the bitcoind credential must never be echoed: {described}"
        );
        assert!(
            described.contains("bitcoind-auth=<set>"),
            "presence of the credential is still reported: {described}"
        );
    }

    #[test]
    fn test_parse_no_command() {
        assert!(matches!(
            Args::parse(args_from_strings(&[])).expect_err("a command is required"),
            CliError::MissingRequired(_)
        ));
    }

    #[test]
    fn test_parse_unknown_command() {
        assert!(matches!(
            Args::parse(args_from_strings(&["replay", "--network", "regtest"]))
                .expect_err("only capture and mint exist"),
            CliError::MissingRequired(_)
        ));
    }

    #[test]
    fn test_parse_unknown_flag() {
        assert!(matches!(
            Args::parse(args_from_strings(&[
                "capture",
                "--network",
                "regtest",
                "--bogus"
            ]))
            .expect_err("an unknown flag is rejected"),
            CliError::Unknown(_)
        ));
    }
}
