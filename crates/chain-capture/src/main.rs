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
mod chain;
mod fixture;
mod mint;
mod record;
mod secret;
mod targets;
mod validate;

use crate::secret::Secret;
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
        /// `user:password` for that endpoint's HTTP basic auth, given inline.
        ///
        /// Kept for a disposable local regtest, where the credential is a
        /// fixture. An argv value is readable by any user's `ps` for the life of
        /// the process and lands in shell history, so
        /// `bitcoind_auth_file` is the documented form.
        bitcoind_auth: Option<String>,
        /// A file holding `user:password` for that endpoint.
        bitcoind_auth_file: Option<PathBuf>,
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

    /// The minting session failed.
    Mint(#[from] mint::MintError),

    /// The node credential was named twice, inline and in a file.
    #[error(
        "--bitcoind-auth and --bitcoind-auth-file both name a credential ({path}) — pass one. Prefer the file: a value passed as an argument is readable in /proc/<pid>/cmdline by any user for the life of the process, lands in shell history, and appears in `ps`"
    )]
    AmbiguousBitcoindAuth {
        /// The credential file that was also named.
        path: String,
    },

    /// The credential file could not be read. Names the path, never a byte of
    /// what it holds.
    #[error("{path}: --bitcoind-auth-file could not be read")]
    CredentialFileUnreadable {
        /// The file that was named.
        path: String,
        /// Why it could not be read.
        #[source]
        source: std::io::Error,
    },

    /// The credential file held nothing usable.
    #[error("{path}: --bitcoind-auth-file is empty — it must hold `user:password`")]
    CredentialFileEmpty {
        /// The file that was named.
        path: String,
    },
}

/// The help text, as a value rather than a side effect, so a test can assert
/// what it tells an operator about the two ways to supply a node credential.
const HELP_TEXT: &str = concat!(
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
    "    --bitcoind-auth-file <file> File holding `user:password` for that endpoint.\n",
    "                                PREFERRED over --bitcoind-auth.\n",
    "    --bitcoind-auth <user:pass> HTTP basic auth for that endpoint, inline. The\n",
    "                                value is readable by any user's `ps` for the\n",
    "                                life of the process and lands in shell history;\n",
    "                                use it only on a disposable local chain.\n",
    "    --key-file <file>           REQUIRED. Secret key controlling the minted\n",
    "                                DIDs (raw 32-byte lowercase hex).\n",
    "    --state-file <file>         REQUIRED. Minting progress, so an interrupted\n",
    "                                session resumes instead of re-announcing.\n",
    "    --fee <sats>                Absolute fee per announcement (default 1000).\n",
    "    --yes                       Skip the broadcast confirm prompt.\n",
);

impl OnlyArgs for Args {
    const VERSION: &'static str = onlyargs::impl_version!();

    fn help() -> ! {
        println!("{HELP_TEXT}");
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
            // `chain-capture capture --help` is what an operator reaches for; the
            // global scan above only sees a leading `--help`, so each subcommand
            // answers it too rather than reporting an unknown argument.
            Some("--help") | Some("-h") => Args::help(),
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
    let mut bitcoind_auth_file: Option<PathBuf> = None;
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
            Some(p @ "--bitcoind-auth-file") => {
                bitcoind_auth_file = Some(sub_args.next().parse_path(p)?);
            }
            Some(p @ "--key-file") => key_file = Some(sub_args.next().parse_path(p)?),
            Some(p @ "--state-file") => state_file = Some(sub_args.next().parse_path(p)?),
            Some(p @ "--fee") => fee = sub_args.next().parse_int::<u64, _>(p)?,
            Some("--yes") => yes = true,
            Some("--help") | Some("-h") => Args::help(),
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
        bitcoind_auth_file,
        key_file: key_file
            .ok_or_else(|| CliError::MissingRequired(String::from("--key-file <path>")))?,
        state_file: state_file
            .ok_or_else(|| CliError::MissingRequired(String::from("--state-file <path>")))?,
        fee,
        yes,
    })
}

/// Describe a parsed command back to the operator at session start, so a long
/// session says out loud which chain, endpoint and files it is about to use.
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
            bitcoind_auth_file,
            key_file,
            state_file,
            fee,
            yes,
        } => format!(
            "mint (scenario={scenario}, network={network}, esplora-url={}, \
             bitcoind-url={}, bitcoind-auth={}, bitcoind-auth-file={}, key-file={}, \
             state-file={}, fee={fee}, yes={yes})",
            esplora_url.as_deref().unwrap_or("<default>"),
            bitcoind_url.as_deref().unwrap_or("<unset>"),
            // Presence only, from EITHER source, and never the value. A path is
            // not a credential, so the file is named; what is in it is not.
            match (bitcoind_auth.is_some(), bitcoind_auth_file.is_some()) {
                (true, _) => "<set on the command line>",
                (false, true) => "<set from file>",
                (false, false) => "<unset>",
            },
            bitcoind_auth_file
                .as_ref()
                .map_or_else(|| "<unset>".to_string(), |path| path.display().to_string()),
            key_file.display(),
            state_file.display(),
        ),
    }
}

/// Resolve the node credential from whichever source named it.
///
/// The file form is preferred and documented as such: a value passed as
/// `--bitcoind-auth` sits in `/proc/<pid>/cmdline` — world-readable — for the
/// life of the process, lands in shell history, and appears in any `ps` an
/// unrelated user runs. Everything downstream of this point already takes care:
/// the RPC client's `Debug` is redacted by hand, no error variant carries the
/// header, and the session summary reports presence rather than the value. The
/// argument was the weakest link in that chain.
///
/// Naming both is refused rather than silently resolved one way: an operator who
/// passed two credentials should be told which one would have been used.
///
/// Both sources come back as a [`Secret`], which holds the value as bytes it
/// overwrites when it is dropped. The file is read as BYTES for the same reason:
/// `read_to_string` would put the whole credential file into a `String` that is
/// freed intact, which is precisely the leak the minting key's loader goes out of
/// its way to avoid one file over. Two secrets in one crate, one rule.
fn resolve_bitcoind_auth(
    inline: Option<String>,
    file: Option<PathBuf>,
) -> Result<Option<Secret>, CaptureRunError> {
    let Some(path) = file else {
        return Ok(inline.as_deref().map(Secret::from_exposed));
    };
    if inline.is_some() {
        return Err(CaptureRunError::AmbiguousBitcoindAuth {
            path: path.display().to_string(),
        });
    }
    // The path is reported on failure; not one byte of the contents is.
    let secret =
        Secret::from_file(&path).map_err(|source| CaptureRunError::CredentialFileUnreadable {
            path: path.display().to_string(),
            source,
        })?;
    if secret.is_empty() {
        return Err(CaptureRunError::CredentialFileEmpty {
            path: path.display().to_string(),
        });
    }
    Ok(Some(secret))
}

fn run() -> Result<(), CaptureRunError> {
    let args: Args = onlyargs::parse()?;
    // The session's own report goes to stderr, so a shell pipeline reading stdout
    // is unaffected by it. The bitcoind credential is reported as present or
    // absent and never echoed.
    eprintln!("{}", describe(&args.command));

    match args.command {
        Command::Capture {
            network,
            esplora_url,
            vector,
        } => Ok(capture::run(&network, esplora_url, vector)?),
        Command::Mint {
            scenario,
            network,
            esplora_url,
            bitcoind_url,
            bitcoind_auth,
            bitcoind_auth_file,
            key_file,
            state_file,
            fee,
            yes,
        } => Ok(mint::run(
            &scenario,
            &network,
            esplora_url,
            bitcoind_url,
            resolve_bitcoind_auth(bitcoind_auth, bitcoind_auth_file)?,
            &key_file,
            &state_file,
            fee,
            yes,
        )?),
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
            bitcoind_auth_file,
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
        assert_eq!(bitcoind_auth_file, None);
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
            described.contains("bitcoind-auth=<set on the command line>"),
            "presence of the credential is still reported, and so is the source that \
             put it in argv: {described}"
        );
    }

    /// A scratch directory unique to one test, removed by the test itself.
    fn scratch_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "chain-capture-main-{}-{tag}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("scratch directory is creatable");
        dir
    }

    /// A credential that would be conspicuous in any output that leaked it.
    const CREDENTIAL: &str = "rpcuser:s3cr3t-node-password";

    #[test]
    fn a_credential_file_is_read_trimmed_and_preferred_to_an_argv_value() {
        let dir = scratch_dir("auth-file");
        let path = dir.join("rpc.auth");
        std::fs::write(&path, format!("  {CREDENTIAL}\n")).expect("the file is writable");

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
            "--bitcoind-auth-file",
            &path.display().to_string(),
        ]))
        .expect("a mint with a credential file parses");
        let Command::Mint {
            bitcoind_auth,
            bitcoind_auth_file,
            ..
        } = &parsed.command
        else {
            panic!("expected Mint");
        };
        assert_eq!(*bitcoind_auth, None, "no credential is in argv");
        assert_eq!(bitcoind_auth_file.as_deref(), Some(path.as_path()));

        let resolved = resolve_bitcoind_auth(bitcoind_auth.clone(), bitcoind_auth_file.clone())
            .expect("the credential file resolves");
        assert_eq!(
            resolved.as_ref().map(Secret::expose),
            Some(CREDENTIAL),
            "surrounding whitespace is not part of the credential"
        );
        assert_eq!(
            format!("{resolved:?}"),
            "Some(<redacted>)",
            "the resolved credential renders redacted, so it cannot reach a log \
             through a Debug on anything holding it"
        );

        // The session summary still reports presence and never the value, and it
        // says which source supplied it.
        let described = describe(&parsed.command);
        assert!(
            !described.contains("s3cr3t-node-password") && !described.contains("rpcuser"),
            "the credential must never be echoed: {described}"
        );
        assert!(
            described.contains("bitcoind-auth=<set from file>"),
            "the summary says the credential came from a file: {described}"
        );

        std::fs::remove_dir_all(&dir).expect("scratch directory is removable");
    }

    #[test]
    fn naming_the_credential_twice_is_refused_rather_than_resolved_silently() {
        let dir = scratch_dir("auth-both");
        let path = dir.join("rpc.auth");
        std::fs::write(&path, CREDENTIAL).expect("the file is writable");

        let error = resolve_bitcoind_auth(Some(CREDENTIAL.to_string()), Some(path.clone()))
            .expect_err("two credentials is an ambiguity, not a preference");
        match &error {
            CaptureRunError::AmbiguousBitcoindAuth { path: named } => {
                assert!(named.ends_with("rpc.auth"), "{named}");
            }
            other => panic!("expected AmbiguousBitcoindAuth, got {other:?}"),
        }
        assert!(
            !error.to_string().contains(CREDENTIAL),
            "not even the ambiguity report echoes it: {error}"
        );

        std::fs::remove_dir_all(&dir).expect("scratch directory is removable");
    }

    #[test]
    fn an_unusable_credential_file_names_the_path_and_never_its_contents() {
        let dir = scratch_dir("auth-bad");
        let empty = dir.join("empty.auth");
        std::fs::write(&empty, "   \n").expect("the file is writable");

        let error = resolve_bitcoind_auth(None, Some(empty.clone()))
            .expect_err("an empty credential file is not a credential");
        assert!(
            matches!(error, CaptureRunError::CredentialFileEmpty { .. }),
            "got {error:?}"
        );
        assert!(error.to_string().contains("empty.auth"), "{error}");

        let absent = dir.join("absent.auth");
        let error = resolve_bitcoind_auth(None, Some(absent.clone()))
            .expect_err("a missing credential file is a failure, not an absent credential");
        assert!(
            matches!(error, CaptureRunError::CredentialFileUnreadable { .. }),
            "got {error:?}"
        );
        assert!(error.to_string().contains("absent.auth"), "{error}");

        // With neither source, there is no credential and no failure: a chain
        // that mines itself needs none.
        assert!(
            resolve_bitcoind_auth(None, None)
                .expect("no credential is not an error")
                .is_none()
        );

        std::fs::remove_dir_all(&dir).expect("scratch directory is removable");
    }

    #[test]
    fn the_help_text_prefers_the_credential_file_and_names_the_argv_exposure() {
        // The flag stays for a disposable local chain, so the documentation is
        // what steers an operator on any other one.
        let help = HELP_TEXT;
        assert!(help.contains("--bitcoind-auth-file"), "{help}");
        assert!(
            help.contains("PREFERRED"),
            "the file form is marked as preferred: {help}"
        );
        assert!(
            help.contains("shell history") && help.contains("`ps`"),
            "the inline form's exposure is stated where an operator reads it: {help}"
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
