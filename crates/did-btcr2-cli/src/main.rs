//! `did-btcr2` — command-line client for the `did:btcr2` DID method.
//!
//! This binary is a thin shell over the `did-btcr2-client` facade. It parses
//! subcommands and loads input (DIDs, patch files, secret
//! keys) and then dispatches into [`did_btcr2_client::Client`], which owns all
//! operation composition: the resolver FSM loop, beacon funding, fee resolution,
//! and broadcast. The CLI carries NO FSM pump, no UTXO/fee math, and no
//! announce/broadcast logic of its own; the sans-I/O core (`did-btcr2`) makes no
//! network calls, and all HTTP lives behind the facade's transport seam.

use did_btcr2::{
    ResolutionResult,
    document::{IntermediateDocument, SidecarData},
};
use did_btcr2_client::{BtcTransport, Client, Fee, ResolutionOptions, UreqTransport};
use error_iter::ErrorIter as _;
use onlyargs::{CliError, OnlyArgs, traits::*};
use onlyerror::Error;
use std::ffi::OsString;
use std::fs::File;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

mod keyload;

use keyload::KeySource;

/// CLI subcommands. `resolve` reads a DID; `update`/`deactivate` write a beacon
/// announcement. Each variant is one match arm in `run()` that builds a
/// [`Client`] and dispatches into the facade.
#[derive(Debug)]
enum Command {
    Create {
        network: Option<String>,
        key_file: Option<PathBuf>,
        key_stdin: bool,
        generate: bool,
        /// External (`x1`) creation: an externally-authored intermediate DID
        /// document. Mutually exclusive with `--generate`/key sources (this mode
        /// consumes NO signing key).
        intermediate_document: Option<PathBuf>,
        /// Write a ready-to-use `{"genesisDocument": ..}` sidecar for
        /// `resolve --sidecar` to this path (external mode only).
        sidecar_out: Option<PathBuf>,
    },
    Resolve {
        did: String,
        network: Option<String>,
        esplora_url: Option<String>,
        sidecar: Option<PathBuf>,
    },
    Update {
        did: String,
        patch: PathBuf,
        vm_id: Option<String>,
        key_file: Option<PathBuf>,
        key_stdin: bool,
        beacon_key_file: Option<PathBuf>,
        beacon_key_stdin: bool,
        fee: FeeArg,
        change: Option<String>,
        beacon: Option<String>,
        dry_run: bool,
        yes: bool,
        network: Option<String>,
        esplora_url: Option<String>,
        sidecar: Option<PathBuf>,
    },
    Deactivate {
        did: String,
        vm_id: Option<String>,
        key_file: Option<PathBuf>,
        key_stdin: bool,
        beacon_key_file: Option<PathBuf>,
        beacon_key_stdin: bool,
        fee: FeeArg,
        change: Option<String>,
        beacon: Option<String>,
        dry_run: bool,
        yes: bool,
        network: Option<String>,
        esplora_url: Option<String>,
        sidecar: Option<PathBuf>,
    },
}

/// How the broadcast fee is specified on the command line: an absolute sat
/// amount (`--fee`), a sat/vB rate (`--feerate`), or unset (a built-in default
/// absolute fee).
#[derive(Debug, Clone, PartialEq)]
enum FeeArg {
    /// `--fee <sats>`: an absolute fee in satoshis.
    Absolute(u64),
    /// `--feerate <sat/vB>`: a fee rate.
    Rate(f64),
    /// Neither flag supplied: use the built-in default absolute fee.
    Default,
}

impl FeeArg {
    /// The built-in default absolute fee (sats) when neither `--fee` nor
    /// `--feerate` is given. A conservative fixed amount for the small,
    /// single-input singleton announce tx.
    const DEFAULT_ABSOLUTE_SATS: u64 = 1_000;

    /// Convert to the facade's [`Fee`] model.
    fn to_fee(&self) -> Fee {
        match self {
            FeeArg::Absolute(n) => Fee::Absolute(*n),
            FeeArg::Rate(r) => Fee::Rate(*r),
            FeeArg::Default => Fee::Absolute(Self::DEFAULT_ABSOLUTE_SATS),
        }
    }
}

/// Parsed command-line arguments. Subcommand options are subcommand-scoped
/// so there are no global config flags.
#[derive(Debug)]
struct Args {
    command: Command,
}

/// Top-level CLI error. Argument parsing, the DID parse, key loading, JSON
/// (de)serialization, file I/O, and every facade call flow through here to
/// stderr + a nonzero exit; the CLI never panics on these.
#[derive(Debug, Error)]
enum CliRunError {
    /// Argument parsing error.
    Cli(#[from] CliError),

    /// Invalid DID identifier.
    DidParse(#[from] did_btcr2::identifier::Error),

    /// An error from the `did-btcr2-client` facade (resolve/update/deactivate:
    /// transport, funding, broadcast, or a core composition error).
    Client(#[from] did_btcr2_client::Error),

    /// Secret-key loading error (file/stdin/env, hex decode, key validity).
    Key(#[from] keyload::KeyError),

    /// JSON (de)serialization error (sidecar/patch parse or output build).
    Json(#[from] serde_json::Error),

    /// I/O error (opening the sidecar/patch file, prompting on stdin).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// `--key-stdin` (or `--beacon-key-stdin`) was combined with an interactive
    /// broadcast confirm: both would read stdin, so the key and the y/N answer
    /// cannot be disambiguated. Pass `--yes` (to skip the prompt) or use
    /// `--key-file` instead.
    #[error(
        "--key-stdin cannot be combined with an interactive confirm prompt; pass --yes or use --key-file"
    )]
    StdinConflict,

    /// `create` was given both `--generate` and a key source
    /// (`--key-file`/`--key-stdin`/`DIDBTCR2_KEY`). The two key modes are
    /// mutually exclusive: `--generate` mints a fresh secret, while a key source
    /// derives the public key from a secret you already hold.
    #[error(
        "use either --generate or a key source (--key-file/--key-stdin/DIDBTCR2_KEY), not both"
    )]
    CreateKeySourceConflict,
}

impl OnlyArgs for Args {
    const VERSION: &'static str = onlyargs::impl_version!();

    fn help() -> ! {
        let help_text = concat!(
            env!("CARGO_PKG_NAME"),
            " v",
            env!("CARGO_PKG_VERSION"),
            "\n",
            "Command-line client for the did:btcr2 DID method.\n\n",
            "Usage:\n  did-btcr2 [flags] <command> [command args]\n",
            "\nFlags:\n",
            "  -h --help     Show this help message.\n",
            "  -V --version  Show the application version.\n",
            "\nCommands:\n",
            "  create                       Mint a did:btcr2 document OFFLINE and print\n",
            "                               it. No broadcast; no network calls. Prints the\n",
            "                               DID identifier and the document as JSON.\n",
            "                               Key-based (default) mints a k1 DID; external\n",
            "                               (--intermediate-document) mints an x1 DID.\n",
            "    --generate                  Mint a fresh secp256k1 key; the generated\n",
            "                                secret is printed (store it — it controls\n",
            "                                the DID).\n",
            "    --key-file <file>           Derive the pubkey from this secret key file\n",
            "                                (raw 32-byte lowercase hex); no secret echoed.\n",
            "    --key-stdin                 Read that secret key from stdin instead\n",
            "                                (or set DIDBTCR2_KEY).\n",
            "    --intermediate-document <f> Mint an external x1 DID from this\n",
            "                                externally-authored intermediate document.\n",
            "                                Consumes NO signing key (mutually exclusive\n",
            "                                with --generate/--key-file/--key-stdin). The\n",
            "                                x1 DID is not deterministically resolvable.\n",
            "    --sidecar-out <file>        (external mode) Write a {\"genesisDocument\":..}\n",
            "                                sidecar for a later `resolve --sidecar <file>`.\n",
            "                                An OUTPUT, distinct from resolve's --sidecar.\n",
            "    --network <net>             Network: testnet (default), signet, mainnet,\n",
            "                                or mutinynet.\n",
            "\n",
            "  resolve <did>                Resolve a did:btcr2 identifier and print the\n",
            "                               DID resolution result as JSON.\n",
            "    --network <net>             Network: testnet (default), signet, mainnet,\n",
            "                                or mutinynet.\n",
            "    --esplora-url <url>         Esplora base URL override (no trailing slash).\n",
            "    --sidecar <file>            Path to a sidecar data JSON file.\n",
            "\n",
            "  update <did>                 Update a did:btcr2 document via a beacon signal.\n",
            "    --patch <file.json>         REQUIRED. RFC-6902 JSON Patch to apply.\n",
            "    --vm <id>                   Verification method id to sign with\n",
            "                                (default: <did>#initialKey).\n",
            "    --key-file <file>           Secret key file (raw 32-byte lowercase hex).\n",
            "    --key-stdin                 Read the secret key from stdin.\n",
            "                                (or set DIDBTCR2_KEY)\n",
            "    --beacon-key-file <file>    Beacon secret key file (defaults to the key).\n",
            "    --beacon-key-stdin          Read the beacon secret key from stdin.\n",
            "                                (or set DIDBTCR2_BEACON_KEY)\n",
            "    --fee <sats>                Absolute fee in satoshis.\n",
            "    --feerate <sat/vB>          Fee rate (single-input only).\n",
            "    --change <addr>             Change address (defaults to the beacon address).\n",
            "    --beacon <type>             Beacon to fund: P2PKH, P2WPKH (default), P2TR.\n",
            "    --dry-run                   Build and print the tx without broadcasting.\n",
            "    --yes                       Skip the broadcast confirm prompt.\n",
            "    --network / --esplora-url / --sidecar   As for resolve.\n",
            "\n",
            "  deactivate <did>             Deactivate a did:btcr2 document via a beacon\n",
            "                               signal. Same key/fee/broadcast flags as update.\n",
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
                "A command is required ('create', 'resolve', 'update', or 'deactivate')",
            )));
        }

        let subcommand = positional_args[0].to_string_lossy().to_string();
        let sub_args = positional_args.into_iter().skip(1);

        let command = match subcommand.as_ref() {
            "create" => parse_create(sub_args)?,
            "resolve" => parse_resolve(sub_args)?,
            "update" => parse_write(sub_args, WriteKind::Update)?,
            "deactivate" => parse_write(sub_args, WriteKind::Deactivate)?,
            _ => {
                return Err(CliError::MissingRequired(String::from(
                    "Unknown command. Expected 'create', 'resolve', 'update', or 'deactivate'",
                )));
            }
        };

        Ok(Self { command })
    }
}

/// Parse the `create` subcommand.
///
/// Two creation modes:
/// - key-based (default): `--network <net>`, the key-input trio (`--key-file
///   <path>` / `--key-stdin`, with `DIDBTCR2_KEY` consulted at run time), and
///   `--generate`.
/// - external (`x1`): `--intermediate-document <file>` mints an `x1` DID from an
///   externally-authored intermediate document and consumes NO signing key
///   (combining it with `--generate` or any key source is a conflict).
///   `--sidecar-out <file>` optionally writes a `{"genesisDocument": ..}` sidecar
///   for a later `resolve --sidecar <file>`.
///
/// There is NO positional `<did>` and NO `--key <hex>` arm (argv-secret hygiene).
/// `--sidecar-out` is an OUTPUT distinct from resolve's `--sidecar` INPUT; other
/// funding/broadcast flags (`--esplora-url`, `--patch`, `--fee`, …) do not apply
/// to the offline `create` and are rejected as Unknown.
fn parse_create(mut sub_args: impl Iterator<Item = OsString>) -> Result<Command, CliError> {
    let mut network: Option<String> = None;
    let mut key_file: Option<PathBuf> = None;
    let mut key_stdin = false;
    let mut generate = false;
    let mut intermediate_document: Option<PathBuf> = None;
    let mut sidecar_out: Option<PathBuf> = None;
    while let Some(arg) = sub_args.next() {
        match arg.to_str() {
            Some(p @ "--network") => network = Some(sub_args.next().parse_str(p)?),
            Some(p @ "--key-file") => key_file = Some(sub_args.next().parse_path(p)?),
            Some("--key-stdin") => key_stdin = true,
            Some("--generate") => generate = true,
            Some(p @ "--intermediate-document") => {
                intermediate_document = Some(sub_args.next().parse_path(p)?)
            }
            Some(p @ "--sidecar-out") => sidecar_out = Some(sub_args.next().parse_path(p)?),
            _ => return Err(CliError::Unknown(arg)),
        }
    }
    Ok(Command::Create {
        network,
        key_file,
        key_stdin,
        generate,
        intermediate_document,
        sidecar_out,
    })
}

/// Map a `--network` string to a [`did_btcr2::identifier::Network`].
///
/// `None` and `"testnet"` both map to `TestnetV3` (the CLI default); `"signet"`,
/// `"mainnet"`, and `"mutinynet"` map to their variants. Anything else is a
/// typed [`did_btcr2_client::Error::UnknownNetwork`] (surfaced via
/// `CliRunError::Client`), mirroring how [`beacon_index`] handles an unknown
/// beacon type — the unknown string is NOT laundered through another variant.
fn network_from_str(network: Option<&str>) -> Result<did_btcr2::identifier::Network, CliRunError> {
    use did_btcr2::identifier::Network;
    match network {
        None | Some("testnet") => Ok(Network::TestnetV3),
        Some("signet") => Ok(Network::Signet),
        Some("mainnet") => Ok(Network::Mainnet),
        Some("mutinynet") => Ok(Network::Mutinynet),
        Some(other) => Err(CliRunError::Client(
            did_btcr2_client::Error::UnknownNetwork(other.to_string()),
        )),
    }
}

/// Which key the offline `create` uses: a freshly generated keypair
/// (`--generate`) or a public key derived from a supplied secret (the key-input
/// trio). The two are mutually exclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CreateKeyMode {
    /// `--generate`: mint a fresh keypair; print the generated secret.
    Generate,
    /// A key source was supplied: derive the public key from it; no secret
    /// echoed.
    Supplied,
}

/// Decide the key mode for `create` from the two boolean inputs, keeping the
/// conflict/missing-source logic in one pure, directly-testable place.
///
/// - both `--generate` and a key source → [`CliRunError::CreateKeySourceConflict`].
/// - neither → the typed missing-source error (reusing
///   [`keyload::KeyError::MissingSource`] so the wording matches
///   `update`/`deactivate`).
fn resolve_create_key_mode(
    generate: bool,
    key_source_given: bool,
) -> Result<CreateKeyMode, CliRunError> {
    match (generate, key_source_given) {
        (true, true) => Err(CliRunError::CreateKeySourceConflict),
        (true, false) => Ok(CreateKeyMode::Generate),
        (false, true) => Ok(CreateKeyMode::Supplied),
        (false, false) => Err(CliRunError::Key(keyload::KeyError::MissingSource(
            "DIDBTCR2_KEY",
        ))),
    }
}

/// Parse the `resolve` subcommand.
fn parse_resolve(mut sub_args: impl Iterator<Item = OsString>) -> Result<Command, CliError> {
    let mut did: Option<String> = None;
    let mut network: Option<String> = None;
    let mut esplora_url: Option<String> = None;
    let mut sidecar: Option<PathBuf> = None;
    while let Some(arg) = sub_args.next() {
        match arg.to_str() {
            Some(p @ "--network") => network = Some(sub_args.next().parse_str(p)?),
            Some(p @ "--esplora-url") => esplora_url = Some(sub_args.next().parse_str(p)?),
            Some(p @ "--sidecar") => sidecar = Some(sub_args.next().parse_path(p)?),
            Some(s) if !s.starts_with('-') => {
                if did.is_some() {
                    return Err(CliError::Unknown(arg));
                }
                did = Some(s.to_string());
            }
            _ => return Err(CliError::Unknown(arg)),
        }
    }
    Ok(Command::Resolve {
        did: did.ok_or_else(|| CliError::MissingRequired("did".to_string()))?,
        network,
        esplora_url,
        sidecar,
    })
}

/// Which write subcommand is being parsed (they share a flag set).
#[derive(Debug, Clone, Copy)]
enum WriteKind {
    Update,
    Deactivate,
}

/// Parse the `update` / `deactivate` subcommands (a shared flag set; `update`
/// additionally requires `--patch`).
fn parse_write(
    mut sub_args: impl Iterator<Item = OsString>,
    kind: WriteKind,
) -> Result<Command, CliError> {
    let mut did: Option<String> = None;
    let mut patch: Option<PathBuf> = None;
    let mut vm_id: Option<String> = None;
    let mut key_file: Option<PathBuf> = None;
    let mut key_stdin = false;
    let mut beacon_key_file: Option<PathBuf> = None;
    let mut beacon_key_stdin = false;
    let mut fee = FeeArg::Default;
    let mut change: Option<String> = None;
    let mut beacon: Option<String> = None;
    let mut dry_run = false;
    let mut yes = false;
    let mut network: Option<String> = None;
    let mut esplora_url: Option<String> = None;
    let mut sidecar: Option<PathBuf> = None;

    while let Some(arg) = sub_args.next() {
        match arg.to_str() {
            Some(p @ "--patch") => patch = Some(sub_args.next().parse_path(p)?),
            Some(p @ "--vm") => vm_id = Some(sub_args.next().parse_str(p)?),
            Some(p @ "--key-file") => key_file = Some(sub_args.next().parse_path(p)?),
            Some("--key-stdin") => key_stdin = true,
            Some(p @ "--beacon-key-file") => beacon_key_file = Some(sub_args.next().parse_path(p)?),
            Some("--beacon-key-stdin") => beacon_key_stdin = true,
            Some(p @ "--fee") => fee = FeeArg::Absolute(sub_args.next().parse_int::<u64, _>(p)?),
            Some(p @ "--feerate") => fee = FeeArg::Rate(sub_args.next().parse_float::<f64, _>(p)?),
            Some(p @ "--change") => change = Some(sub_args.next().parse_str(p)?),
            Some(p @ "--beacon") => beacon = Some(sub_args.next().parse_str(p)?),
            Some("--dry-run") => dry_run = true,
            Some("--yes") => yes = true,
            Some(p @ "--network") => network = Some(sub_args.next().parse_str(p)?),
            Some(p @ "--esplora-url") => esplora_url = Some(sub_args.next().parse_str(p)?),
            Some(p @ "--sidecar") => sidecar = Some(sub_args.next().parse_path(p)?),
            Some(s) if !s.starts_with('-') => {
                if did.is_some() {
                    return Err(CliError::Unknown(arg));
                }
                did = Some(s.to_string());
            }
            _ => return Err(CliError::Unknown(arg)),
        }
    }

    let did = did.ok_or_else(|| CliError::MissingRequired("did".to_string()))?;
    match kind {
        WriteKind::Update => {
            let patch = patch.ok_or_else(|| CliError::MissingRequired("--patch".to_string()))?;
            Ok(Command::Update {
                did,
                patch,
                vm_id,
                key_file,
                key_stdin,
                beacon_key_file,
                beacon_key_stdin,
                fee,
                change,
                beacon,
                dry_run,
                yes,
                network,
                esplora_url,
                sidecar,
            })
        }
        WriteKind::Deactivate => Ok(Command::Deactivate {
            did,
            vm_id,
            key_file,
            key_stdin,
            beacon_key_file,
            beacon_key_stdin,
            fee,
            change,
            beacon,
            dry_run,
            yes,
            network,
            esplora_url,
            sidecar,
        }),
    }
}

/// Build the spec-key resolution JSON triple.
///
/// `ResolutionResult` does NOT implement `Serialize`, so this uses
/// `serde_json::json!` at the build site. Output is byte-identical to the
/// pre-facade CLI.
fn build_resolution_json(result: &ResolutionResult) -> serde_json::Value {
    serde_json::json!({
        "didResolutionMetadata": {},
        "didDocument": result.document.as_ref(),
        "didDocumentMetadata": result.document_metadata,
    })
}

/// Map a `--beacon` type name to its index in the document's default beacon
/// ordering (0 = P2PKH, 1 = P2WPKH, 2 = P2TR). The default is P2WPKH (index 1),
/// which the default singleton DID key can spend.
fn beacon_index(beacon: Option<&str>) -> Result<usize, CliRunError> {
    match beacon.map(str::to_ascii_uppercase).as_deref() {
        None | Some("P2WPKH") => Ok(1),
        Some("P2PKH") => Ok(0),
        Some("P2TR") => Ok(2),
        Some(other) => Err(CliRunError::Client(
            did_btcr2_client::Error::UnknownBeaconType(other.to_string()),
        )),
    }
}

/// Build a sidecar resolution options bundle from the optional sidecar file.
fn load_sidecar(sidecar: Option<PathBuf>) -> Result<ResolutionOptions, CliRunError> {
    let sidecar_data = match sidecar {
        Some(path) => {
            let file = File::open(path)?;
            Some(serde_json::from_reader::<_, SidecarData>(file)?)
        }
        None => None,
    };
    Ok(ResolutionOptions {
        sidecar_data,
        ..Default::default()
    })
}

/// Run the `resolve` subcommand: dispatch into the facade and print the spec
/// resolution triple. The facade owns the chain-tip fetch and the FSM loop.
fn run_resolve(
    did_str: &str,
    network: Option<&str>,
    esplora_url: Option<String>,
    sidecar: Option<PathBuf>,
) -> Result<(), CliRunError> {
    let did: did_btcr2::identifier::Did = did_str.parse()?;
    let opts = load_sidecar(sidecar)?;
    let client = Client::with_network(
        network.unwrap_or("testnet"),
        esplora_url,
        UreqTransport::new(),
    )?;
    let result = client.resolve(&did, opts)?;
    let out = build_resolution_json(&result);
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

/// Mint a genesis document via the facade and print the DID identifier + the
/// document as pretty JSON.
///
/// Generic over the transport so the dispatch test can inject an in-process fake
/// and assert that `create` issues ZERO transport calls — the facade's
/// `create` is pure composition and never touches the transport. Returns the
/// parsed [`did_btcr2::identifier::Did`] (already printed) so a caller/test can
/// assert on it.
fn create_and_print<T: BtcTransport>(
    client: &Client<T>,
    public_key: &did_btcr2::key::PublicKey,
    network: did_btcr2::identifier::Network,
) -> Result<did_btcr2::identifier::Did, CliRunError> {
    let doc = client.create(public_key, network)?;
    let id = doc.as_ref()["id"].as_str().ok_or_else(|| {
        CliRunError::DidParse(did_btcr2::identifier::Error::InvalidDidFormat(
            "genesis document has no string \"id\" field".to_string(),
        ))
    })?;
    let did: did_btcr2::identifier::Did = id.parse()?;
    println!("{id}");
    println!("{}", serde_json::to_string_pretty(doc.as_ref())?);
    Ok(did)
}

/// Mint an external (`x1`) DID via the facade and print the DID identifier + the
/// initial document as pretty JSON, plus a stderr note that the `x1` DID is not
/// deterministically resolvable and must be resolved with `resolve --sidecar`.
///
/// If `sidecar_out` is `Some`, writes a `{"genesisDocument": <intermediate
/// placeholder doc>}` payload — the INTERMEDIATE (placeholder-DID) document the
/// facade was given, NOT the placeholder-substituted initial document — which is
/// exactly what `SidecarData`'s `genesisDocument` wire key and the resolve-side
/// bridge consume. No secret is printed (external mode has none).
///
/// Generic over the transport so tests can inject an in-process fake and assert
/// zero transport calls. Returns the minted DID (already printed).
fn create_external_and_print<T: BtcTransport>(
    client: &Client<T>,
    intermediate_json: serde_json::Value,
    network: did_btcr2::identifier::Network,
    sidecar_out: Option<PathBuf>,
) -> Result<did_btcr2::identifier::Did, CliRunError> {
    // A structural error in the intermediate document is a core document error;
    // route it through the facade's `Error::Core` so it surfaces as a typed
    // `CliRunError::Client` (no new CLI error variant, no panic).
    let intermediate = IntermediateDocument::from_json_value(intermediate_json.clone(), network)
        .map_err(did_btcr2_client::Error::from)?;
    let (did, doc) = client.create_external(intermediate, network)?;
    println!("{}", did.encode());
    println!("{}", serde_json::to_string_pretty(doc.as_ref())?);
    eprintln!(
        "this x1 DID is not deterministically resolvable; resolve it with: \
         did-btcr2 resolve --sidecar <file>"
    );

    if let Some(out) = sidecar_out {
        let sidecar = serde_json::json!({ "genesisDocument": intermediate_json });
        let mut file = File::create(out)?;
        file.write_all(serde_json::to_string_pretty(&sidecar)?.as_bytes())?;
    }

    Ok(did)
}

/// Run the `create` subcommand: mint a genesis `did:btcr2` document OFFLINE and
/// print the DID + document (+ the generated secret with `--generate`).
///
/// `create` makes ZERO transport calls — the facade's `create`/`create_external`
/// are pure composition — so the `Client` is built only to reach those methods;
/// its URL and transport are never used.
///
/// `--intermediate-document` selects the external (`x1`) mode, which consumes no
/// signing key; combining it with `--generate` or any key source is a conflict.
fn run_create(
    network: Option<&str>,
    key_file: Option<PathBuf>,
    key_stdin: bool,
    generate: bool,
    intermediate_document: Option<PathBuf>,
    sidecar_out: Option<PathBuf>,
) -> Result<(), CliRunError> {
    // A key source is "given" if any of file/stdin/env is present, mirroring
    // KeySource precedence (file > stdin > env) and the conflict/missing
    // semantics.
    let key_source_given = key_file.is_some() || key_stdin || std::env::var("DIDBTCR2_KEY").is_ok();

    // External (x1) mode: mint from an intermediate document with NO signing key.
    if let Some(path) = intermediate_document {
        // A key source or --generate is a conflict: the external document is
        // prepared out-of-band and takes no key. Reject BEFORE reading any key.
        if generate || key_source_given {
            return Err(CliRunError::CreateKeySourceConflict);
        }
        let net = network_from_str(network)?;
        // Load the raw intermediate JSON (typed Io/Json errors, no panic). The
        // facade re-parses/validates it into an IntermediateDocument; the raw
        // value is also what a --sidecar-out genesisDocument carries verbatim.
        let intermediate_json: serde_json::Value = serde_json::from_reader(File::open(path)?)?;
        // The external facade never touches the transport, so URL/transport are
        // unused; build the client the same way the other arms do.
        let client =
            Client::with_network(network.unwrap_or("testnet"), None, UreqTransport::new())?;
        create_external_and_print(&client, intermediate_json, net, sidecar_out)?;
        return Ok(());
    }

    let mode = resolve_create_key_mode(generate, key_source_given)?;

    let secp = secp256k1::Secp256k1::new();
    // `generated_secret` is `Some` only in the --generate path, printed last.
    let (public_key, generated_secret) = match mode {
        CreateKeyMode::Generate => {
            // Generate a raw secp256k1 key here (not did_btcr2::key::KeyPair):
            // the --generate path must print the secret bytes as hex, and the
            // crate newtype intentionally does not expose its bytes publicly.
            // Keeping the secret-bytes-printing local to the CLI avoids widening
            // the newtype's public surface. Mint from OsRng (the OS CSPRNG),
            // matching the crate newtype's SecretKey::generate — one RNG source
            // for the "mint a signing key" operation, not thread_rng here and
            // OsRng there.
            let sk = secp256k1::SecretKey::new(&mut secp256k1::rand::rngs::OsRng);
            (sk.public_key(&secp), Some(sk))
        }
        CreateKeyMode::Supplied => {
            let sk = KeySource {
                file: key_file,
                stdin: key_stdin,
                env_var: "DIDBTCR2_KEY",
            }
            .load()?;
            (sk.public_key(&secp), None)
        }
    };

    let net = network_from_str(network)?;

    // `create` invokes no transport, so the URL/transport are never touched;
    // build the client the same way the other arms do rather than adding a
    // bespoke no-transport constructor.
    let client = Client::with_network(network.unwrap_or("testnet"), None, UreqTransport::new())?;

    create_and_print(&client, &public_key, net)?;

    if let Some(secret_key) = generated_secret {
        eprintln!("store this secret — it controls the DID and is shown only once:");
        println!("{}", hex::encode(secret_key.secret_bytes()));
    }
    Ok(())
}

/// The two write operations share their entire dispatch shape except the final
/// facade call; this carries the parsed-and-loaded arguments.
struct WriteDispatch {
    did: String,
    /// `Some(patch)` for update; `None` for deactivate (the patch is implicit).
    patch: Option<PathBuf>,
    vm_id: Option<String>,
    key: KeySource,
    beacon_key_file: Option<PathBuf>,
    beacon_key_stdin: bool,
    fee: FeeArg,
    change: Option<String>,
    beacon: Option<String>,
    dry_run: bool,
    yes: bool,
    network: Option<String>,
    esplora_url: Option<String>,
    sidecar: Option<PathBuf>,
}

/// Run a write operation (`update` or `deactivate`) through the facade.
///
/// Order of operations:
/// 1. Guard the stdin double-consume hazard FIRST, before any stdin read.
/// 2. Load the update + beacon keys (file/stdin/env; beacon defaults to update).
/// 3. Resolve the CURRENT document to obtain its `document_metadata.version_id`
///    — the `current_version_id` the facade needs (never hardcoded).
/// 4. `--dry-run`: build the tx via the facade and print hex + txid; no POST.
/// 5. real run: print a summary, prompt `y/N` (unless `--yes`), then dispatch
///    into `client.update` / `client.deactivate` and print the broadcast txid.
fn run_write(d: WriteDispatch) -> Result<(), CliRunError> {
    // Step 1: stdin guard. A stdin key cannot coexist with an interactive
    // prompt. The key reads stdin only when no file/env source supersedes it.
    let key_uses_stdin = d.key.reads_stdin();
    keyload::guard_stdin_confirm(key_uses_stdin, d.yes, d.dry_run)?;

    // Step 2: load keys. The beacon key defaults to the update key. Load
    // the update key first; the beacon key is loaded only if a source is given.
    let beacon_key_source_given = d.beacon_key_file.is_some() || d.beacon_key_stdin;
    if beacon_key_source_given && d.beacon_key_stdin && d.key.reads_stdin() {
        // Two distinct stdin readers (update key + beacon key) also cannot
        // coexist — surface the same typed conflict rather than reading twice.
        return Err(CliRunError::StdinConflict);
    }
    // The DID-update key is loaded as a raw secp key by keyload, then converted
    // to the crate-owned newtype at this boundary (the update-signing path takes
    // the newtype). The beacon key signs the Bitcoin announcement tx and stays a
    // raw secp key; when no separate beacon key is given it reuses the loaded
    // update key (secp `SecretKey` is `Copy`).
    let loaded_update_sk = d.key.load()?;
    let beacon_sk = if beacon_key_source_given {
        KeySource {
            file: d.beacon_key_file,
            stdin: d.beacon_key_stdin,
            env_var: "DIDBTCR2_BEACON_KEY",
        }
        .load()?
    } else {
        loaded_update_sk
    };
    // `loaded_update_sk` is already a valid secp256k1 secret key, so its 32
    // bytes are a valid scalar and this conversion cannot fail. Use the array
    // constructor (not `.to_vec()`): a heap `Vec<u8>` of raw secret bytes would
    // be dropped by the ordinary `Vec` destructor, which does NOT scrub its
    // buffer, leaving a copy of the secret on the heap. The array form copies
    // only onto the stack (unavoidable, since `secret_bytes()` returns an array).
    let update_sk = did_btcr2::key::SecretKey::try_from(loaded_update_sk.secret_bytes())
        .expect("bytes from a valid secp256k1::SecretKey are a valid secret key");

    let did: did_btcr2::identifier::Did = d.did.parse()?;
    let vm_id = d
        .vm_id
        .unwrap_or_else(|| format!("{}#initialKey", did.encode()));
    let beacon_idx = beacon_index(d.beacon.as_deref())?;
    let fee = d.fee.to_fee();
    let change = match d.change {
        Some(addr) => {
            // The change output is spent on the DID's network, so the --change
            // address must match it (nothing downstream re-checks this).
            let btc_network = esploda::bitcoin::Network::try_from(did.components().network())
                .map_err(did_btcr2_client::Error::from)?;
            Some(parse_change_address(&addr, btc_network)?)
        }
        None => None,
    };

    let client = Client::with_network(
        d.network.as_deref().unwrap_or("testnet"),
        d.esplora_url,
        UreqTransport::new(),
    )?;

    execute_write(
        &client,
        WriteParams {
            did,
            patch: d.patch,
            vm_id,
            update_sk,
            beacon_sk,
            beacon_idx,
            fee,
            change,
            dry_run: d.dry_run,
            yes: d.yes,
            sidecar: d.sidecar,
        },
    )
}

/// Loaded-and-validated parameters for a write dispatch, transport-agnostic so
/// [`execute_write`] can be driven by either the production transport or an
/// in-process fake.
struct WriteParams {
    did: did_btcr2::identifier::Did,
    /// `Some(path)` for update; `None` for deactivate.
    patch: Option<PathBuf>,
    vm_id: String,
    update_sk: did_btcr2::key::SecretKey,
    beacon_sk: secp256k1::SecretKey,
    beacon_idx: usize,
    fee: Fee,
    change: Option<esploda::bitcoin::Address>,
    dry_run: bool,
    yes: bool,
    sidecar: Option<PathBuf>,
}

/// Dispatch a write operation into the facade. Generic over the transport so a
/// fake can assert that a `--dry-run` issues zero `POST /tx`.
///
/// This is orchestration only: it resolves the current document for
/// its `version_id`, constructs the signed update for the
/// `--dry-run` preview/print, and otherwise hands everything to
/// `client.update` / `client.deactivate`. No FSM pump, UTXO/fee math, or
/// broadcast logic lives here — those are the facade's.
fn execute_write<T: BtcTransport>(client: &Client<T>, p: WriteParams) -> Result<(), CliRunError> {
    // Resolve the current document for its version_id. Any
    // --sidecar data is threaded in so a DID with prior sidecar-only updates
    // resolves to its true current state before the next update is built.
    let current = client.resolve(&p.did, load_sidecar(p.sidecar)?)?;
    let current_version_id = current.document_metadata.version_id;
    let doc = did_btcr2::Document::from_json_value(current.document.as_ref().clone())
        .map_err(did_btcr2_client::Error::from)?;
    let target = current_version_id
        .checked_add(1)
        .ok_or(CliRunError::Client(
            did_btcr2_client::Error::VersionIdOverflow,
        ))?;

    // Read the patch once (update only); deactivate has an implicit patch.
    let patch = match &p.patch {
        Some(path) => {
            let patch_json = std::fs::read_to_string(path)?;
            Some(serde_json::from_str::<did_btcr2_client::Patch>(
                &patch_json,
            )?)
        }
        None => None,
    };

    // Build the signed update so a --dry-run can print the tx without broadcast,
    // and so the real run can show a pre-confirm summary.
    let signed = match patch.clone() {
        Some(patch) => doc
            .construct_signed_update(patch, target, &p.vm_id, p.update_sk)
            .map_err(did_btcr2_client::Error::from)?,
        None => doc
            .deactivate(&p.vm_id, p.update_sk, target)
            .map_err(did_btcr2_client::Error::from)?,
    };

    // --dry-run — build the tx via the facade, print hex + txid, no POST.
    if p.dry_run {
        let tx =
            client.build_update_tx(&doc, signed, p.beacon_idx, p.fee, p.change, p.beacon_sk)?;
        let raw = esploda::bitcoin::consensus::encode::serialize(tx.as_tx());
        println!("dry-run: tx not broadcast");
        println!("txid: {}", tx.as_tx().txid());
        println!("raw:  {}", hex::encode(raw));
        return Ok(());
    }

    // Real run: print a summary, confirm, then dispatch into the facade.
    let preview = client.build_update_tx(
        &doc,
        signed,
        p.beacon_idx,
        p.fee,
        p.change.clone(),
        p.beacon_sk,
    )?;
    print_tx_summary(&preview);

    if !p.yes && !confirm_broadcast()? {
        println!("aborted: not broadcast");
        return Ok(());
    }

    // Broadcast the EXACT tx the user just confirmed. Calling
    // client.update / client.deactivate here would re-resolve, re-fund, and
    // rebuild the tx — if the confirmed UTXO set changed between the preview's
    // /utxo GET and that second GET, the broadcast tx (and its txid) would differ
    // from the one shown in the summary. Broadcasting `preview` makes the
    // confirmed bytes and the broadcast bytes identical.
    let txid = client.broadcast(&preview)?;
    println!("broadcast txid: {txid}");
    Ok(())
}

/// Parse a `--change` address string into a Bitcoin address checked against the
/// DID's network.
///
/// A wrong-network change address is NOT caught anywhere downstream: the funding
/// path only calls `change_address.script_pubkey()` (no network comparison), so a
/// mainnet `--change` on a testnet DID would silently produce an unspendable
/// change output. The CLI already knows the target network, so require it here.
fn parse_change_address(
    addr: &str,
    network: esploda::bitcoin::Network,
) -> Result<esploda::bitcoin::Address, CliRunError> {
    use std::str::FromStr as _;
    esploda::bitcoin::Address::from_str(addr)
        .and_then(|a| a.require_network(network))
        .map_err(|e| {
            CliRunError::Io(std::io::Error::other(format!(
                "invalid --change address: {e}"
            )))
        })
}

/// Print a one-paragraph transaction summary before the confirm prompt.
fn print_tx_summary(tx: &did_btcr2::SignedBeaconTx) {
    let bitcoin_tx = tx.as_tx();
    println!("about to broadcast a beacon-signal transaction:");
    println!("  txid:    {}", bitcoin_tx.txid());
    println!("  inputs:  {}", bitcoin_tx.input.len());
    println!("  outputs: {}", bitcoin_tx.output.len());
    println!("  vsize:   {} vB", bitcoin_tx.vsize());
}

/// Prompt `y/N` on stderr and read a single answer from stdin. Anything other
/// than an explicit `y`/`yes` (case-insensitive) is a "no".
fn confirm_broadcast() -> Result<bool, CliRunError> {
    eprint!("broadcast this transaction? [y/N] ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    let answer = answer.trim().to_ascii_lowercase();
    Ok(answer == "y" || answer == "yes")
}

fn run() -> Result<(), CliRunError> {
    let args: Args = onlyargs::parse()?;
    match args.command {
        Command::Create {
            network,
            key_file,
            key_stdin,
            generate,
            intermediate_document,
            sidecar_out,
        } => run_create(
            network.as_deref(),
            key_file,
            key_stdin,
            generate,
            intermediate_document,
            sidecar_out,
        ),
        Command::Resolve {
            did,
            network,
            esplora_url,
            sidecar,
        } => run_resolve(&did, network.as_deref(), esplora_url, sidecar),
        Command::Update {
            did,
            patch,
            vm_id,
            key_file,
            key_stdin,
            beacon_key_file,
            beacon_key_stdin,
            fee,
            change,
            beacon,
            dry_run,
            yes,
            network,
            esplora_url,
            sidecar,
        } => run_write(WriteDispatch {
            did,
            patch: Some(patch),
            vm_id,
            key: KeySource {
                file: key_file,
                stdin: key_stdin,
                env_var: "DIDBTCR2_KEY",
            },
            beacon_key_file,
            beacon_key_stdin,
            fee,
            change,
            beacon,
            dry_run,
            yes,
            network,
            esplora_url,
            sidecar,
        }),
        Command::Deactivate {
            did,
            vm_id,
            key_file,
            key_stdin,
            beacon_key_file,
            beacon_key_stdin,
            fee,
            change,
            beacon,
            dry_run,
            yes,
            network,
            esplora_url,
            sidecar,
        } => run_write(WriteDispatch {
            did,
            patch: None,
            vm_id,
            key: KeySource {
                file: key_file,
                stdin: key_stdin,
                env_var: "DIDBTCR2_KEY",
            },
            beacon_key_file,
            beacon_key_stdin,
            fee,
            change,
            beacon,
            dry_run,
            yes,
            network,
            esplora_url,
            sidecar,
        }),
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
        "did:btcr2:k1qqpuwwde82nennsavvf0lqfnlvx7frrgzs57lchr02q8mz49qzaaxmqphnvcx";

    fn args_from_strings(strings: &[&str]) -> Vec<OsString> {
        strings.iter().map(OsString::from).collect()
    }

    #[test]
    fn test_parse_resolve_command() {
        let parsed = Args::parse(args_from_strings(&["resolve", SAMPLE_DID])).unwrap();
        assert!(matches!(parsed.command, Command::Resolve { .. }));
        let Command::Resolve { did, .. } = parsed.command else {
            panic!("expected Resolve");
        };
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
        let Command::Resolve { network, .. } = parsed.command else {
            panic!("expected Resolve");
        };
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
        let Command::Resolve { esplora_url, .. } = parsed.command else {
            panic!("expected Resolve");
        };
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
        let Command::Resolve { sidecar, .. } = parsed.command else {
            panic!("expected Resolve");
        };
        assert_eq!(sidecar, Some(PathBuf::from("/tmp/s.json")));
    }

    #[test]
    fn test_parse_sidecar_absent_is_none() {
        let parsed = Args::parse(args_from_strings(&["resolve", SAMPLE_DID])).unwrap();
        let Command::Resolve { sidecar, .. } = parsed.command else {
            panic!("expected Resolve");
        };
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
    fn parse_update_command() {
        let parsed = Args::parse(args_from_strings(&[
            "update",
            SAMPLE_DID,
            "--patch",
            "p.json",
            "--key-file",
            "k.hex",
            "--fee",
            "500",
        ]))
        .unwrap();
        let Command::Update {
            did,
            patch,
            key_file,
            fee,
            ..
        } = parsed.command
        else {
            panic!("expected an Update command");
        };
        assert_eq!(did, SAMPLE_DID);
        assert_eq!(patch, PathBuf::from("p.json"));
        assert_eq!(key_file, Some(PathBuf::from("k.hex")));
        assert_eq!(fee, FeeArg::Absolute(500));
    }

    #[test]
    fn parse_update_requires_patch() {
        // `update` without --patch is a missing-required error.
        assert!(matches!(
            Args::parse(args_from_strings(&[
                "update",
                SAMPLE_DID,
                "--key-file",
                "k.hex"
            ]))
            .unwrap_err(),
            CliError::MissingRequired(_)
        ));
    }

    #[test]
    fn parse_deactivate_command() {
        let parsed = Args::parse(args_from_strings(&[
            "deactivate",
            SAMPLE_DID,
            "--key-stdin",
            "--yes",
            "--feerate",
            "2.5",
        ]))
        .unwrap();
        let Command::Deactivate {
            did,
            key_stdin,
            yes,
            fee,
            ..
        } = parsed.command
        else {
            panic!("expected a Deactivate command");
        };
        assert_eq!(did, SAMPLE_DID);
        assert!(key_stdin);
        assert!(yes);
        assert_eq!(fee, FeeArg::Rate(2.5));
    }

    #[test]
    fn beacon_index_maps_types() {
        assert_eq!(beacon_index(None).unwrap(), 1);
        assert_eq!(beacon_index(Some("p2pkh")).unwrap(), 0);
        assert_eq!(beacon_index(Some("P2WPKH")).unwrap(), 1);
        assert_eq!(beacon_index(Some("p2tr")).unwrap(), 2);
        // an unknown beacon type is its own typed variant, NOT laundered
        // through UnknownNetwork.
        match beacon_index(Some("bogus")).unwrap_err() {
            CliRunError::Client(did_btcr2_client::Error::UnknownBeaconType(t)) => {
                assert_eq!(t, "BOGUS");
            }
            other => panic!("expected UnknownBeaconType, got {other:?}"),
        }
    }

    #[test]
    fn parse_change_rejects_wrong_network() {
        // a mainnet address must be rejected when the DID is on testnet —
        // nothing downstream re-checks the change-address network.
        let mainnet = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let err = parse_change_address(mainnet, esploda::bitcoin::Network::Testnet)
            .expect_err("a mainnet change address on testnet must be rejected");
        assert!(matches!(err, CliRunError::Io(_)), "got {err:?}");
    }

    #[test]
    fn parse_change_accepts_matching_network() {
        // A testnet address on the testnet network parses.
        let testnet = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
        parse_change_address(testnet, esploda::bitcoin::Network::Testnet)
            .expect("a testnet change address on testnet is accepted");
    }

    #[test]
    fn fee_arg_to_fee() {
        assert!(matches!(FeeArg::Absolute(7).to_fee(), Fee::Absolute(7)));
        assert!(matches!(FeeArg::Default.to_fee(), Fee::Absolute(_)));
        match FeeArg::Rate(3.0).to_fee() {
            Fee::Rate(r) => assert!((r - 3.0).abs() < f64::EPSILON),
            other => panic!("expected a rate fee, got {other:?}"),
        }
    }

    // ── Dispatch test: --dry-run performs ZERO broadcast ─────────────────────

    use std::cell::Cell;
    use std::rc::Rc;

    use ureq::http;

    /// An in-process fake transport for the dispatch test. Routes by path +
    /// method and counts `POST /tx` into a SHARED handle (so the test can read
    /// the count after the fake is moved into the `Client`). Serves an empty
    /// `/txs` (genesis v1), a chain tip, and a funding `/utxo` so the dry-run
    /// build path completes.
    struct FakeTransport {
        post_tx_calls: Rc<Cell<usize>>,
        utxo_calls: Rc<Cell<usize>>,
    }

    impl FakeTransport {
        fn new(counter: Rc<Cell<usize>>) -> Self {
            Self {
                post_tx_calls: counter,
                utxo_calls: Rc::new(Cell::new(0)),
            }
        }

        fn with_utxo_counter(post: Rc<Cell<usize>>, utxo: Rc<Cell<usize>>) -> Self {
            Self {
                post_tx_calls: post,
                utxo_calls: utxo,
            }
        }
    }

    impl BtcTransport for FakeTransport {
        fn execute(
            &self,
            req: http::Request<Vec<u8>>,
        ) -> Result<http::Response<Vec<u8>>, did_btcr2_client::TransportError> {
            let method = req.method().clone();
            let path = req.uri().path();

            if method == http::Method::POST && path.ends_with("/tx") {
                self.post_tx_calls.set(self.post_tx_calls.get() + 1);
                // Recover the posted tx from its hex body and echo its real txid;
                // the facade cross-checks the response body against the locally
                // computed txid, so an arbitrary body would be rejected.
                let raw = hex::decode(req.body()).expect("the facade posts ASCII hex");
                let tx: esploda::bitcoin::Transaction =
                    esploda::bitcoin::consensus::encode::deserialize(&raw)
                        .expect("the facade posts a consensus-encoded tx");
                return Ok(http::Response::builder()
                    .status(200)
                    .body(tx.txid().to_string().into_bytes())
                    .expect("static status is valid"));
            }

            let body: Vec<u8> = if path.ends_with("/blocks/tip/height") {
                b"100".to_vec()
            } else if path.contains("/address/") && path.ends_with("/utxo") {
                self.utxo_calls.set(self.utxo_calls.get() + 1);
                serde_json::json!([{
                    "txid": "0000000000000000000000000000000000000000000000000000000000000001",
                    "vout": 0,
                    "value": 100_000u64,
                    "status": { "confirmed": true, "block_height": 90 }
                }])
                .to_string()
                .into_bytes()
            } else {
                // /txs (empty → genesis) and any other tx-list probe.
                b"[]".to_vec()
            };

            Ok(http::Response::builder()
                .status(200)
                .body(body)
                .expect("static status is valid"))
        }
    }

    /// The deterministic key backing the DID, the update proof, and the beacon
    /// inputs (default singleton path).
    fn test_secret_key() -> secp256k1::SecretKey {
        secp256k1::SecretKey::from_slice(&[0x07; 32]).expect("[7u8; 32] is valid")
    }

    /// The same key material as [`test_secret_key`] but as the crate-owned
    /// newtype `WriteParams.update_sk` now takes.
    fn test_update_sk() -> did_btcr2::key::SecretKey {
        did_btcr2::key::SecretKey::try_from([0x07; 32]).expect("[7u8; 32] is valid")
    }

    #[test]
    fn dry_run_no_broadcast() {
        let post_count = Rc::new(Cell::new(0usize));
        let transport = FakeTransport::new(Rc::clone(&post_count));
        let client = Client::new("http://fake".to_string(), transport);
        let sk = test_secret_key();
        let secp = secp256k1::Secp256k1::new();
        let pk = sk.public_key(&secp);

        // Create a genesis DID document via the facade (no I/O).
        let doc = client
            .create(&pk, did_btcr2::identifier::Network::Mutinynet)
            .expect("create succeeds");
        let did: did_btcr2::identifier::Did = doc.as_ref()["id"]
            .as_str()
            .expect("document has a string id")
            .parse()
            .expect("document id parses as a Did");
        let vm_id = format!("{}#initialKey", did.encode());

        // Write a benign patch file the dispatch reads.
        let dir = std::env::temp_dir();
        let patch_path = dir.join(format!("did-btcr2-cli-dryrun-{}.json", std::process::id()));
        std::fs::write(
            &patch_path,
            serde_json::json!([{"op": "add", "path": "/assertionMethod/-", "value": vm_id}])
                .to_string(),
        )
        .expect("write patch file");

        let result = execute_write(
            &client,
            WriteParams {
                did,
                patch: Some(patch_path.clone()),
                vm_id,
                update_sk: test_update_sk(),
                beacon_sk: sk,
                beacon_idx: 1, // P2WPKH default beacon (spendable by the DID key)
                fee: Fee::Absolute(1_000),
                change: None,
                dry_run: true,
                yes: true,
                sidecar: None,
            },
        );

        let _ = std::fs::remove_file(&patch_path);
        // Keep the client (and its moved-in fake) alive until the assertion.
        drop(client);
        result.expect("dry-run dispatch succeeds");

        // The whole point: a --dry-run issues ZERO POST /tx.
        assert_eq!(post_count.get(), 0, "a --dry-run broadcasts nothing");
    }

    #[test]
    fn real_write_funds_once_and_broadcasts_preview() {
        // a real (non-dry-run) write must build the funded tx ONCE for the
        // confirmation preview and broadcast THAT exact tx — not rebuild it. The
        // old code called client.update, which re-fetched /utxo and rebuilt the
        // tx, so a UTXO change between the two /utxo GETs could broadcast a tx
        // different from the previewed one. With the fix, /utxo is fetched
        // exactly once. (The broadcast also only succeeds because the fake echoes
        // the posted tx's real txid, which the facade cross-checks.)
        let post_count = Rc::new(Cell::new(0usize));
        let utxo_count = Rc::new(Cell::new(0usize));
        let transport =
            FakeTransport::with_utxo_counter(Rc::clone(&post_count), Rc::clone(&utxo_count));
        let client = Client::new("http://fake".to_string(), transport);
        let sk = test_secret_key();
        let secp = secp256k1::Secp256k1::new();
        let pk = sk.public_key(&secp);

        let doc = client
            .create(&pk, did_btcr2::identifier::Network::Mutinynet)
            .expect("create succeeds");
        let did: did_btcr2::identifier::Did = doc.as_ref()["id"]
            .as_str()
            .expect("document has a string id")
            .parse()
            .expect("document id parses as a Did");
        let vm_id = format!("{}#initialKey", did.encode());

        let dir = std::env::temp_dir();
        let patch_path = dir.join(format!(
            "did-btcr2-cli-realwrite-{}.json",
            std::process::id()
        ));
        std::fs::write(
            &patch_path,
            serde_json::json!([{"op": "add", "path": "/assertionMethod/-", "value": vm_id}])
                .to_string(),
        )
        .expect("write patch file");

        let result = execute_write(
            &client,
            WriteParams {
                did,
                patch: Some(patch_path.clone()),
                vm_id,
                update_sk: test_update_sk(),
                beacon_sk: sk,
                beacon_idx: 1,
                fee: Fee::Absolute(1_000),
                change: None,
                dry_run: false,
                yes: true, // skip the interactive confirm
                sidecar: None,
            },
        );

        let _ = std::fs::remove_file(&patch_path);
        drop(client);
        result.expect("a real write broadcasts the confirmed tx");

        assert_eq!(post_count.get(), 1, "a real write broadcasts exactly once");
        assert_eq!(
            utxo_count.get(),
            1,
            "a real write funds (fetches /utxo) exactly once — the previewed tx \
             is the broadcast tx, not a rebuild"
        );
    }

    // ── create: parse paths ──────────────────────────────────────────────────

    #[test]
    fn parse_create_generate() {
        let parsed = Args::parse(args_from_strings(&["create", "--generate"])).unwrap();
        let Command::Create {
            generate,
            key_file,
            key_stdin,
            network,
            intermediate_document,
            sidecar_out,
        } = parsed.command
        else {
            panic!("expected a Create command");
        };
        assert!(generate);
        assert_eq!(key_file, None);
        assert!(!key_stdin);
        assert_eq!(network, None);
        assert_eq!(intermediate_document, None);
        assert_eq!(sidecar_out, None);
    }

    #[test]
    fn parse_create_supplied_key_and_network() {
        let parsed = Args::parse(args_from_strings(&[
            "create",
            "--key-file",
            "k.hex",
            "--network",
            "signet",
        ]))
        .unwrap();
        let Command::Create {
            generate,
            key_file,
            network,
            ..
        } = parsed.command
        else {
            panic!("expected a Create command");
        };
        assert!(!generate);
        assert_eq!(key_file, Some(PathBuf::from("k.hex")));
        assert_eq!(network, Some("signet".to_string()));
    }

    #[test]
    fn parse_create_rejects_positional() {
        // create takes no positional <did>.
        assert!(matches!(
            Args::parse(args_from_strings(&["create", SAMPLE_DID])).unwrap_err(),
            CliError::Unknown(_)
        ));
    }

    #[test]
    fn parse_create_rejects_inapplicable_flags() {
        // funding/resolution flags do not apply to the offline create.
        assert!(matches!(
            Args::parse(args_from_strings(&[
                "create",
                "--esplora-url",
                "https://node.example/api"
            ]))
            .unwrap_err(),
            CliError::Unknown(_)
        ));
        assert!(matches!(
            Args::parse(args_from_strings(&["create", "--sidecar", "/tmp/s.json"])).unwrap_err(),
            CliError::Unknown(_)
        ));
    }

    // ── create: network mapping ──────────────────────────────────────────────

    #[test]
    fn network_from_str_maps_known_and_default() {
        use did_btcr2::identifier::Network;
        assert!(matches!(
            network_from_str(None).unwrap(),
            Network::TestnetV3
        ));
        assert!(matches!(
            network_from_str(Some("testnet")).unwrap(),
            Network::TestnetV3
        ));
        assert!(matches!(
            network_from_str(Some("signet")).unwrap(),
            Network::Signet
        ));
        assert!(matches!(
            network_from_str(Some("mainnet")).unwrap(),
            Network::Mainnet
        ));
        assert!(matches!(
            network_from_str(Some("mutinynet")).unwrap(),
            Network::Mutinynet
        ));
        // an unknown network is its own typed variant.
        match network_from_str(Some("bogus")).unwrap_err() {
            CliRunError::Client(did_btcr2_client::Error::UnknownNetwork(n)) => {
                assert_eq!(n, "bogus");
            }
            other => panic!("expected UnknownNetwork, got {other:?}"),
        }
    }

    // ── create: key-mode truth table (pure helper, no env touch) ──────────────

    #[test]
    fn resolve_create_key_mode_truth_table() {
        assert_eq!(
            resolve_create_key_mode(true, false).unwrap(),
            CreateKeyMode::Generate
        );
        assert_eq!(
            resolve_create_key_mode(false, true).unwrap(),
            CreateKeyMode::Supplied
        );
        // neither --generate nor a key source → typed missing-source error.
        assert!(matches!(
            resolve_create_key_mode(false, false).unwrap_err(),
            CliRunError::Key(keyload::KeyError::MissingSource(_))
        ));
        // both → typed conflict.
        assert!(matches!(
            resolve_create_key_mode(true, true).unwrap_err(),
            CliRunError::CreateKeySourceConflict
        ));
    }

    // ── create: zero-transport dispatch yields a parseable genesis DID ────────

    #[test]
    fn create_makes_zero_transport_calls() {
        let post_count = Rc::new(Cell::new(0usize));
        let utxo_count = Rc::new(Cell::new(0usize));
        // A counter the fake bumps on EVERY execute() call. create must never
        // reach the transport at all, so this stays 0.
        let transport =
            FakeTransport::with_utxo_counter(Rc::clone(&post_count), Rc::clone(&utxo_count));
        let client = Client::new("http://fake".to_string(), transport);

        let sk = test_secret_key();
        let secp = secp256k1::Secp256k1::new();
        let pk = sk.public_key(&secp);

        let did = create_and_print(&client, &pk, did_btcr2::identifier::Network::Mutinynet)
            .expect("create dispatch succeeds offline");

        drop(client);
        // create is pure composition — it issues no POST /tx and no /utxo GET.
        assert_eq!(post_count.get(), 0, "create broadcasts nothing");
        assert_eq!(utxo_count.get(), 0, "create funds nothing");
        // The produced document yields a parseable did:btcr2: identifier.
        assert!(did.encode().starts_with("did:btcr2:"));
    }

    // ── create: external (x1) mode ────────────────────────────────────────────

    /// A self-contained x1 intermediate (placeholder-DID) document JSON, matching
    /// the spec `did:btcr2:_` genesis-document shape. Inlined so the CLI test does
    /// not depend on the `did-btcr2` crate's test-suite submodule.
    fn x1_intermediate_json() -> serde_json::Value {
        serde_json::json!({
            "id": "did:btcr2:_",
            "@context": [
                "https://www.w3.org/ns/did/v1.1",
                "https://btcr2.dev/context/v1"
            ],
            "verificationMethod": [{
                "id": "did:btcr2:_#key-0",
                "type": "Multikey",
                "controller": "did:btcr2:_",
                "publicKeyMultibase": "zQ3shTHn9hZ1BHtoZayz4VmPAZT97p2v8swmuPEUwBKHCanTL"
            }],
            "authentication": ["did:btcr2:_#key-0"],
            "assertionMethod": ["did:btcr2:_#key-0"],
            "capabilityInvocation": ["did:btcr2:_#key-0"],
            "capabilityDelegation": ["did:btcr2:_#key-0"],
            "service": [{
                "id": "did:btcr2:_#service-0",
                "serviceEndpoint": "bitcoin:mnDXvNsFTf9cs4hWigPkENCBDp9eJpfyxF",
                "type": "SingletonBeacon"
            }]
        })
    }

    /// A unique path under the OS temp dir (no `tempfile` dev-dep in this crate).
    fn unique_temp_path(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        std::env::temp_dir().join(format!("did-btcr2-cli-test-{tag}-{pid}-{n}.json"))
    }

    #[test]
    fn parse_create_accepts_intermediate_and_sidecar_out() {
        let parsed = Args::parse(args_from_strings(&[
            "create",
            "--intermediate-document",
            "genesis.json",
            "--sidecar-out",
            "sc.json",
        ]))
        .unwrap();
        let Command::Create {
            intermediate_document,
            sidecar_out,
            generate,
            key_file,
            key_stdin,
            ..
        } = parsed.command
        else {
            panic!("expected a Create command");
        };
        assert_eq!(intermediate_document, Some(PathBuf::from("genesis.json")));
        assert_eq!(sidecar_out, Some(PathBuf::from("sc.json")));
        assert!(!generate);
        assert_eq!(key_file, None);
        assert!(!key_stdin);
    }

    #[test]
    fn external_create_rejects_generate_conflict() {
        // --intermediate-document + --generate → CreateKeySourceConflict, and the
        // conflict is detected before any key is read.
        let err = run_create(
            Some("regtest"),
            None,
            false,
            true, // --generate
            Some(unique_temp_path("noexist")),
            None,
        )
        .expect_err("external mode + --generate must conflict");
        assert!(
            matches!(err, CliRunError::CreateKeySourceConflict),
            "got {err:?}"
        );
    }

    #[test]
    fn external_create_rejects_key_source_conflict() {
        // --intermediate-document + a key source (here a key file) → conflict,
        // before any file is opened.
        let err = run_create(
            Some("regtest"),
            Some(PathBuf::from("some-key.hex")),
            false,
            false,
            Some(unique_temp_path("noexist")),
            None,
        )
        .expect_err("external mode + key source must conflict");
        assert!(
            matches!(err, CliRunError::CreateKeySourceConflict),
            "got {err:?}"
        );
    }

    #[test]
    fn external_create_missing_file_is_typed_io_error() {
        let missing = unique_temp_path("definitely-missing");
        let err = run_create(Some("signet"), None, false, false, Some(missing), None)
            .expect_err("a missing intermediate-document file must error");
        assert!(matches!(err, CliRunError::Io(_)), "got {err:?}");
    }

    #[test]
    fn external_create_malformed_json_is_typed_json_error() {
        let path = unique_temp_path("malformed");
        std::fs::write(&path, b"{ this is not json").unwrap();
        let err = run_create(Some("signet"), None, false, false, Some(path.clone()), None)
            .expect_err("malformed intermediate-document JSON must error");
        let _ = std::fs::remove_file(&path);
        assert!(matches!(err, CliRunError::Json(_)), "got {err:?}");
    }

    #[test]
    fn external_create_roundtrip_resolves_via_sidecar() {
        use did_btcr2::identifier::Network;

        // 1. Mint an x1 DID from the intermediate document and write a
        //    --sidecar-out payload, all offline through a fake transport.
        let sidecar_path = unique_temp_path("sidecar-out");
        let post_count = Rc::new(Cell::new(0usize));
        let utxo_count = Rc::new(Cell::new(0usize));
        let transport =
            FakeTransport::with_utxo_counter(Rc::clone(&post_count), Rc::clone(&utxo_count));
        let client = Client::new("http://fake".to_string(), transport);

        let did = create_external_and_print(
            &client,
            x1_intermediate_json(),
            Network::Regtest,
            Some(sidecar_path.clone()),
        )
        .expect("external create succeeds offline");

        assert!(
            did.encode().starts_with("did:btcr2:x1"),
            "external create must mint an x1 DID, got {}",
            did.encode()
        );
        // Minting touches no transport.
        assert_eq!(post_count.get(), 0);
        assert_eq!(utxo_count.get(), 0);

        // The sidecar carries the genesisDocument wire key = the INTERMEDIATE doc
        // (placeholder id), NOT the substituted initial document.
        let written: serde_json::Value =
            serde_json::from_reader(File::open(&sidecar_path).unwrap()).unwrap();
        assert_eq!(written["genesisDocument"], x1_intermediate_json());
        assert_eq!(written["genesisDocument"]["id"], "did:btcr2:_");

        // 2. Feed the written sidecar back through load_sidecar + the facade's
        //    resolve (offline, empty /txs → genesis version 1). This exercises the
        //    REAL serde/CLI path and the resolve-side genesis→initial bridge.
        let opts = load_sidecar(Some(sidecar_path.clone())).expect("load_sidecar");
        let result = client
            .resolve(&did, opts)
            .expect("x1 resolve via genesisDocument sidecar succeeds");
        let _ = std::fs::remove_file(&sidecar_path);

        // The resolved document is the minted x1 DID's initial document.
        assert_eq!(
            result.document.as_ref().get("id").and_then(|v| v.as_str()),
            Some(did.encode())
        );
    }
}
