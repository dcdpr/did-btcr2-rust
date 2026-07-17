//! The `did-btcr2` CLI must exit cleanly (code 0, no `Broken pipe` on
//! stderr) when its stdout reader closes the pipe early (`create … | head`,
//! `… | grep -q`, a quit pager) — the safe-Rust `writeln!` + `StdoutClosed`
//! BrokenPipe path, NOT a SIGPIPE reset.
//!
//! `create --generate` is a no-network, no-file subcommand that writes the DID +
//! genesis document (and the generated secret) to stdout, so it exercises the
//! stdout display sites without any transport or filesystem dependency.

use std::process::{Command, Stdio};

/// Deterministic broken-pipe: drop the read end of the child's stdout pipe
/// BEFORE the child writes, so its first stdout write hits `EPIPE` regardless of
/// the OS pipe-buffer size. The CLI must exit 0 with no `Broken pipe` on stderr.
#[test]
fn early_closed_stdout_exits_zero_without_broken_pipe() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_did-btcr2"))
        .args(["create", "--generate"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn did-btcr2 create --generate");

    // Close the read end immediately — before the child writes anything — so the
    // child's first stdout write is guaranteed to hit a broken pipe. This is the
    // buffer-size-independent form (no read-a-few-bytes race).
    drop(child.stdout.take().expect("child stdout piped"));

    let out = child.wait_with_output().expect("wait for child");
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        out.status.success(),
        "early-closed stdout must exit 0, got {:?}; stderr: {stderr}",
        out.status.code(),
    );
    assert!(
        !stderr.contains("Broken pipe"),
        "stderr must not mention a broken pipe, got: {stderr}",
    );
}

/// Non-vacuous sibling: the SAME command with NO early close must exit 0 AND
/// actually produce stdout — proving the broken-pipe test above is not passing
/// merely because the command emits nothing.
#[test]
fn same_command_without_early_close_produces_stdout() {
    let out = Command::new(env!("CARGO_BIN_EXE_did-btcr2"))
        .args(["create", "--generate"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run did-btcr2 create --generate");

    assert!(
        out.status.success(),
        "a normal run must exit 0, got {:?}",
        out.status.code(),
    );
    assert!(
        !out.stdout.is_empty(),
        "a normal run must write the DID + document to stdout",
    );
}
