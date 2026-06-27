//! Black-box tests for the `cc-me` binary's argument and exit behaviour,
//! driven via `std::process::Command`. Cargo exposes the freshly built binary
//! path through the `CARGO_BIN_EXE_cc-me` environment variable.

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cc-me"))
}

#[test]
fn missing_target_exits_64() {
    let output = bin().output().expect("run cc-me with no args");
    assert_eq!(output.status.code(), Some(64));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("usage"), "expected usage, got: {stderr}");
}

#[test]
fn help_flag_exits_zero() {
    let output = bin().arg("--help").output().expect("run cc-me --help");
    assert_eq!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("usage"));
}

#[test]
fn short_help_flag_exits_zero() {
    let output = bin().arg("-h").output().expect("run cc-me -h");
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn unknown_option_fails() {
    let output = bin().arg("--nope").output().expect("run cc-me --nope");
    assert_ne!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown option"), "got: {stderr}");
}

#[test]
fn key_flag_without_value_fails() {
    let output = bin().arg("--key").output().expect("run cc-me --key");
    assert_ne!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--key needs a value"), "got: {stderr}");
}

#[test]
fn two_positionals_fail() {
    let output = bin()
        .args(["http://a/", "http://b/"])
        .output()
        .expect("run cc-me with two urls");
    assert_ne!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("only one forward URL"), "got: {stderr}");
}
