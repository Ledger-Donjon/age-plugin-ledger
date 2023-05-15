use std::env;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

const PLUGIN_BIN: &str = env!("CARGO_BIN_EXE_age-plugin-ledger");

#[cfg(feature = "test-device")]
#[test]
fn recipient_and_identity_match() {
    let recipient = Command::new(PLUGIN_BIN).arg("--list").output().unwrap();
    assert_eq!(recipient.status.code(), Some(0));

    let identity = Command::new(PLUGIN_BIN).arg("--identity").output().unwrap();
    assert_eq!(identity.status.code(), Some(0));

    let recipient_file = String::from_utf8_lossy(&recipient.stdout);
    let recipient = recipient_file.lines().last().unwrap();
    let identity = String::from_utf8_lossy(&identity.stdout);
    assert!(identity.contains(recipient));
}

#[test]
fn plugin_encrypt() {
    let enc_file = tempfile::NamedTempFile::new_in(env!("CARGO_TARGET_TMPDIR")).unwrap();

    // Use abandon seed
    let mut process = Command::new(which::which("rage").unwrap())
        .arg("-r")
        .arg("age1ledger1q0a49dn0xft2ts5dhl8wgkncl7vy6kt5wwqpxcx6jzk6ucxfs6u9zhgs0q4")
        .arg("-o")
        .arg(enc_file.path())
        .stdin(Stdio::piped())
        .env("PATH", Path::new(PLUGIN_BIN).parent().unwrap())
        .spawn()
        .unwrap();

    // Scope to ensure stdin is closed.
    {
        let mut stdin = process.stdin.take().unwrap();
        stdin.write_all(b"Testing device encryption").unwrap();
        stdin.flush().unwrap();
    }

    let status = process.wait().unwrap();
    assert_eq!(status.code(), Some(0));
}

#[cfg(feature = "test-device")]
#[test]
fn plugin_decrypt() {
    let mut identity_file = tempfile::NamedTempFile::new_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let enc_file = tempfile::NamedTempFile::new_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let plaintext = "Testing device encryption";

    // Write an identity file corresponding to this device slot.
    let identity = Command::new(PLUGIN_BIN).arg("--identity").output().unwrap();
    assert_eq!(identity.status.code(), Some(0));
    identity_file.write_all(&identity.stdout).unwrap();
    identity_file.flush().unwrap();

    // Encrypt to the device slot.
    let mut enc_process = Command::new(which::which("rage").unwrap())
        .arg("-e")
        .arg("-i")
        .arg(identity_file.path())
        .arg("-o")
        .arg(enc_file.path())
        .stdin(Stdio::piped())
        .env("PATH", Path::new(PLUGIN_BIN).parent().unwrap())
        .spawn()
        .unwrap();

    // Scope to ensure stdin is closed.
    {
        let mut stdin = enc_process.stdin.take().unwrap();
        stdin.write_all(plaintext.as_bytes()).unwrap();
        stdin.flush().unwrap();
    }

    let enc_status = enc_process.wait().unwrap();
    assert_eq!(enc_status.code(), Some(0));

    // Decrypt with the device.
    let dec_process = Command::new(which::which("rage").unwrap())
        .arg("-d")
        .arg("-i")
        .arg(identity_file.path())
        .arg(enc_file.path())
        .stdin(Stdio::piped())
        .env("PATH", Path::new(PLUGIN_BIN).parent().unwrap())
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&dec_process.stderr);
    if !stderr.is_empty() {
        assert!(stderr.contains("age-plugin-ledger"));
        assert!(stderr.ends_with("...\n"));
    }
    assert_eq!(String::from_utf8_lossy(&dec_process.stdout), plaintext);
}
