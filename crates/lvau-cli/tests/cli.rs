use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::tempdir;

fn lvau() -> Command {
    Command::cargo_bin("lvau-cli").unwrap()
}

#[test]
fn help_lists_core_commands() {
    lvau()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("encrypt"))
        .stdout(predicate::str::contains("decrypt"))
        .stdout(predicate::str::contains("inspect"))
        .stdout(predicate::str::contains("keygen"));
}

#[test]
fn password_roundtrip_and_inspect_work() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("input.txt");
    let encrypted = dir.path().join("input.lvau");
    let decrypted = dir.path().join("output.txt");
    let password = dir.path().join("password.txt");

    fs::write(&input, "hello from lvau").unwrap();
    fs::write(&password, "correct horse battery staple\n").unwrap();

    lvau()
        .args([
            "encrypt",
            "--in-file",
            input.to_str().unwrap(),
            "--out-file",
            encrypted.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
            "--profile",
            "fast",
        ])
        .assert()
        .success();

    lvau()
        .args(["inspect", "--in-file", encrypted.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Lvau envelope metadata"))
        .stdout(predicate::str::contains("Argon2id"));

    lvau()
        .args([
            "decrypt",
            "--in-file",
            encrypted.to_str().unwrap(),
            "--out-file",
            decrypted.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(fs::read(&decrypted).unwrap(), fs::read(&input).unwrap());
}

#[test]
fn wrong_password_fails_without_output() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("input.txt");
    let encrypted = dir.path().join("input.lvau");
    let decrypted = dir.path().join("output.txt");
    let password = dir.path().join("password.txt");
    let wrong_password = dir.path().join("wrong-password.txt");

    fs::write(&input, "secret").unwrap();
    fs::write(&password, "correct\n").unwrap();
    fs::write(&wrong_password, "wrong\n").unwrap();

    lvau()
        .args([
            "encrypt",
            "--in-file",
            input.to_str().unwrap(),
            "--out-file",
            encrypted.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
            "--profile",
            "fast",
        ])
        .assert()
        .success();

    lvau()
        .args([
            "decrypt",
            "--in-file",
            encrypted.to_str().unwrap(),
            "--out-file",
            decrypted.to_str().unwrap(),
            "--password-file",
            wrong_password.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Decryption failed"));

    assert!(!decrypted.exists());
}

#[test]
fn corrupted_file_fails_gracefully() {
    let dir = tempdir().unwrap();
    let encrypted = dir.path().join("garbage.lvau");
    let decrypted = dir.path().join("output.txt");
    let password = dir.path().join("password.txt");

    fs::write(&encrypted, "not an envelope").unwrap();
    fs::write(&password, "correct\n").unwrap();

    lvau()
        .args([
            "decrypt",
            "--in-file",
            encrypted.to_str().unwrap(),
            "--out-file",
            decrypted.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("error:"));
}

#[test]
fn refuses_overwrite_without_force() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("input.txt");
    let encrypted = dir.path().join("input.lvau");
    let password = dir.path().join("password.txt");

    fs::write(&input, "secret").unwrap();
    fs::write(&encrypted, "existing").unwrap();
    fs::write(&password, "correct\n").unwrap();

    lvau()
        .args([
            "encrypt",
            "--in-file",
            input.to_str().unwrap(),
            "--out-file",
            encrypted.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));

    assert_eq!(fs::read_to_string(&encrypted).unwrap(), "existing");
}
