use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

fn lvau() -> Command {
    Command::cargo_bin("lvau-cli").unwrap()
}

fn write_secret_file(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
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
        .stdout(predicate::str::contains("keygen"))
        .stdout(predicate::str::contains("bundle"))
        .stdout(predicate::str::contains("sign-keygen"))
        .stdout(predicate::str::contains("sign"))
        .stdout(predicate::str::contains("verify-signature"));
}

#[test]
fn version_flag_works() {
    lvau()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("lvau-cli"));
}

#[test]
fn password_roundtrip_and_inspect_work() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("input.txt");
    let encrypted = dir.path().join("input.lvau");
    let decrypted = dir.path().join("output.txt");
    let password = dir.path().join("password.txt");

    fs::write(&input, "hello from lvau").unwrap();
    write_secret_file(&password, "correct horse battery staple\n");

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
fn inspect_json_output_is_valid() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("input.txt");
    let encrypted = dir.path().join("input.lvau");
    let password = dir.path().join("password.txt");

    fs::write(&input, "json test").unwrap();
    write_secret_file(&password, "testpass\n");

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

    let output = lvau()
        .args([
            "inspect",
            "--in-file",
            encrypted.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json_str = String::from_utf8(output).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed["magic"], "LVAU");
    assert_eq!(parsed["signed"], false);
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
    write_secret_file(&password, "correct\n");
    write_secret_file(&wrong_password, "wrong\n");

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
    write_secret_file(&password, "correct\n");

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
    write_secret_file(&password, "correct\n");

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

#[test]
fn recipient_groups_lifecycle() {
    let dir = tempdir().unwrap();
    let group = dir.path().join("mygroup.toml");
    let key_dir = dir.path().join("keys");
    let input = dir.path().join("input.txt");
    let encrypted = dir.path().join("input.lvau");

    fs::create_dir_all(&key_dir).unwrap();
    fs::write(&input, "secret message for group").unwrap();

    // 1. Generate two keypairs
    lvau()
        .args([
            "keygen",
            "--out-base",
            key_dir.join("alice").to_str().unwrap(),
        ])
        .assert()
        .success();
    lvau()
        .args([
            "keygen",
            "--out-base",
            key_dir.join("bob").to_str().unwrap(),
        ])
        .assert()
        .success();

    // 2. Create group
    lvau()
        .args(["recipients", "group", "create", group.to_str().unwrap()])
        .assert()
        .success();

    // 3. Add to group
    lvau()
        .args([
            "recipients",
            "group",
            "add",
            group.to_str().unwrap(),
            "--pub-key",
            key_dir.join("alice.lvau-pub").to_str().unwrap(),
        ])
        .assert()
        .success();
    lvau()
        .args([
            "recipients",
            "group",
            "add",
            group.to_str().unwrap(),
            "--pub-key",
            key_dir.join("bob.lvau-pub").to_str().unwrap(),
        ])
        .assert()
        .success();

    // 4. List group
    lvau()
        .args(["recipients", "group", "list", group.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("alice"))
        .stdout(predicate::str::contains("bob"));

    // 5. Encrypt with group
    lvau()
        .args([
            "encrypt",
            "--in-file",
            input.to_str().unwrap(),
            "--out-file",
            encrypted.to_str().unwrap(),
            "--recipient-group",
            group.to_str().unwrap(),
        ])
        .assert()
        .success();

    // 6. Decrypt with Alice
    let dec_alice = dir.path().join("dec_alice.txt");
    lvau()
        .args([
            "decrypt",
            "--in-file",
            encrypted.to_str().unwrap(),
            "--out-file",
            dec_alice.to_str().unwrap(),
            "--priv-key",
            key_dir.join("alice.lvau-key").to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read_to_string(&dec_alice).unwrap(),
        "secret message for group"
    );

    // 7. Decrypt with Bob
    let dec_bob = dir.path().join("dec_bob.txt");
    lvau()
        .args([
            "decrypt",
            "--in-file",
            encrypted.to_str().unwrap(),
            "--out-file",
            dec_bob.to_str().unwrap(),
            "--priv-key",
            key_dir.join("bob.lvau-key").to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read_to_string(&dec_bob).unwrap(),
        "secret message for group"
    );
}

#[test]
fn bundle_policy_diff_lifecycle() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("src_dir");
    let bundle = dir.path().join("mybundle.lvau");
    let extracted = dir.path().join("extracted_dir");
    let policy = dir.path().join("policy.toml");
    let key_dir = dir.path().join("keys");
    let password = dir.path().join("password.txt");

    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&key_dir).unwrap();
    fs::write(src.join("file1.txt"), "hello world").unwrap();
    fs::write(src.join("file2.txt"), "secret data").unwrap();
    write_secret_file(&password, "super_secure_password\n");

    // Generate keys
    lvau()
        .args([
            "keygen",
            "--out-base",
            key_dir.join("alice").to_str().unwrap(),
        ])
        .assert()
        .success();

    // Create a policy
    lvau()
        .args(["policy", "create", "--out-file", policy.to_str().unwrap()])
        .assert()
        .success();

    // Pack the bundle
    lvau()
        .args([
            "bundle",
            "pack",
            "--in-dir",
            src.to_str().unwrap(),
            "--out-file",
            bundle.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Lint the bundle against the policy
    lvau()
        .args([
            "policy",
            "lint",
            "--in-file",
            bundle.to_str().unwrap(),
            "--policy",
            policy.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Result: PASS"));

    // Preflight inspect the bundle
    lvau()
        .args(["preflight", "--in-file", bundle.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature Present: false"))
        .stdout(predicate::str::contains("Preflight Report for:"));

    // Verify the bundle
    lvau()
        .args([
            "bundle",
            "verify",
            "--in-file",
            bundle.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Bundle verified: 2 files"));

    let bundle2 = dir.path().join("mybundle2.lvau");
    fs::write(src.join("file1.txt"), "hello world changed").unwrap();
    lvau()
        .args([
            "bundle",
            "pack",
            "--in-dir",
            src.to_str().unwrap(),
            "--out-file",
            bundle2.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Diff the bundle
    lvau()
        .args([
            "bundle",
            "diff",
            "--old-file",
            bundle.to_str().unwrap(),
            "--new-file",
            bundle2.to_str().unwrap(),
            "--old-password-file",
            password.to_str().unwrap(),
            "--new-password-file",
            password.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("file1.txt"));

    // Extract the bundle
    lvau()
        .args([
            "bundle",
            "extract",
            "--in-file",
            bundle.to_str().unwrap(),
            "--out-dir",
            extracted.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read_to_string(extracted.join("file1.txt")).unwrap(),
        "hello world"
    );
}
