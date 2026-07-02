use super::keys::generate_keypair;
use super::parallel::CHUNK_SIZE;
use super::*;
use lvau_protocol::envelope::Envelope;
use secrecy::Secret;
use sha2::{Digest, Sha256};
use std::env::temp_dir;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_path(name: &str) -> PathBuf {
    let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    temp_dir().join(format!("lvau-test-{}-{}-{}", std::process::id(), id, name))
}

fn roundtrip_bytes(name: &str, bytes: &[u8]) {
    let input = unique_path(&format!("{name}.input"));
    let enc = unique_path(&format!("{name}.lvau"));
    let dec = unique_path(&format!("{name}.output"));
    let password = Secret::new("correct horse battery staple".to_string());

    fs::write(&input, bytes).unwrap();
    let original_hash = Sha256::digest(bytes);

    encrypt_file_password(
        &input,
        &enc,
        password.clone(),
        None,
        SecurityProfile::Fast,
        None,
    )
    .unwrap();
    decrypt_file_password(&enc, &dec, password, None, None).unwrap();

    let decrypted = fs::read(&dec).unwrap();
    assert_eq!(Sha256::digest(&decrypted), original_hash);
    assert_eq!(decrypted, bytes);
}

#[test]
fn small_file_roundtrips() {
    roundtrip_bytes("small", b"Hello, Lvau.");
}

#[test]
fn empty_file_roundtrips() {
    roundtrip_bytes("empty", b"");
}

#[test]
fn unicode_text_roundtrips() {
    roundtrip_bytes("unicode", "Lvau encrypts UTF-8 text: こんにちは".as_bytes());
}

#[test]
fn binary_file_roundtrips() {
    let bytes: Vec<u8> = (0..=255).cycle().take(8192).collect();
    roundtrip_bytes("binary", &bytes);
}

#[test]
fn larger_file_roundtrips() {
    let bytes: Vec<u8> = (0..(CHUNK_SIZE + 37))
        .map(|i| ((i * 31) % 251) as u8)
        .collect();
    roundtrip_bytes("large", &bytes);
}

#[test]
fn wrong_password_fails() {
    let input = unique_path("wrong-password.input");
    let enc = unique_path("wrong-password.lvau");
    let dec = unique_path("wrong-password.output");

    fs::write(&input, b"Secret Data").unwrap();
    encrypt_file_password(
        &input,
        &enc,
        Secret::new("correct-password".to_string()),
        None,
        SecurityProfile::Fast,
        None,
    )
    .unwrap();

    let result = decrypt_file_password(
        &enc,
        &dec,
        Secret::new("wrong-password".to_string()),
        None,
        None,
    );

    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
}

#[test]
fn modified_ciphertext_fails() {
    let input = unique_path("tamper-ciphertext.input");
    let enc = unique_path("tamper-ciphertext.lvau");
    let dec = unique_path("tamper-ciphertext.output");
    let password = Secret::new("password123".to_string());

    fs::write(&input, b"Data to be tampered").unwrap();
    encrypt_file_password(
        &input,
        &enc,
        password.clone(),
        None,
        SecurityProfile::Fast,
        None,
    )
    .unwrap();

    let mut data = fs::read(&enc).unwrap();
    *data.last_mut().unwrap() ^= 0xFF;
    fs::write(&enc, data).unwrap();

    let result = decrypt_file_password(&enc, &dec, password, None, None);
    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
}

#[test]
fn modified_header_aad_fails() {
    let input = unique_path("tamper-header.input");
    let enc = unique_path("tamper-header.lvau");
    let dec = unique_path("tamper-header.output");
    let password = Secret::new("password123".to_string());

    fs::write(&input, b"header-bound data").unwrap();
    encrypt_file_password(
        &input,
        &enc,
        password.clone(),
        None,
        SecurityProfile::Fast,
        None,
    )
    .unwrap();

    // Read the streaming format: 4 bytes length, then envelope, then payload.
    let data = fs::read(&enc).unwrap();
    let env_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    let mut envelope: Envelope = postcard::from_bytes(&data[4..4 + env_len]).unwrap();
    envelope.header.profile = SecurityProfile::Archive;

    let new_env_bytes = postcard::to_allocvec(&envelope).unwrap();
    let new_len = new_env_bytes.len() as u32;

    let mut new_data = Vec::new();
    new_data.extend_from_slice(&new_len.to_le_bytes());
    new_data.extend_from_slice(&new_env_bytes);
    new_data.extend_from_slice(&data[4 + env_len..]);

    fs::write(&enc, new_data).unwrap();

    let result = decrypt_file_password(&enc, &dec, password, None, None);
    assert!(matches!(result, Err(CryptoError::Validation(_))));
}

#[test]
fn truncated_file_fails() {
    let input = unique_path("truncated.input");
    let enc = unique_path("truncated.lvau");
    let dec = unique_path("truncated.output");
    let password = Secret::new("password123".to_string());
    let bytes: Vec<u8> = (0..(CHUNK_SIZE * 2 + 11))
        .map(|i| (i % 251) as u8)
        .collect();

    fs::write(&input, bytes).unwrap();
    encrypt_file_password(
        &input,
        &enc,
        password.clone(),
        None,
        SecurityProfile::Fast,
        None,
    )
    .unwrap();

    let file = std::fs::OpenOptions::new().write(true).open(&enc).unwrap();
    let len = file.metadata().unwrap().len();
    file.set_len(len - 10).unwrap();

    let result = decrypt_file_password(&enc, &dec, password, None, None);
    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
}

#[test]
fn random_garbage_input_fails_gracefully() {
    let enc = unique_path("garbage.lvau");
    let dec = unique_path("garbage.output");
    fs::write(&enc, b"not an lvau envelope").unwrap();

    let result = decrypt_file_password(
        &enc,
        &dec,
        Secret::new("password123".to_string()),
        None,
        None,
    );

    // It fails with an IO error first because it tries to read length which exceeds file bounds
    assert!(result.is_err());
}

#[test]
fn inspect_works_without_password() {
    let input = unique_path("inspect.input");
    let enc = unique_path("inspect.lvau");

    fs::write(&input, b"inspectable").unwrap();
    encrypt_file_password(
        &input,
        &enc,
        Secret::new("password123".to_string()),
        None,
        SecurityProfile::Fast,
        None,
    )
    .unwrap();

    let header = inspect_envelope(&enc).unwrap();
    assert_eq!(header.magic, MAGIC_REAL);
    assert_eq!(header.version, CURRENT_VERSION);
    assert_eq!(header.profile, SecurityProfile::Fast);
    assert_eq!(header.recipients.len(), 1);
}

#[test]
fn paranoid_profile_with_seed_roundtrips_and_rejects_wrong_seed() {
    let input = unique_path("paranoid.input");
    let enc = unique_path("paranoid.lvau");
    let dec = unique_path("paranoid.output");
    let dec_wrong = unique_path("paranoid-wrong.output");

    fs::write(&input, b"Top secret cascaded data").unwrap();

    let password = Secret::new("top_secret_password".to_string());
    let seed = Secret::new("my_random_seed_123".to_string());

    encrypt_file_password(
        &input,
        &enc,
        password.clone(),
        Some(seed.clone()),
        SecurityProfile::Paranoid,
        None,
    )
    .unwrap();

    decrypt_file_password(&enc, &dec, password.clone(), Some(seed), None).unwrap();
    assert_eq!(fs::read(&dec).unwrap(), b"Top secret cascaded data");

    let result = decrypt_file_password(
        &enc,
        &dec_wrong,
        password,
        Some(Secret::new("wrong_seed".to_string())),
        None,
    );
    assert!(result.is_err());
}

#[test]
fn hybrid_keypair_roundtrips() {
    let input = unique_path("keypair.input");
    let enc = unique_path("keypair.lvau");
    let dec = unique_path("keypair.output");
    let (private_key, public_key) = generate_keypair();

    fs::write(&input, b"hybrid recipient data").unwrap();
    encrypt_file_keypair(&input, &enc, &public_key, SecurityProfile::Fast, None).unwrap();
    decrypt_file_keypair(&enc, &dec, &private_key, None).unwrap();

    assert_eq!(fs::read(&dec).unwrap(), b"hybrid recipient data");
}
