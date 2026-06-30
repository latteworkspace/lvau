use super::*;
use lvau_protocol::envelope::Envelope;
use secrecy::Secret;
use std::env::temp_dir;
use std::fs;

#[test]
fn test_roundtrip_password_encryption() {
    let input = temp_dir().join("test_input.txt");
    let enc = temp_dir().join("test.lvau");
    let dec = temp_dir().join("test_decrypted.txt");

    fs::write(&input, b"Hello, Lvau Boring Crypto!").unwrap();

    let password = Secret::new("my_super_secret_password".to_string());

    encrypt_file_password(&input, &enc, password.clone(), None, SecurityProfile::Fast).unwrap();
    decrypt_file_password(&enc, &dec, password, None).unwrap();

    let decrypted_content = fs::read(&dec).unwrap();
    assert_eq!(decrypted_content, b"Hello, Lvau Boring Crypto!");
}

#[test]
fn test_cascade_paranoid_with_seed() {
    let input = temp_dir().join("test_input_paranoid.txt");
    let enc = temp_dir().join("test_paranoid.lvau");
    let dec = temp_dir().join("test_decrypted_paranoid.txt");

    fs::write(&input, b"Top secret cascaded data").unwrap();

    let password = Secret::new("top_secret_password".to_string());
    let seed = Secret::new("my_random_seed_123".to_string());

    encrypt_file_password(
        &input,
        &enc,
        password.clone(),
        Some(seed.clone()),
        SecurityProfile::Paranoid,
    )
    .unwrap();

    // Test with correct seed
    decrypt_file_password(&enc, &dec, password.clone(), Some(seed.clone())).unwrap();
    let decrypted_content = fs::read(&dec).unwrap();
    assert_eq!(decrypted_content, b"Top secret cascaded data");

    // Test with WRONG seed
    let wrong_seed = Secret::new("wrong_seed".to_string());
    let dec_wrong = temp_dir().join("test_dec_wrong.txt");
    let res = decrypt_file_password(&enc, &dec_wrong, password.clone(), Some(wrong_seed));
    assert!(res.is_err());

    // Test with missing seed
    let res_missing = decrypt_file_password(&enc, &dec_wrong, password, None);
    assert!(res_missing.is_err());
}

#[test]
fn test_wrong_password_fails() {
    let input = temp_dir().join("test_input_wrong_pwd.txt");
    let enc = temp_dir().join("test_wrong_pwd.lvau");
    let dec = temp_dir().join("test_decrypted_wrong_pwd.txt");

    fs::write(&input, b"Secret Data").unwrap();

    let password = Secret::new("correct_password".to_string());
    let wrong_password = Secret::new("wrong_password".to_string());

    encrypt_file_password(&input, &enc, password, None, SecurityProfile::Fast).unwrap();

    let result = decrypt_file_password(&enc, &dec, wrong_password, None);
    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
}

#[test]
fn test_tampered_ciphertext_fails() {
    let input = temp_dir().join("test_input_tamper.txt");
    let enc = temp_dir().join("test_tamper.lvau");
    let dec = temp_dir().join("test_decrypted_tamper.txt");

    fs::write(&input, b"Data to be tampered").unwrap();

    let password = Secret::new("password123".to_string());
    encrypt_file_password(&input, &enc, password.clone(), None, SecurityProfile::Fast).unwrap();

    // Tamper with the ciphertext inside the envelope
    let encoded_envelope = fs::read(&enc).unwrap();
    let mut envelope: Envelope = postcard::from_bytes(&encoded_envelope).unwrap();

    if let Some(last_byte) = envelope.ciphertext.last_mut() {
        *last_byte ^= 0xFF; // Flip bits
    }

    let tampered_encoded = postcard::to_allocvec(&envelope).unwrap();
    fs::write(&enc, tampered_encoded).unwrap();

    let result = decrypt_file_password(&enc, &dec, password, None);
    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
}
