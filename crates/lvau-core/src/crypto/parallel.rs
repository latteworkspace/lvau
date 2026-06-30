use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rayon::prelude::*;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::{lco, AlgorithmId, CryptoError};

pub const CHUNK_SIZE: usize = 1024 * 1024; // 1MB chunks

pub fn get_encrypted_chunk_size(algorithm: &AlgorithmId) -> usize {
    match algorithm {
        AlgorithmId::XChaCha20Poly1305 => CHUNK_SIZE + 16,
        AlgorithmId::CascadeAesGcmXChaCha => CHUNK_SIZE + 32,
        AlgorithmId::TripleCascadeAesXChaChaLco => CHUNK_SIZE + 32,
        _ => CHUNK_SIZE,
    }
}

pub fn parallel_encrypt_payload(
    algorithm: &AlgorithmId,
    plaintext: &[u8],
    hk: &Hkdf<Sha256>,
    nonce_bytes: &[u8; 24],
    secondary_nonce_bytes: Option<[u8; 12]>,
    aad_hash: &[u8; 32],
) -> Result<Vec<u8>, CryptoError> {
    let mut file_key = Zeroizing::new([0u8; 32]);
    let mut key_aes = Zeroizing::new([0u8; 32]);
    let mut key_xchacha = Zeroizing::new([0u8; 32]);
    let mut key_lco = Zeroizing::new([0u8; 32]);

    match algorithm {
        AlgorithmId::XChaCha20Poly1305 => {
            hk.expand(b"Lvau-file-encryption", &mut *file_key).unwrap();
        }
        AlgorithmId::CascadeAesGcmXChaCha => {
            hk.expand(b"Lvau-Cascade-AES", &mut *key_aes).unwrap();
            hk.expand(b"Lvau-Cascade-XChaCha", &mut *key_xchacha)
                .unwrap();
        }
        AlgorithmId::TripleCascadeAesXChaChaLco => {
            hk.expand(b"Lvau-Cascade-AES", &mut *key_aes).unwrap();
            hk.expand(b"Lvau-Cascade-XChaCha", &mut *key_xchacha)
                .unwrap();
            hk.expand(b"Lvau-Cascade-LCO", &mut *key_lco).unwrap();
        }
        _ => return Err(CryptoError::UnsupportedProfile),
    }

    let out_chunk_size = get_encrypted_chunk_size(algorithm);
    let tag_size = out_chunk_size - CHUNK_SIZE;

    let mut total_out_len = 0;
    if !plaintext.is_empty() {
        let num_chunks = (plaintext.len() + CHUNK_SIZE - 1) / CHUNK_SIZE;
        let last_chunk_len = plaintext.len() - (num_chunks - 1) * CHUNK_SIZE;
        total_out_len = (num_chunks - 1) * out_chunk_size + last_chunk_len + tag_size;
    }

    let mut ciphertext = vec![0u8; total_out_len];

    plaintext
        .par_chunks(CHUNK_SIZE)
        .zip(ciphertext.par_chunks_mut(out_chunk_size))
        .enumerate()
        .try_for_each(|(idx, (chunk, out_chunk))| -> Result<(), CryptoError> {
            let mut chunk_nonce = *nonce_bytes;
            let idx_bytes = (idx as u32).to_le_bytes();
            for i in 0..4 {
                chunk_nonce[i] ^= idx_bytes[i];
            }

            let encrypted = match algorithm {
                AlgorithmId::XChaCha20Poly1305 => {
                    let cipher = XChaCha20Poly1305::new(file_key.as_ref().into());
                    let nonce = XNonce::from(chunk_nonce);
                    cipher
                        .encrypt(
                            &nonce,
                            Payload {
                                msg: chunk,
                                aad: aad_hash,
                            },
                        )
                        .map_err(|_| CryptoError::EncryptionFailed)
                }
                AlgorithmId::CascadeAesGcmXChaCha => {
                    let sn_bytes = secondary_nonce_bytes.unwrap();
                    let mut chunk_sn = sn_bytes;
                    for i in 0..4 {
                        chunk_sn[i] ^= idx_bytes[i];
                    }

                    let aes_nonce = AesNonce::from(chunk_sn);
                    let aes_cipher = Aes256Gcm::new(key_aes.as_ref().into());
                    let c1 = aes_cipher
                        .encrypt(
                            &aes_nonce,
                            Payload {
                                msg: chunk,
                                aad: aad_hash,
                            },
                        )
                        .map_err(|_| CryptoError::EncryptionFailed)?;

                    let xchacha_nonce = XNonce::from(chunk_nonce);
                    let xchacha_cipher = XChaCha20Poly1305::new(key_xchacha.as_ref().into());
                    xchacha_cipher
                        .encrypt(
                            &xchacha_nonce,
                            Payload {
                                msg: &c1,
                                aad: aad_hash,
                            },
                        )
                        .map_err(|_| CryptoError::EncryptionFailed)
                }
                AlgorithmId::TripleCascadeAesXChaChaLco => {
                    let sn_bytes = secondary_nonce_bytes.unwrap();
                    let mut chunk_sn = sn_bytes;
                    for i in 0..4 {
                        chunk_sn[i] ^= idx_bytes[i];
                    }

                    let aes_nonce = AesNonce::from(chunk_sn);
                    let aes_cipher = Aes256Gcm::new(key_aes.as_ref().into());
                    let c1 = aes_cipher
                        .encrypt(
                            &aes_nonce,
                            Payload {
                                msg: chunk,
                                aad: aad_hash,
                            },
                        )
                        .map_err(|_| CryptoError::EncryptionFailed)?;

                    let xchacha_nonce = XNonce::from(chunk_nonce);
                    let xchacha_cipher = XChaCha20Poly1305::new(key_xchacha.as_ref().into());
                    let mut c2 = xchacha_cipher
                        .encrypt(
                            &xchacha_nonce,
                            Payload {
                                msg: &c1,
                                aad: aad_hash,
                            },
                        )
                        .map_err(|_| CryptoError::EncryptionFailed)?;

                    lco::apply_lco(&mut c2, &key_lco, &chunk_nonce);
                    Ok(c2)
                }
                _ => Err(CryptoError::UnsupportedProfile),
            }?;

            out_chunk.copy_from_slice(&encrypted);
            Ok(())
        })?;

    Ok(ciphertext)
}

pub fn parallel_decrypt_payload(
    algorithm: &AlgorithmId,
    ciphertext: &[u8],
    hk: &Hkdf<Sha256>,
    nonce_bytes: &[u8; 24],
    secondary_nonce_bytes: Option<[u8; 12]>,
    aad_hash: &[u8; 32],
) -> Result<Vec<u8>, CryptoError> {
    let mut file_key = Zeroizing::new([0u8; 32]);
    let mut key_aes = Zeroizing::new([0u8; 32]);
    let mut key_xchacha = Zeroizing::new([0u8; 32]);
    let mut key_lco = Zeroizing::new([0u8; 32]);

    match algorithm {
        AlgorithmId::XChaCha20Poly1305 => {
            hk.expand(b"Lvau-file-encryption", &mut *file_key).unwrap();
        }
        AlgorithmId::CascadeAesGcmXChaCha => {
            hk.expand(b"Lvau-Cascade-AES", &mut *key_aes).unwrap();
            hk.expand(b"Lvau-Cascade-XChaCha", &mut *key_xchacha)
                .unwrap();
        }
        AlgorithmId::TripleCascadeAesXChaChaLco => {
            hk.expand(b"Lvau-Cascade-AES", &mut *key_aes).unwrap();
            hk.expand(b"Lvau-Cascade-XChaCha", &mut *key_xchacha)
                .unwrap();
            hk.expand(b"Lvau-Cascade-LCO", &mut *key_lco).unwrap();
        }
        _ => return Err(CryptoError::UnsupportedProfile),
    }

    let encrypted_chunk_size = get_encrypted_chunk_size(algorithm);

    let tag_size = encrypted_chunk_size - CHUNK_SIZE;

    let mut total_out_len = 0;
    if !ciphertext.is_empty() {
        let num_chunks = (ciphertext.len() + encrypted_chunk_size - 1) / encrypted_chunk_size;
        let last_chunk_len = ciphertext.len() - (num_chunks - 1) * encrypted_chunk_size;
        if last_chunk_len < tag_size {
            return Err(CryptoError::DecryptionFailed);
        }
        total_out_len = (num_chunks - 1) * CHUNK_SIZE + (last_chunk_len - tag_size);
    }

    let mut plaintext = vec![0u8; total_out_len];

    ciphertext
        .par_chunks(encrypted_chunk_size)
        .zip(plaintext.par_chunks_mut(CHUNK_SIZE))
        .enumerate()
        .try_for_each(|(idx, (chunk, out_chunk))| -> Result<(), CryptoError> {
            let mut chunk_nonce = *nonce_bytes;
            let idx_bytes = (idx as u32).to_le_bytes();
            for i in 0..4 {
                chunk_nonce[i] ^= idx_bytes[i];
            }

            let decrypted = match algorithm {
                AlgorithmId::XChaCha20Poly1305 => {
                    let cipher = XChaCha20Poly1305::new(file_key.as_ref().into());
                    let nonce = XNonce::from(chunk_nonce);
                    cipher
                        .decrypt(
                            &nonce,
                            Payload {
                                msg: chunk,
                                aad: aad_hash,
                            },
                        )
                        .map_err(|_| CryptoError::DecryptionFailed)
                }
                AlgorithmId::CascadeAesGcmXChaCha => {
                    let sn_bytes = secondary_nonce_bytes.unwrap();
                    let mut chunk_sn = sn_bytes;
                    for i in 0..4 {
                        chunk_sn[i] ^= idx_bytes[i];
                    }

                    let xchacha_nonce = XNonce::from(chunk_nonce);
                    let xchacha_cipher = XChaCha20Poly1305::new(key_xchacha.as_ref().into());
                    let c1 = xchacha_cipher
                        .decrypt(
                            &xchacha_nonce,
                            Payload {
                                msg: chunk,
                                aad: aad_hash,
                            },
                        )
                        .map_err(|_| CryptoError::DecryptionFailed)?;

                    let aes_nonce = AesNonce::from(chunk_sn);
                    let aes_cipher = Aes256Gcm::new(key_aes.as_ref().into());
                    aes_cipher
                        .decrypt(
                            &aes_nonce,
                            Payload {
                                msg: &c1,
                                aad: aad_hash,
                            },
                        )
                        .map_err(|_| CryptoError::DecryptionFailed)
                }
                AlgorithmId::TripleCascadeAesXChaChaLco => {
                    let sn_bytes = secondary_nonce_bytes.unwrap();
                    let mut chunk_sn = sn_bytes;
                    for i in 0..4 {
                        chunk_sn[i] ^= idx_bytes[i];
                    }

                    let mut c2 = chunk.to_vec();
                    lco::apply_lco(&mut c2, &key_lco, &chunk_nonce);

                    let xchacha_nonce = XNonce::from(chunk_nonce);
                    let xchacha_cipher = XChaCha20Poly1305::new(key_xchacha.as_ref().into());
                    let c1 = xchacha_cipher
                        .decrypt(
                            &xchacha_nonce,
                            Payload {
                                msg: &c2,
                                aad: aad_hash,
                            },
                        )
                        .map_err(|_| CryptoError::DecryptionFailed)?;

                    let aes_nonce = AesNonce::from(chunk_sn);
                    let aes_cipher = Aes256Gcm::new(key_aes.as_ref().into());
                    aes_cipher
                        .decrypt(
                            &aes_nonce,
                            Payload {
                                msg: &c1,
                                aad: aad_hash,
                            },
                        )
                        .map_err(|_| CryptoError::DecryptionFailed)
                }
                _ => Err(CryptoError::UnsupportedProfile),
            }?;

            out_chunk.copy_from_slice(&decrypted);
            Ok(())
        })?;

    Ok(plaintext)
}
