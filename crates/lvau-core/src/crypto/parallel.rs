use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rayon::prelude::*;
use sha2::Sha256;
use std::io::{Read, Write};
use zeroize::Zeroizing;

use super::{lco, AlgorithmId, CryptoError};

/// Each chunk is 1 MiB. This size balances parallelism and memory usage.
pub const CHUNK_SIZE: usize = 1024 * 1024;
/// To maintain small memory footprint but utilize multiple cores, we process blocks of chunks.
pub const BATCH_CHUNKS: usize = 32; // 32 MiB per batch

pub fn get_encrypted_chunk_size(algorithm: &AlgorithmId) -> usize {
    match algorithm {
        AlgorithmId::XChaCha20Poly1305 => CHUNK_SIZE + 16,
        AlgorithmId::CascadeAesGcmXChaCha => CHUNK_SIZE + 32,
        AlgorithmId::TripleCascadeAesXChaChaLco => CHUNK_SIZE + 32,
        _ => CHUNK_SIZE,
    }
}

fn expand_key(
    hk: &Hkdf<Sha256>,
    info: &'static [u8],
    out: &mut [u8; 32],
) -> Result<(), CryptoError> {
    hk.expand(info, out)
        .map_err(|_| CryptoError::EncryptionFailed)
}

/// Encrypt plaintext in batches of 1 MiB chunks from a reader to a writer.
///
/// # Security invariants
/// - Each chunk gets a unique nonce derived by XORing the chunk index into
///   the first 4 bytes of the base nonce.
/// - Each chunk uses the header hash + chunk index as AEAD AAD, binding every chunk to the
///   envelope header and preventing chunk reordering attacks.
#[allow(clippy::too_many_arguments)]
pub fn stream_encrypt_payload(
    algorithm: &AlgorithmId,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    hk: &Hkdf<Sha256>,
    nonce_bytes: &[u8; 24],
    secondary_nonce_bytes: Option<[u8; 12]>,
    aad_hash: &[u8; 32],
    mut progress_callback: Option<&mut dyn FnMut(u64)>,
) -> Result<u64, CryptoError> {
    let mut file_key = Zeroizing::new([0u8; 32]);
    let mut key_aes = Zeroizing::new([0u8; 32]);
    let mut key_xchacha = Zeroizing::new([0u8; 32]);
    let mut key_lco = Zeroizing::new([0u8; 32]);

    match algorithm {
        AlgorithmId::XChaCha20Poly1305 => {
            expand_key(hk, b"Lvau-file-encryption", &mut file_key)?;
        }
        AlgorithmId::CascadeAesGcmXChaCha => {
            expand_key(hk, b"Lvau-Cascade-AES", &mut key_aes)?;
            expand_key(hk, b"Lvau-Cascade-XChaCha", &mut key_xchacha)?;
        }
        AlgorithmId::TripleCascadeAesXChaChaLco => {
            expand_key(hk, b"Lvau-Cascade-AES", &mut key_aes)?;
            expand_key(hk, b"Lvau-Cascade-XChaCha", &mut key_xchacha)?;
            expand_key(hk, b"Lvau-Cascade-LCO", &mut key_lco)?;
        }
        _ => return Err(CryptoError::UnsupportedProfile),
    }

    let mut total_bytes_read = 0u64;
    let mut global_chunk_idx = 0u64;

    loop {
        // Read a batch of chunks
        let mut batch_plaintext = Vec::new();
        for _ in 0..BATCH_CHUNKS {
            let mut chunk = vec![0u8; CHUNK_SIZE];
            let mut chunk_len = 0;
            while chunk_len < CHUNK_SIZE {
                let n = reader
                    .read(&mut chunk[chunk_len..])
                    .map_err(CryptoError::Io)?;
                if n == 0 {
                    break;
                }
                chunk_len += n;
            }
            if chunk_len > 0 {
                chunk.truncate(chunk_len);
                batch_plaintext.push(chunk);
            }
            if chunk_len < CHUNK_SIZE {
                break; // EOF reached
            }
        }

        if batch_plaintext.is_empty() {
            break;
        }

        let num_chunks_in_batch = batch_plaintext.len();
        let batch_bytes_read: usize = batch_plaintext.iter().map(|c| c.len()).sum();
        let mut batch_ciphertext: Vec<Vec<u8>> = vec![Vec::new(); num_chunks_in_batch];

        let start_idx = global_chunk_idx;

        batch_plaintext
            .into_par_iter()
            .zip(batch_ciphertext.par_iter_mut())
            .enumerate()
            .try_for_each(
                |(local_idx, (chunk, out_chunk))| -> Result<(), CryptoError> {
                    let chunk_idx = start_idx + local_idx as u64;

                    let mut chunk_nonce = *nonce_bytes;
                    let idx_bytes = chunk_idx.to_le_bytes();
                    for i in 0..8 {
                        chunk_nonce[i] ^= idx_bytes[i];
                    }

                    let mut chunk_aad = aad_hash.to_vec();
                    chunk_aad.extend_from_slice(&idx_bytes);

                    let encrypted = match algorithm {
                        AlgorithmId::XChaCha20Poly1305 => {
                            let cipher = XChaCha20Poly1305::new(file_key.as_ref().into());
                            let nonce = XNonce::from(chunk_nonce);
                            cipher
                                .encrypt(
                                    &nonce,
                                    Payload {
                                        msg: &chunk,
                                        aad: &chunk_aad,
                                    },
                                )
                                .map_err(|_| CryptoError::EncryptionFailed)
                        }
                        AlgorithmId::CascadeAesGcmXChaCha => {
                            let sn_bytes =
                                secondary_nonce_bytes.ok_or(CryptoError::MissingSecondaryNonce)?;
                            let mut chunk_sn = sn_bytes;
                            for i in 0..8 {
                                chunk_sn[i] ^= idx_bytes[i];
                            }

                            let aes_nonce = AesNonce::from(chunk_sn);
                            let aes_cipher = Aes256Gcm::new(key_aes.as_ref().into());
                            let c1 = aes_cipher
                                .encrypt(
                                    &aes_nonce,
                                    Payload {
                                        msg: &chunk,
                                        aad: &chunk_aad,
                                    },
                                )
                                .map_err(|_| CryptoError::EncryptionFailed)?;

                            let xchacha_nonce = XNonce::from(chunk_nonce);
                            let xchacha_cipher =
                                XChaCha20Poly1305::new(key_xchacha.as_ref().into());
                            xchacha_cipher
                                .encrypt(
                                    &xchacha_nonce,
                                    Payload {
                                        msg: &c1,
                                        aad: &chunk_aad,
                                    },
                                )
                                .map_err(|_| CryptoError::EncryptionFailed)
                        }
                        AlgorithmId::TripleCascadeAesXChaChaLco => {
                            let sn_bytes =
                                secondary_nonce_bytes.ok_or(CryptoError::MissingSecondaryNonce)?;
                            let mut chunk_sn = sn_bytes;
                            for i in 0..8 {
                                chunk_sn[i] ^= idx_bytes[i];
                            }

                            let aes_nonce = AesNonce::from(chunk_sn);
                            let aes_cipher = Aes256Gcm::new(key_aes.as_ref().into());
                            let c1 = aes_cipher
                                .encrypt(
                                    &aes_nonce,
                                    Payload {
                                        msg: &chunk,
                                        aad: &chunk_aad,
                                    },
                                )
                                .map_err(|_| CryptoError::EncryptionFailed)?;

                            let xchacha_nonce = XNonce::from(chunk_nonce);
                            let xchacha_cipher =
                                XChaCha20Poly1305::new(key_xchacha.as_ref().into());
                            let mut c2 = xchacha_cipher
                                .encrypt(
                                    &xchacha_nonce,
                                    Payload {
                                        msg: &c1,
                                        aad: &chunk_aad,
                                    },
                                )
                                .map_err(|_| CryptoError::EncryptionFailed)?;

                            lco::apply_lco(&mut c2, &key_lco, &chunk_nonce);
                            Ok(c2)
                        }
                        _ => Err(CryptoError::UnsupportedProfile),
                    }?;

                    *out_chunk = encrypted;
                    Ok(())
                },
            )?;

        for chunk_ct in batch_ciphertext {
            writer.write_all(&chunk_ct).map_err(CryptoError::Io)?;
        }

        total_bytes_read += batch_bytes_read as u64;
        global_chunk_idx += num_chunks_in_batch as u64;

        if let Some(ref mut cb) = progress_callback {
            cb(total_bytes_read);
        }

        if batch_bytes_read < BATCH_CHUNKS * CHUNK_SIZE {
            break;
        }
    }

    Ok(total_bytes_read)
}

#[allow(clippy::too_many_arguments)]
pub fn stream_decrypt_payload(
    algorithm: &AlgorithmId,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    hk: &Hkdf<Sha256>,
    nonce_bytes: &[u8; 24],
    secondary_nonce_bytes: Option<[u8; 12]>,
    aad_hash: &[u8; 32],
    plaintext_len: u64,
    mut progress_callback: Option<&mut dyn FnMut(u64)>,
) -> Result<(), CryptoError> {
    let mut file_key = Zeroizing::new([0u8; 32]);
    let mut key_aes = Zeroizing::new([0u8; 32]);
    let mut key_xchacha = Zeroizing::new([0u8; 32]);
    let mut key_lco = Zeroizing::new([0u8; 32]);

    match algorithm {
        AlgorithmId::XChaCha20Poly1305 => {
            expand_key(hk, b"Lvau-file-encryption", &mut file_key)?;
        }
        AlgorithmId::CascadeAesGcmXChaCha => {
            expand_key(hk, b"Lvau-Cascade-AES", &mut key_aes)?;
            expand_key(hk, b"Lvau-Cascade-XChaCha", &mut key_xchacha)?;
        }
        AlgorithmId::TripleCascadeAesXChaChaLco => {
            expand_key(hk, b"Lvau-Cascade-AES", &mut key_aes)?;
            expand_key(hk, b"Lvau-Cascade-XChaCha", &mut key_xchacha)?;
            expand_key(hk, b"Lvau-Cascade-LCO", &mut key_lco)?;
        }
        _ => return Err(CryptoError::UnsupportedProfile),
    }

    let encrypted_chunk_size = get_encrypted_chunk_size(algorithm);
    let tag_size = encrypted_chunk_size - CHUNK_SIZE;

    let mut total_bytes_written = 0u64;
    let mut global_chunk_idx = 0u64;
    let mut eof_reached = false;

    while !eof_reached {
        let mut batch_ciphertext = Vec::new();
        for _ in 0..BATCH_CHUNKS {
            // Determine expected chunk size based on remaining plaintext length
            let remaining = plaintext_len.saturating_sub(
                total_bytes_written + (batch_ciphertext.len() as u64 * CHUNK_SIZE as u64),
            );
            if remaining == 0 {
                eof_reached = true;
                break;
            }

            let expected_read_size = if remaining < CHUNK_SIZE as u64 {
                (remaining as usize) + tag_size
            } else {
                encrypted_chunk_size
            };

            let mut chunk = vec![0u8; expected_read_size];
            let mut chunk_len = 0;
            while chunk_len < expected_read_size {
                let n = reader
                    .read(&mut chunk[chunk_len..])
                    .map_err(CryptoError::Io)?;
                if n == 0 {
                    if chunk_len == 0 {
                        eof_reached = true;
                        break;
                    }
                    return Err(CryptoError::DecryptionFailed); // Truncated ciphertext
                }
                chunk_len += n;
            }

            if chunk_len > 0 {
                if chunk_len != expected_read_size {
                    return Err(CryptoError::DecryptionFailed); // Wrong chunk size
                }
                batch_ciphertext.push(chunk);
            }

            if remaining < CHUNK_SIZE as u64 {
                eof_reached = true;
                break;
            }
        }

        if batch_ciphertext.is_empty() {
            break;
        }

        let num_chunks_in_batch = batch_ciphertext.len();
        let mut batch_plaintext: Vec<Vec<u8>> = vec![Vec::new(); num_chunks_in_batch];
        let start_idx = global_chunk_idx;

        batch_ciphertext
            .into_par_iter()
            .zip(batch_plaintext.par_iter_mut())
            .enumerate()
            .try_for_each(
                |(local_idx, (chunk, out_chunk))| -> Result<(), CryptoError> {
                    let chunk_idx = start_idx + local_idx as u64;

                    let mut chunk_nonce = *nonce_bytes;
                    let idx_bytes = chunk_idx.to_le_bytes();
                    for i in 0..8 {
                        chunk_nonce[i] ^= idx_bytes[i];
                    }

                    let mut chunk_aad = aad_hash.to_vec();
                    chunk_aad.extend_from_slice(&idx_bytes);

                    let decrypted = match algorithm {
                        AlgorithmId::XChaCha20Poly1305 => {
                            let cipher = XChaCha20Poly1305::new(file_key.as_ref().into());
                            let nonce = XNonce::from(chunk_nonce);
                            cipher
                                .decrypt(
                                    &nonce,
                                    Payload {
                                        msg: &chunk,
                                        aad: &chunk_aad,
                                    },
                                )
                                .map_err(|_| CryptoError::DecryptionFailed)
                        }
                        AlgorithmId::CascadeAesGcmXChaCha => {
                            let sn_bytes =
                                secondary_nonce_bytes.ok_or(CryptoError::MissingSecondaryNonce)?;
                            let mut chunk_sn = sn_bytes;
                            for i in 0..8 {
                                chunk_sn[i] ^= idx_bytes[i];
                            }

                            let xchacha_nonce = XNonce::from(chunk_nonce);
                            let xchacha_cipher =
                                XChaCha20Poly1305::new(key_xchacha.as_ref().into());
                            let c1 = xchacha_cipher
                                .decrypt(
                                    &xchacha_nonce,
                                    Payload {
                                        msg: &chunk,
                                        aad: &chunk_aad,
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
                                        aad: &chunk_aad,
                                    },
                                )
                                .map_err(|_| CryptoError::DecryptionFailed)
                        }
                        AlgorithmId::TripleCascadeAesXChaChaLco => {
                            let sn_bytes =
                                secondary_nonce_bytes.ok_or(CryptoError::MissingSecondaryNonce)?;
                            let mut chunk_sn = sn_bytes;
                            for i in 0..8 {
                                chunk_sn[i] ^= idx_bytes[i];
                            }

                            let mut c2 = chunk.clone();
                            lco::apply_lco(&mut c2, &key_lco, &chunk_nonce);

                            let xchacha_nonce = XNonce::from(chunk_nonce);
                            let xchacha_cipher =
                                XChaCha20Poly1305::new(key_xchacha.as_ref().into());
                            let c1 = xchacha_cipher
                                .decrypt(
                                    &xchacha_nonce,
                                    Payload {
                                        msg: &c2,
                                        aad: &chunk_aad,
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
                                        aad: &chunk_aad,
                                    },
                                )
                                .map_err(|_| CryptoError::DecryptionFailed)
                        }
                        _ => Err(CryptoError::UnsupportedProfile),
                    }?;

                    *out_chunk = decrypted;
                    Ok(())
                },
            )?;

        let mut batch_bytes_written = 0u64;
        for chunk_pt in batch_plaintext {
            writer.write_all(&chunk_pt).map_err(CryptoError::Io)?;
            batch_bytes_written += chunk_pt.len() as u64;
        }

        total_bytes_written += batch_bytes_written;
        global_chunk_idx += num_chunks_in_batch as u64;

        if let Some(ref mut cb) = progress_callback {
            cb(total_bytes_written);
        }
    }

    if total_bytes_written != plaintext_len {
        return Err(CryptoError::DecryptionFailed);
    }

    Ok(())
}
