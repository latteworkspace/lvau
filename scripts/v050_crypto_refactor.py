#!/usr/bin/env python3
"""Connect existing v2 cryptographic paths to the shared v0.5.0 helpers.

The replacements preserve every existing HKDF label, nonce derivation rule, and
AAD byte sequence. The script is idempotent and is removed before release.
"""

from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]

parallel_path = ROOT / "crates/lvau-core/src/crypto/parallel.rs"
parallel = parallel_path.read_text(encoding="utf-8")
parallel = parallel.replace(
    "use super::{lco, AlgorithmId, CryptoError};",
    "use super::{\n    framing,\n    key_schedule::{derive_subkey, KeyPurpose},\n    lco, AlgorithmId, CryptoError,\n};",
)
parallel = re.sub(
    r"\nfn expand_key\(\n    hk: &Hkdf<Sha256>,\n    info: &'static \[u8\],\n    out: &mut \[u8; 32\],\n\) -> Result<\(\), CryptoError> \{\n    hk\.expand\(info, out\)\n        \.map_err\(\|_\| CryptoError::EncryptionFailed\)\n\}\n",
    "\n",
    parallel,
)
label_replacements = {
    'expand_key(hk, b"Lvau-file-encryption", &mut file_key)?;':
        'derive_subkey(hk, KeyPurpose::Payload, &mut file_key)?;',
    'expand_key(hk, b"Lvau-Cascade-AES", &mut key_aes)?;':
        'derive_subkey(hk, KeyPurpose::CascadeAes, &mut key_aes)?;',
    'expand_key(hk, b"Lvau-Cascade-XChaCha", &mut key_xchacha)?;':
        'derive_subkey(hk, KeyPurpose::CascadeXChaCha, &mut key_xchacha)?;',
    'expand_key(hk, b"Lvau-Cascade-LCO", &mut key_lco)?;':
        'derive_subkey(hk, KeyPurpose::LegacyLco, &mut key_lco)?;',
}
for old, new in label_replacements.items():
    parallel = parallel.replace(old, new)

nonce_block = """                    let mut chunk_nonce = *nonce_bytes;
                    let idx_bytes = chunk_idx.to_le_bytes();
                    for i in 0..8 {
                        chunk_nonce[i] ^= idx_bytes[i];
                    }

                    let mut chunk_aad = aad_hash.to_vec();
                    chunk_aad.extend_from_slice(&idx_bytes);
"""
nonce_replacement = """                    let chunk_nonce = framing::xchacha_nonce(nonce_bytes, chunk_idx);
                    let chunk_aad = framing::chunk_aad(aad_hash, chunk_idx);
"""
parallel = parallel.replace(nonce_block, nonce_replacement)
# Remove the now-obsolete binding from branches already transformed by an
# earlier bootstrap run.
parallel = parallel.replace(
    "                    let idx_bytes = chunk_idx.to_le_bytes();\n",
    "",
)

aes_block = """                            let sn_bytes =
                                secondary_nonce_bytes.ok_or(CryptoError::MissingSecondaryNonce)?;
                            let mut chunk_sn = sn_bytes;
                            for i in 0..8 {
                                chunk_sn[i] ^= idx_bytes[i];
                            }
"""
aes_replacement = """                            let sn_bytes =
                                secondary_nonce_bytes.ok_or(CryptoError::MissingSecondaryNonce)?;
                            let chunk_sn = framing::aes_nonce(&sn_bytes, chunk_idx);
"""
parallel = parallel.replace(aes_block, aes_replacement)
parallel = parallel.replace(
    "let chunk_idx = start_idx + local_idx as u64;",
    "let chunk_idx = start_idx\n                        .checked_add(local_idx as u64)\n                        .ok_or(CryptoError::Validation(\"Chunk index overflow\"))?;",
)
parallel = parallel.replace(
    "global_chunk_idx += num_chunks_in_batch as u64;",
    "global_chunk_idx = global_chunk_idx\n            .checked_add(num_chunks_in_batch as u64)\n            .ok_or(CryptoError::Validation(\"Chunk index overflow\"))?;",
)
parallel_path.write_text(parallel, encoding="utf-8")

crypto_path = ROOT / "crates/lvau-core/src/crypto/mod.rs"
crypto = crypto_path.read_text(encoding="utf-8")
crypto = re.sub(
    r"kw_hk\s*\.expand\(b\"Lvau-Key-Wrap\", &mut \*kwk\)\s*\.map_err\(\|_\| CryptoError::EncryptionFailed\)\?;",
    "key_schedule::derive_subkey(&kw_hk, key_schedule::KeyPurpose::KeyWrap, &mut *kwk)?;",
    crypto,
)
crypto_path.write_text(crypto, encoding="utf-8")
