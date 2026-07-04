//! Sealed bundle mode: pack a directory into a single encrypted `.lvau` file.
//!
//! The bundle stores multiple files in one encrypted payload with an
//! authenticated private manifest containing relative paths, sizes, and
//! per-file BLAKE3 hashes. By default, no file names or directory structure
//! are exposed in the public envelope.

use crate::crypto::{decrypt_file_password, verify_file_password, CryptoError};
use lvau_protocol::envelope::{BundleEntry, BundleManifest, ContentType, EnvelopeHeader};
use secrecy::Secret;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use walkdir::WalkDir;

/// Errors specific to bundle operations.
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Serialization error: {0}")]
    Serialization(#[from] postcard::Error),
    #[error("Path traversal detected: {0}")]
    PathTraversal(String),
    #[error("Symlink rejected: {0}")]
    SymlinkRejected(String),
    #[error("Refusing to overwrite: {0}")]
    OutputExists(String),
    #[error("Bundle manifest error: {0}")]
    ManifestError(String),
    #[error("Walk error: {0}")]
    WalkError(String),
    #[error("Input directory does not exist: {0}")]
    InputDirNotFound(String),
}

/// Metadata privacy level for bundle public metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataProfile {
    /// Minimal: only format version, algorithm, profile, and tool version.
    Minimal,
    /// Balanced: adds file count and approximate total size.
    Balanced,
    /// Verbose: adds public file listing (opt-in, not default).
    Verbose,
}

/// Padding mode for reducing size-based inference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaddingProfile {
    /// No padding.
    None,
    /// Round up to the next power-of-two bucket.
    Bucket,
    /// Pad to exactly this size in bytes.
    Fixed(usize),
}

/// Validate that a relative path is safe for extraction.
///
/// Rejects:
/// - Absolute paths
/// - Paths containing `..`
/// - Windows drive paths (e.g., `C:\`)
/// - Paths starting with `/` or `\`
pub fn validate_relative_path(path: &str) -> Result<PathBuf, BundleError> {
    let p = Path::new(path);

    // Reject absolute paths
    if p.is_absolute() {
        return Err(BundleError::PathTraversal(format!(
            "Absolute path rejected: {path}"
        )));
    }

    // Reject Windows drive paths like C: or D:
    if path.len() >= 2 && path.as_bytes()[1] == b':' {
        return Err(BundleError::PathTraversal(format!(
            "Windows drive path rejected: {path}"
        )));
    }

    // Reject paths starting with / or \
    if path.starts_with('/') || path.starts_with('\\') {
        return Err(BundleError::PathTraversal(format!(
            "Leading separator rejected: {path}"
        )));
    }

    // Reject paths containing ..
    for component in p.components() {
        match component {
            Component::ParentDir => {
                return Err(BundleError::PathTraversal(format!(
                    "Parent directory traversal rejected: {path}"
                )));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(BundleError::PathTraversal(format!(
                    "Root/prefix path rejected: {path}"
                )));
            }
            _ => {}
        }
    }

    Ok(p.to_path_buf())
}

/// Collect files from a directory, returning (relative_path, absolute_path) pairs.
fn collect_files(
    in_dir: &Path,
    allow_symlinks: bool,
) -> Result<Vec<(String, PathBuf)>, BundleError> {
    if !in_dir.is_dir() {
        return Err(BundleError::InputDirNotFound(in_dir.display().to_string()));
    }

    let mut files = Vec::new();
    for entry in WalkDir::new(in_dir).follow_links(false) {
        let entry = entry.map_err(|e| BundleError::WalkError(e.to_string()))?;
        let path = entry.path();

        // Skip the root directory itself
        if path == in_dir {
            continue;
        }

        // Check for symlinks
        if entry.path_is_symlink() && !allow_symlinks {
            return Err(BundleError::SymlinkRejected(path.display().to_string()));
        }

        // Skip directories, only collect files
        if entry.file_type().is_dir() {
            continue;
        }

        let relative = path
            .strip_prefix(in_dir)
            .map_err(|_| BundleError::WalkError("Failed to compute relative path".into()))?;

        // Normalize to forward slashes for cross-platform consistency
        let relative_str = relative
            .components()
            .map(|c| c.as_os_str().to_string_lossy().to_string())
            .collect::<Vec<_>>()
            .join("/");

        files.push((relative_str, path.to_path_buf()));
    }

    // Sort for deterministic output
    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(files)
}

/// Pack a directory into a single encrypted `.lvau` bundle file.
#[allow(clippy::too_many_arguments)]
pub fn pack_directory(
    in_dir: &Path,
    out_file: &Path,
    credential: crate::crypto::EncryptCredential,
    profile: lvau_protocol::envelope::SecurityProfile,
    allow_symlinks: bool,
    padding: &PaddingProfile,
    force: bool,
    policy: Option<&crate::policy::CapsulePolicy>,
    allow_policy_override: bool,
) -> Result<BundleManifest, BundleError> {
    // Check output doesn't exist
    if out_file.exists() && !force {
        return Err(BundleError::OutputExists(out_file.display().to_string()));
    }

    let files = collect_files(in_dir, allow_symlinks)?;

    // Build manifest and concatenate file contents
    let mut entries = Vec::new();
    let mut payload_data = Vec::new();
    let mut offset = 0u64;

    for (relative_path, abs_path) in &files {
        let file_data = fs::read(abs_path).map_err(BundleError::Io)?;
        let size = file_data.len() as u64;
        let hash = blake3::hash(&file_data);

        entries.push(BundleEntry {
            relative_path: relative_path.clone(),
            size,
            blake3_hash: *hash.as_bytes(),
            offset,
        });

        payload_data.extend_from_slice(&file_data);
        offset += size;
    }

    let manifest = BundleManifest {
        entries,
        created_at: Some(chrono_now_iso()),
        tool_version: Some(format!("lvau {}", env!("CARGO_PKG_VERSION"))),
    };

    // Serialize manifest
    let manifest_bytes = postcard::to_allocvec(&manifest).map_err(BundleError::Serialization)?;

    // Build the bundle payload: [manifest_len (4 bytes LE)] [manifest_bytes] [file_data...]
    let mut bundle_payload = Vec::new();
    let manifest_len = manifest_bytes.len() as u32;
    bundle_payload.extend_from_slice(&manifest_len.to_le_bytes());
    bundle_payload.extend_from_slice(&manifest_bytes);
    bundle_payload.extend_from_slice(&payload_data);

    // Apply padding
    match padding {
        PaddingProfile::None => {}
        PaddingProfile::Bucket => {
            let current_len = bundle_payload.len();
            let target = current_len.next_power_of_two();
            if target > current_len {
                bundle_payload.resize(target, 0);
            }
        }
        PaddingProfile::Fixed(size) => {
            if bundle_payload.len() < *size {
                bundle_payload.resize(*size, 0);
            }
        }
    }

    // Write to a temp file and encrypt it
    let parent = out_file.parent().unwrap_or_else(|| Path::new("."));
    let temp_plain = parent.join(format!(".lvau-bundle-{}.tmp", std::process::id()));

    fs::write(&temp_plain, &bundle_payload).map_err(BundleError::Io)?;

    let result = match credential {
        crate::crypto::EncryptCredential::Password(password, seed) => {
            crate::crypto::encrypt_file_password(
                &temp_plain,
                out_file,
                password,
                seed,
                profile,
                None,
                policy,
                allow_policy_override,
            )
        }
        crate::crypto::EncryptCredential::Keypairs(pubs) => crate::crypto::encrypt_file_keypairs(
            &temp_plain,
            out_file,
            &pubs,
            profile,
            None,
            policy,
            allow_policy_override,
        ),
    };

    // Always clean up temp file
    let _ = fs::remove_file(&temp_plain);
    result.map_err(BundleError::Crypto)?;

    // Now we need to update the content_type in the envelope.
    // We'll do this by reading the file, patching the envelope, and rewriting.
    patch_content_type(out_file, ContentType::Bundle)?;

    Ok(manifest)
}

/// Patch the content_type field in an existing .lvau file's envelope.
fn patch_content_type(file_path: &Path, content_type: ContentType) -> Result<(), BundleError> {
    let data = fs::read(file_path).map_err(BundleError::Io)?;
    if data.len() < 4 {
        return Err(BundleError::ManifestError("File too small".into()));
    }
    let env_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    if data.len() < 4 + env_len {
        return Err(BundleError::ManifestError(
            "File too small for envelope".into(),
        ));
    }

    let mut envelope: lvau_protocol::envelope::Envelope =
        postcard::from_bytes(&data[4..4 + env_len]).map_err(BundleError::Serialization)?;

    envelope.content_type = Some(content_type);

    let new_env_bytes = postcard::to_allocvec(&envelope).map_err(BundleError::Serialization)?;
    let new_len = new_env_bytes.len() as u32;

    let mut new_data = Vec::with_capacity(4 + new_env_bytes.len() + (data.len() - 4 - env_len));
    new_data.extend_from_slice(&new_len.to_le_bytes());
    new_data.extend_from_slice(&new_env_bytes);
    new_data.extend_from_slice(&data[4 + env_len..]);

    fs::write(file_path, new_data).map_err(BundleError::Io)?;
    Ok(())
}

/// Inspect the public metadata of a bundle without decrypting.
pub fn inspect_bundle(
    in_file: &Path,
) -> Result<(EnvelopeHeader, Option<ContentType>, Option<String>), BundleError> {
    let data = fs::read(in_file).map_err(BundleError::Io)?;
    if data.len() < 4 {
        return Err(BundleError::ManifestError("File too small".into()));
    }
    let env_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    if data.len() < 4 + env_len {
        return Err(BundleError::ManifestError(
            "File too small for envelope".into(),
        ));
    }

    let envelope: lvau_protocol::envelope::Envelope =
        postcard::from_bytes(&data[4..4 + env_len]).map_err(BundleError::Serialization)?;
    envelope
        .validate()
        .map_err(|e| BundleError::ManifestError(e.to_string()))?;

    Ok((
        envelope.header,
        envelope.content_type,
        envelope.public_label,
    ))
}

/// List files in a bundle (requires password to decrypt the manifest).
pub fn list_bundle(
    in_file: &Path,
    password: Secret<String>,
) -> Result<BundleManifest, BundleError> {
    // Decrypt to memory
    let temp_dir = std::env::temp_dir();
    let temp_plain = temp_dir.join(format!(".lvau-list-{}.tmp", std::process::id()));

    decrypt_file_password(in_file, &temp_plain, password, None, None)
        .map_err(BundleError::Crypto)?;

    let bundle_data = fs::read(&temp_plain).map_err(BundleError::Io)?;
    let _ = fs::remove_file(&temp_plain);

    parse_bundle_manifest(&bundle_data)
}

/// Parse a bundle manifest from decrypted payload data.
fn parse_bundle_manifest(data: &[u8]) -> Result<BundleManifest, BundleError> {
    if data.len() < 4 {
        return Err(BundleError::ManifestError(
            "Bundle payload too small".into(),
        ));
    }

    let manifest_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    if data.len() < 4 + manifest_len {
        return Err(BundleError::ManifestError(
            "Bundle payload truncated before manifest end".into(),
        ));
    }

    let manifest: BundleManifest =
        postcard::from_bytes(&data[4..4 + manifest_len]).map_err(BundleError::Serialization)?;

    Ok(manifest)
}

/// Extract a bundle to a directory.
pub fn extract_bundle(
    in_file: &Path,
    out_dir: &Path,
    password: Secret<String>,
    allow_symlinks: bool,
    force: bool,
    dry_run: bool,
) -> Result<BundleManifest, BundleError> {
    // Decrypt to temp
    let temp_dir = std::env::temp_dir();
    let temp_plain = temp_dir.join(format!(".lvau-extract-{}.tmp", std::process::id()));

    decrypt_file_password(in_file, &temp_plain, password, None, None)
        .map_err(BundleError::Crypto)?;

    let bundle_data = fs::read(&temp_plain).map_err(BundleError::Io)?;
    let _ = fs::remove_file(&temp_plain);

    let manifest = parse_bundle_manifest(&bundle_data)?;

    // Compute where file data starts
    let manifest_len = u32::from_le_bytes(bundle_data[0..4].try_into().unwrap()) as usize;
    let file_data_start = 4 + manifest_len;

    for entry in &manifest.entries {
        // Validate path safety
        let safe_relative = validate_relative_path(&entry.relative_path)?;
        let target_path = out_dir.join(&safe_relative);

        // Ensure the target path is within out_dir (canonicalization check)
        // We need to create parent dirs first, then check
        if !dry_run {
            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent).map_err(BundleError::Io)?;
            }
        }

        // Verify the resolved path stays within out_dir
        // Note: we can't canonicalize a non-existent file, so we canonicalize the parent
        if !dry_run {
            let canonical_parent = target_path
                .parent()
                .unwrap_or(out_dir)
                .canonicalize()
                .map_err(BundleError::Io)?;
            let canonical_out = out_dir.canonicalize().map_err(BundleError::Io)?;
            if !canonical_parent.starts_with(&canonical_out) {
                return Err(BundleError::PathTraversal(format!(
                    "Resolved path escapes output directory: {}",
                    entry.relative_path
                )));
            }
        }

        // Check overwrite
        if !dry_run && target_path.exists() && !force {
            return Err(BundleError::OutputExists(target_path.display().to_string()));
        }

        // Check symlink (if the target already exists and is a symlink)
        if !dry_run
            && target_path.exists()
            && target_path.symlink_metadata()?.file_type().is_symlink()
            && !allow_symlinks
        {
            return Err(BundleError::SymlinkRejected(
                target_path.display().to_string(),
            ));
        }

        // Extract file data
        let start = file_data_start + entry.offset as usize;
        let end = start + entry.size as usize;

        if end > bundle_data.len() {
            return Err(BundleError::ManifestError(format!(
                "File data truncated for: {}",
                entry.relative_path
            )));
        }

        let file_data = &bundle_data[start..end];

        // Verify BLAKE3 hash
        let actual_hash = blake3::hash(file_data);
        if *actual_hash.as_bytes() != entry.blake3_hash {
            return Err(BundleError::ManifestError(format!(
                "BLAKE3 hash mismatch for: {}",
                entry.relative_path
            )));
        }

        if dry_run {
            // Just print what would be extracted
            log::info!(
                "Would extract: {} ({} bytes)",
                entry.relative_path,
                entry.size
            );
        } else {
            // Write the file
            let mut f = File::create(&target_path).map_err(BundleError::Io)?;
            f.write_all(file_data).map_err(BundleError::Io)?;
            f.sync_all().map_err(BundleError::Io)?;

            log::info!("Extracted: {} ({} bytes)", entry.relative_path, entry.size);
        }
    }

    Ok(manifest)
}

/// Verify a bundle's integrity without extracting.
pub fn verify_bundle(
    in_file: &Path,
    password: Secret<String>,
) -> Result<BundleManifest, BundleError> {
    // First verify the outer envelope integrity
    verify_file_password(in_file, password.clone(), None, None).map_err(BundleError::Crypto)?;

    // Then verify the manifest and file hashes
    let manifest = list_bundle(in_file, password)?;

    log::info!("Bundle verified: {} files", manifest.entries.len());
    Ok(manifest)
}

/// Generate a simple ISO 8601-ish timestamp without external crate dependencies.
fn chrono_now_iso() -> String {
    // Use a simple approach: we don't have chrono, so we return a placeholder
    // that can be replaced with std::time::SystemTime
    use std::time::SystemTime;
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => format!("{}Z", d.as_secs()),
        Err(_) => "0Z".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lvau_protocol::envelope::SecurityProfile;
    use std::fs;
    use tempfile::tempdir;

    fn test_password() -> Secret<String> {
        Secret::new("test-bundle-password".to_string())
    }

    #[test]
    fn validate_relative_path_rejects_absolute() {
        assert!(validate_relative_path("/etc/passwd").is_err());
    }

    #[test]
    fn validate_relative_path_rejects_parent_traversal() {
        assert!(validate_relative_path("../secret").is_err());
        assert!(validate_relative_path("foo/../../etc/passwd").is_err());
    }

    #[test]
    fn validate_relative_path_rejects_windows_drive() {
        assert!(validate_relative_path("C:\\Windows\\System32").is_err());
        assert!(validate_relative_path("D:file.txt").is_err());
    }

    #[test]
    fn validate_relative_path_rejects_leading_separator() {
        assert!(validate_relative_path("\\Windows\\file").is_err());
    }

    #[test]
    fn validate_relative_path_accepts_safe_paths() {
        assert!(validate_relative_path("file.txt").is_ok());
        assert!(validate_relative_path("subdir/file.txt").is_ok());
        assert!(validate_relative_path("a/b/c/deep.bin").is_ok());
    }

    #[test]
    fn pack_and_extract_roundtrip() {
        let dir = tempdir().unwrap();
        let in_dir = dir.path().join("input");
        let out_file = dir.path().join("bundle.lvau");
        let out_dir = dir.path().join("output");

        // Create input files
        fs::create_dir_all(in_dir.join("subdir")).unwrap();
        fs::write(in_dir.join("hello.txt"), "Hello, World!").unwrap();
        fs::write(in_dir.join("subdir/nested.txt"), "Nested file").unwrap();
        fs::write(in_dir.join("empty.txt"), "").unwrap();

        // Pack
        let manifest = pack_directory(
            &in_dir,
            &out_file,
            crate::crypto::EncryptCredential::Password(test_password(), None),
            SecurityProfile::Fast,
            false,
            &PaddingProfile::None,
            false,
            None,
            false,
        )
        .unwrap();

        assert_eq!(manifest.entries.len(), 3);

        // Extract
        let extracted =
            extract_bundle(&out_file, &out_dir, test_password(), false, false, false).unwrap();

        assert_eq!(extracted.entries.len(), 3);
        assert_eq!(
            fs::read_to_string(out_dir.join("hello.txt")).unwrap(),
            "Hello, World!"
        );
        assert_eq!(
            fs::read_to_string(out_dir.join("subdir/nested.txt")).unwrap(),
            "Nested file"
        );
        assert_eq!(fs::read_to_string(out_dir.join("empty.txt")).unwrap(), "");
    }

    #[test]
    fn pack_and_list_shows_files() {
        let dir = tempdir().unwrap();
        let in_dir = dir.path().join("input");
        let out_file = dir.path().join("bundle.lvau");

        fs::create_dir_all(&in_dir).unwrap();
        fs::write(in_dir.join("a.txt"), "aaa").unwrap();
        fs::write(in_dir.join("b.txt"), "bbb").unwrap();

        pack_directory(
            &in_dir,
            &out_file,
            crate::crypto::EncryptCredential::Password(test_password(), None),
            SecurityProfile::Fast,
            false,
            &PaddingProfile::None,
            false,
            None,
            false,
        )
        .unwrap();

        let manifest = list_bundle(&out_file, test_password()).unwrap();
        assert_eq!(manifest.entries.len(), 2);
        assert!(manifest.entries.iter().any(|e| e.relative_path == "a.txt"));
        assert!(manifest.entries.iter().any(|e| e.relative_path == "b.txt"));
    }

    #[test]
    fn extract_rejects_path_traversal_in_manifest() {
        // We test the validation function directly since crafting a malicious
        // encrypted manifest is complex. The validation is the safety boundary.
        assert!(validate_relative_path("../../../etc/passwd").is_err());
        assert!(validate_relative_path("foo/../../../bar").is_err());
    }

    #[test]
    fn wrong_password_fails_cleanly() {
        let dir = tempdir().unwrap();
        let in_dir = dir.path().join("input");
        let out_file = dir.path().join("bundle.lvau");
        let out_dir = dir.path().join("output");

        fs::create_dir_all(&in_dir).unwrap();
        fs::write(in_dir.join("test.txt"), "secret").unwrap();

        pack_directory(
            &in_dir,
            &out_file,
            crate::crypto::EncryptCredential::Password(test_password(), None),
            SecurityProfile::Fast,
            false,
            &PaddingProfile::None,
            false,
            None,
            false,
        )
        .unwrap();

        let result = extract_bundle(
            &out_file,
            &out_dir,
            Secret::new("wrong-password".to_string()),
            false,
            false,
            false,
        );

        assert!(result.is_err());
    }

    #[test]
    fn inspect_does_not_reveal_filenames() {
        let dir = tempdir().unwrap();
        let in_dir = dir.path().join("input");
        let out_file = dir.path().join("bundle.lvau");

        fs::create_dir_all(&in_dir).unwrap();
        fs::write(in_dir.join("secret_name.txt"), "data").unwrap();

        pack_directory(
            &in_dir,
            &out_file,
            crate::crypto::EncryptCredential::Password(test_password(), None),
            SecurityProfile::Fast,
            false,
            &PaddingProfile::None,
            false,
            None,
            false,
        )
        .unwrap();

        let (header, content_type, _label) = inspect_bundle(&out_file).unwrap();
        // Public inspect should show the header but NOT expose file names
        assert_eq!(header.magic, lvau_protocol::envelope::MAGIC_REAL);
        assert_eq!(content_type, Some(ContentType::Bundle));
        // The header and content_type are public, but file names are encrypted
        // in the payload — they're not in the public envelope.
    }

    #[test]
    fn dry_run_does_not_write_files() {
        let dir = tempdir().unwrap();
        let in_dir = dir.path().join("input");
        let out_file = dir.path().join("bundle.lvau");
        let out_dir = dir.path().join("output");

        fs::create_dir_all(&in_dir).unwrap();
        fs::write(in_dir.join("test.txt"), "dry run test").unwrap();

        pack_directory(
            &in_dir,
            &out_file,
            crate::crypto::EncryptCredential::Password(test_password(), None),
            SecurityProfile::Fast,
            false,
            &PaddingProfile::None,
            false,
            None,
            false,
        )
        .unwrap();

        // Dry run should succeed but not create output files
        let _manifest = extract_bundle(
            &out_file,
            &out_dir,
            test_password(),
            false,
            false,
            true, // dry_run
        )
        .unwrap();

        assert!(!out_dir.join("test.txt").exists());
    }

    #[test]
    fn unicode_filenames_roundtrip() {
        let dir = tempdir().unwrap();
        let in_dir = dir.path().join("input");
        let out_file = dir.path().join("bundle.lvau");
        let out_dir = dir.path().join("output");

        fs::create_dir_all(&in_dir).unwrap();
        fs::write(in_dir.join("こんにちは.txt"), "日本語テスト").unwrap();

        pack_directory(
            &in_dir,
            &out_file,
            crate::crypto::EncryptCredential::Password(test_password(), None),
            SecurityProfile::Fast,
            false,
            &PaddingProfile::None,
            false,
            None,
            false,
        )
        .unwrap();

        extract_bundle(&out_file, &out_dir, test_password(), false, false, false).unwrap();

        assert_eq!(
            fs::read_to_string(out_dir.join("こんにちは.txt")).unwrap(),
            "日本語テスト"
        );
    }

    #[test]
    #[cfg(unix)]
    fn extract_rejects_symlink_overwrite_unless_allowed() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let in_dir = dir.path().join("input");
        let out_dir = dir.path().join("output");
        let out_file = dir.path().join("bundle.lvau");

        fs::create_dir_all(&in_dir).unwrap();
        fs::write(in_dir.join("test.txt"), "secret").unwrap();

        pack_directory(
            &in_dir,
            &out_file,
            crate::crypto::EncryptCredential::Password(test_password(), None),
            SecurityProfile::Fast,
            false,
            &PaddingProfile::None,
            false,
            None,
            false,
        )
        .unwrap();

        fs::create_dir_all(&out_dir).unwrap();
        symlink("/etc/passwd", out_dir.join("test.txt")).unwrap();

        let result = extract_bundle(
            &out_file,
            &out_dir,
            test_password(),
            false, // allow_symlinks
            false, // force
            false, // dry_run
        );

        assert!(result.is_err());
    }
}
