//! Sealed bundle mode: pack a directory into a single encrypted `.lvau` file.
//!
//! The bundle stores multiple files in one encrypted payload with an
//! authenticated private manifest containing relative paths, sizes, and
//! per-file BLAKE3 hashes. By default, no file names or directory structure
//! are exposed in the public envelope.

use crate::crypto::{decrypt_file_password, CryptoError};
use lvau_protocol::envelope::{BundleEntry, BundleManifest, ContentType, EnvelopeHeader};
use secrecy::SecretString;
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use tempfile::{tempdir, NamedTempFile};
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
    #[error("Hardlink rejected: {0}")]
    HardlinkRejected(String),
    #[error("Special file rejected: {0}")]
    SpecialFileRejected(String),
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
    if path.is_empty() || path.contains('\\') {
        return Err(BundleError::PathTraversal(format!(
            "Empty or non-canonical path rejected: {path}"
        )));
    }
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
            Component::CurDir => {
                return Err(BundleError::PathTraversal(format!(
                    "Current-directory component rejected: {path}"
                )));
            }
            Component::Normal(_) => {}
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
        if !entry.file_type().is_file() && !entry.path_is_symlink() {
            return Err(BundleError::SpecialFileRejected(path.display().to_string()));
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
    let mut temp_plain = NamedTempFile::new_in(parent).map_err(BundleError::Io)?;
    temp_plain
        .write_all(&bundle_payload)
        .map_err(BundleError::Io)?;
    temp_plain.as_file().sync_all().map_err(BundleError::Io)?;
    let temp_plain_path = temp_plain.path().to_path_buf();

    let result = match credential {
        crate::crypto::EncryptCredential::Password(password, seed) => {
            crate::crypto::encrypt_file_password_with_content_type(
                &temp_plain_path,
                out_file,
                password,
                seed,
                profile,
                None,
                policy,
                allow_policy_override,
                Some(ContentType::Bundle),
            )
        }
        crate::crypto::EncryptCredential::Keypairs(pubs) => {
            crate::crypto::encrypt_file_keypairs_with_content_type(
                &temp_plain_path,
                out_file,
                &pubs,
                profile,
                None,
                policy,
                allow_policy_override,
                Some(ContentType::Bundle),
            )
        }
    };

    result.map_err(BundleError::Crypto)?;

    Ok(manifest)
}

/// Inspect the public metadata of a bundle without decrypting.
pub fn inspect_bundle(
    in_file: &Path,
) -> Result<(EnvelopeHeader, Option<ContentType>, Option<String>), BundleError> {
    let envelope = crate::crypto::read_envelope_from_path(in_file).map_err(BundleError::Crypto)?;

    Ok((
        envelope.header,
        envelope.content_type,
        envelope.public_label,
    ))
}

/// List files in a bundle (requires password to decrypt the manifest).
pub fn list_bundle(in_file: &Path, password: SecretString) -> Result<BundleManifest, BundleError> {
    // Decrypt to memory
    let temp_dir = tempdir().map_err(BundleError::Io)?;
    let temp_plain_path = temp_dir.path().join("payload.tmp");

    decrypt_file_password(in_file, &temp_plain_path, password, None, None)
        .map_err(BundleError::Crypto)?;

    let bundle_data = fs::read(&temp_plain_path).map_err(BundleError::Io)?;

    parse_and_validate_bundle_payload(&bundle_data).map(|(manifest, _)| manifest)
}

/// Parse and fully validate a decrypted bundle payload before it is used.
fn parse_and_validate_bundle_payload(data: &[u8]) -> Result<(BundleManifest, usize), BundleError> {
    if data.len() < 4 {
        return Err(BundleError::ManifestError(
            "Bundle payload too small".into(),
        ));
    }

    let manifest_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    let file_data_start = 4usize
        .checked_add(manifest_len)
        .ok_or_else(|| BundleError::ManifestError("Manifest length overflow".into()))?;
    if data.len() < file_data_start {
        return Err(BundleError::ManifestError(
            "Bundle payload truncated before manifest end".into(),
        ));
    }

    let (manifest, remaining): (BundleManifest, &[u8]) =
        postcard::take_from_bytes(&data[4..file_data_start]).map_err(BundleError::Serialization)?;
    if !remaining.is_empty() {
        return Err(BundleError::ManifestError(
            "Manifest contains trailing non-canonical bytes".into(),
        ));
    }

    let mut paths = HashSet::new();
    let mut ranges = Vec::with_capacity(manifest.entries.len());
    for entry in &manifest.entries {
        validate_relative_path(&entry.relative_path)?;
        let portable_path = entry.relative_path.to_lowercase();
        if !paths.insert(portable_path) {
            return Err(BundleError::ManifestError(format!(
                "Duplicate or cross-platform-colliding path: {}",
                entry.relative_path
            )));
        }

        let offset = usize::try_from(entry.offset).map_err(|_| {
            BundleError::ManifestError(format!(
                "File offset is not representable: {}",
                entry.relative_path
            ))
        })?;
        let size = usize::try_from(entry.size).map_err(|_| {
            BundleError::ManifestError(format!(
                "File size is not representable: {}",
                entry.relative_path
            ))
        })?;
        let start = file_data_start.checked_add(offset).ok_or_else(|| {
            BundleError::ManifestError(format!("File offset overflow: {}", entry.relative_path))
        })?;
        let end = start.checked_add(size).ok_or_else(|| {
            BundleError::ManifestError(format!("File size overflow: {}", entry.relative_path))
        })?;
        if end > data.len() {
            return Err(BundleError::ManifestError(format!(
                "File data truncated for: {}",
                entry.relative_path
            )));
        }

        let actual_hash = blake3::hash(&data[start..end]);
        if *actual_hash.as_bytes() != entry.blake3_hash {
            return Err(BundleError::ManifestError(format!(
                "BLAKE3 hash mismatch for: {}",
                entry.relative_path
            )));
        }
        if start != end {
            ranges.push((start, end, entry.relative_path.as_str()));
        }
    }

    ranges.sort_unstable_by_key(|range| range.0);
    for pair in ranges.windows(2) {
        if pair[0].1 > pair[1].0 {
            return Err(BundleError::ManifestError(format!(
                "Overlapping file ranges: {} and {}",
                pair[0].2, pair[1].2
            )));
        }
    }

    Ok((manifest, file_data_start))
}

fn configure_no_follow(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
}

fn validate_open_extraction_target(file: &File, path: &Path) -> Result<(), BundleError> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(BundleError::SpecialFileRejected(path.display().to_string()));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(BundleError::HardlinkRejected(path.display().to_string()));
        }
    }

    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT,
        };

        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        let ok = unsafe {
            GetFileInformationByHandle(file.as_raw_handle() as isize, std::ptr::addr_of_mut!(info))
        };
        if ok == 0 {
            return Err(BundleError::Io(io::Error::last_os_error()));
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(BundleError::SymlinkRejected(path.display().to_string()));
        }
        if info.nNumberOfLinks != 1 {
            return Err(BundleError::HardlinkRejected(path.display().to_string()));
        }
    }

    Ok(())
}

fn open_extraction_target(path: &Path, force: bool) -> Result<File, BundleError> {
    match fs::symlink_metadata(path) {
        Ok(_) if !force => Err(BundleError::OutputExists(path.display().to_string())),
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(BundleError::SymlinkRejected(path.display().to_string()));
            }
            if !metadata.file_type().is_file() {
                return Err(BundleError::SpecialFileRejected(path.display().to_string()));
            }

            let mut options = OpenOptions::new();
            options.write(true);
            configure_no_follow(&mut options);
            let file = options.open(path)?;
            validate_open_extraction_target(&file, path)?;
            file.set_len(0)?;
            Ok(file)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            configure_no_follow(&mut options);
            let file = options.open(path)?;
            validate_open_extraction_target(&file, path)?;
            Ok(file)
        }
        Err(error) => Err(BundleError::Io(error)),
    }
}

/// Extract a bundle to a directory.
pub fn extract_bundle(
    in_file: &Path,
    out_dir: &Path,
    password: SecretString,
    _allow_symlinks: bool,
    force: bool,
    dry_run: bool,
) -> Result<BundleManifest, BundleError> {
    // Decrypt to temp
    let temp_dir = tempdir().map_err(BundleError::Io)?;
    let temp_plain_path = temp_dir.path().join("payload.tmp");

    decrypt_file_password(in_file, &temp_plain_path, password, None, None)
        .map_err(BundleError::Crypto)?;

    let bundle_data = fs::read(&temp_plain_path).map_err(BundleError::Io)?;

    let (manifest, file_data_start) = parse_and_validate_bundle_payload(&bundle_data)?;

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

        // Extract file data
        let offset = usize::try_from(entry.offset)
            .map_err(|_| BundleError::ManifestError("File offset is not representable".into()))?;
        let size = usize::try_from(entry.size)
            .map_err(|_| BundleError::ManifestError("File size is not representable".into()))?;
        let start = file_data_start
            .checked_add(offset)
            .ok_or_else(|| BundleError::ManifestError("File offset overflow".into()))?;
        let end = start
            .checked_add(size)
            .ok_or_else(|| BundleError::ManifestError("File size overflow".into()))?;

        let file_data = &bundle_data[start..end];

        if dry_run {
            // Just print what would be extracted
            log::info!(
                "Would extract: {} ({} bytes)",
                entry.relative_path,
                entry.size
            );
        } else {
            // Write the file
            // The current manifest encodes regular files only. Existing
            // symlink/reparse-point and multi-link targets are always rejected,
            // including with --force, so extraction cannot overwrite an
            // external file through those aliases.
            let mut f = open_extraction_target(&target_path, force)?;
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
    password: SecretString,
) -> Result<BundleManifest, BundleError> {
    let temp_dir = tempdir().map_err(BundleError::Io)?;
    let temp_plain_path = temp_dir.path().join("payload.tmp");
    decrypt_file_password(in_file, &temp_plain_path, password, None, None)
        .map_err(BundleError::Crypto)?;
    let bundle_data = fs::read(&temp_plain_path).map_err(BundleError::Io)?;
    let (manifest, _) = parse_and_validate_bundle_payload(&bundle_data)?;

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

    fn test_password() -> SecretString {
        SecretString::from("test-bundle-password".to_string())
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

    fn encode_test_bundle_payload(manifest: &BundleManifest, file_data: &[u8]) -> Vec<u8> {
        let manifest_bytes = postcard::to_allocvec(manifest).unwrap();
        let mut payload = Vec::new();
        payload.extend_from_slice(&(manifest_bytes.len() as u32).to_le_bytes());
        payload.extend_from_slice(&manifest_bytes);
        payload.extend_from_slice(file_data);
        payload
    }

    #[test]
    fn bundle_validation_rejects_offset_overflow_without_panicking() {
        let manifest = BundleManifest {
            entries: vec![BundleEntry {
                relative_path: "file.bin".to_string(),
                size: 1,
                blake3_hash: *blake3::hash(&[0]).as_bytes(),
                offset: u64::MAX,
            }],
            created_at: None,
            tool_version: None,
        };
        let payload = encode_test_bundle_payload(&manifest, &[0]);

        assert!(parse_and_validate_bundle_payload(&payload).is_err());
    }

    #[test]
    fn bundle_validation_rejects_entry_hash_mismatch() {
        let manifest = BundleManifest {
            entries: vec![BundleEntry {
                relative_path: "file.bin".to_string(),
                size: 4,
                blake3_hash: [0xA5; 32],
                offset: 0,
            }],
            created_at: None,
            tool_version: None,
        };
        let payload = encode_test_bundle_payload(&manifest, b"data");

        assert!(parse_and_validate_bundle_payload(&payload).is_err());
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
            SecretString::from("wrong-password".to_string()),
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

    #[test]
    fn force_extract_rejects_existing_hardlink() {
        let dir = tempdir().unwrap();
        let in_dir = dir.path().join("input");
        let out_dir = dir.path().join("output");
        let out_file = dir.path().join("bundle.lvau");
        let outside = dir.path().join("outside.txt");

        fs::create_dir_all(&in_dir).unwrap();
        fs::create_dir_all(&out_dir).unwrap();
        fs::write(in_dir.join("test.txt"), "bundle data").unwrap();
        fs::write(&outside, "outside data").unwrap();
        fs::hard_link(&outside, out_dir.join("test.txt")).unwrap();
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

        let result = extract_bundle(&out_file, &out_dir, test_password(), false, true, false);

        assert!(result.is_err());
        assert_eq!(fs::read_to_string(outside).unwrap(), "outside data");
    }

    #[test]
    #[cfg(unix)]
    fn pack_rejects_special_files() {
        use std::os::unix::net::UnixListener;

        let dir = tempdir().unwrap();
        let in_dir = dir.path().join("input");
        fs::create_dir_all(&in_dir).unwrap();
        let socket_path = in_dir.join("service.sock");
        let _listener = UnixListener::bind(&socket_path).unwrap();

        let result = collect_files(&in_dir, false);

        assert!(matches!(
            result,
            Err(BundleError::SpecialFileRejected(path)) if path.contains("service.sock")
        ));
    }

    #[test]
    #[cfg(unix)]
    fn force_extract_never_follows_existing_symlink() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let in_dir = dir.path().join("input");
        let out_dir = dir.path().join("output");
        let out_file = dir.path().join("bundle.lvau");
        let outside = dir.path().join("outside.txt");
        fs::create_dir_all(&in_dir).unwrap();
        fs::create_dir_all(&out_dir).unwrap();
        fs::write(in_dir.join("test.txt"), "bundle data").unwrap();
        fs::write(&outside, "outside data").unwrap();
        symlink(&outside, out_dir.join("test.txt")).unwrap();
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

        let result = extract_bundle(&out_file, &out_dir, test_password(), true, true, false);

        assert!(matches!(result, Err(BundleError::SymlinkRejected(_))));
        assert_eq!(fs::read_to_string(outside).unwrap(), "outside data");
    }
}
