use crate::bundle::{list_bundle, BundleError};
use lvau_protocol::envelope::BundleManifest;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct FileDiff {
    pub path: String,
    pub status: DiffStatus,
    pub old_size: Option<u64>,
    pub new_size: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DiffStatus {
    Added,
    Removed,
    Modified,
    Unchanged,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DiffReport {
    pub files: Vec<FileDiff>,
    pub added_count: usize,
    pub removed_count: usize,
    pub modified_count: usize,
    pub unchanged_count: usize,
}

/// Diff two encrypted bundles.
pub fn diff_bundles(
    old_file: &Path,
    old_password: SecretString,
    new_file: &Path,
    new_password: SecretString,
) -> Result<DiffReport, BundleError> {
    let old_manifest = list_bundle(old_file, old_password)?;
    let new_manifest = list_bundle(new_file, new_password)?;

    Ok(diff_manifests(&old_manifest, &new_manifest))
}

pub fn diff_manifests(old_manifest: &BundleManifest, new_manifest: &BundleManifest) -> DiffReport {
    let mut old_map = HashMap::new();
    for entry in &old_manifest.entries {
        old_map.insert(&entry.relative_path, entry);
    }

    let mut new_map = HashMap::new();
    for entry in &new_manifest.entries {
        new_map.insert(&entry.relative_path, entry);
    }

    let mut files = Vec::new();
    let mut added_count = 0;
    let mut removed_count = 0;
    let mut modified_count = 0;
    let mut unchanged_count = 0;

    // Check for removed or modified/unchanged
    for entry in &old_manifest.entries {
        if let Some(new_entry) = new_map.get(&entry.relative_path) {
            if entry.blake3_hash != new_entry.blake3_hash {
                files.push(FileDiff {
                    path: entry.relative_path.clone(),
                    status: DiffStatus::Modified,
                    old_size: Some(entry.size),
                    new_size: Some(new_entry.size),
                });
                modified_count += 1;
            } else {
                files.push(FileDiff {
                    path: entry.relative_path.clone(),
                    status: DiffStatus::Unchanged,
                    old_size: Some(entry.size),
                    new_size: Some(new_entry.size),
                });
                unchanged_count += 1;
            }
        } else {
            files.push(FileDiff {
                path: entry.relative_path.clone(),
                status: DiffStatus::Removed,
                old_size: Some(entry.size),
                new_size: None,
            });
            removed_count += 1;
        }
    }

    // Check for added
    for entry in &new_manifest.entries {
        if !old_map.contains_key(&entry.relative_path) {
            files.push(FileDiff {
                path: entry.relative_path.clone(),
                status: DiffStatus::Added,
                old_size: None,
                new_size: Some(entry.size),
            });
            added_count += 1;
        }
    }

    files.sort_by(|a, b| a.path.cmp(&b.path));

    DiffReport {
        files,
        added_count,
        removed_count,
        modified_count,
        unchanged_count,
    }
}
