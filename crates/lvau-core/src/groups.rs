use crate::crypto::keys::{HybridPublicKey, HybridPublicKeyFormat};
use crate::crypto::CryptoError;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct RecipientGroup {
    pub name: String,
    pub description: Option<String>,
    pub recipients: Vec<GroupRecipient>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GroupRecipient {
    pub name: String,
    pub key: HybridPublicKeyFormat,
}

impl RecipientGroup {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read recipient group file: {}", e))?;
        toml::from_str(&content).map_err(|e| format!("Failed to parse recipient group: {}", e))
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize recipient group: {}", e))?;
        fs::write(path, content).map_err(|e| format!("Failed to write recipient group file: {}", e))
    }

    pub fn extract_public_keys(&self) -> Result<Vec<HybridPublicKey>, CryptoError> {
        let mut keys = Vec::new();
        for rec in &self.recipients {
            keys.push(HybridPublicKey::from_format(&rec.key)?);
        }
        Ok(keys)
    }
}
