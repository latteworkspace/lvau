use lvau_protocol::envelope::{AlgorithmId, Envelope, KdfParams, SecurityProfile};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MinKdfProfile {
    Interactive,
    Moderate,
    Strong,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MetadataProfilePolicy {
    Minimal,
    Balanced,
    Verbose,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PaddingPolicy {
    None,
    Bucket,
    Fixed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapsulePolicy {
    #[serde(default)]
    pub require_signature: bool,
    #[serde(default)]
    pub require_recovery: bool,
    pub min_kdf_profile: Option<MinKdfProfile>,
    pub allowed_ciphers: Option<Vec<String>>,
    pub allowed_kdfs: Option<Vec<String>>,
    #[serde(default = "default_true")]
    pub allow_lco: bool,
    #[serde(default = "default_true")]
    pub allow_experimental: bool,
    pub require_metadata_profile: Option<MetadataProfilePolicy>,
    pub require_padding: Option<PaddingPolicy>,
    #[serde(default)]
    pub require_recipient_count_min: u32,
    #[serde(default)]
    pub require_approval_signatures_min: u32,
    #[serde(default = "default_true")]
    pub public_label_allowed: bool,
    #[serde(default)]
    pub created_by_required: bool,
}

fn default_true() -> bool {
    true
}

impl Default for CapsulePolicy {
    fn default() -> Self {
        Self {
            require_signature: false,
            require_recovery: false,
            min_kdf_profile: None,
            allowed_ciphers: None,
            allowed_kdfs: None,
            allow_lco: true,
            allow_experimental: true,
            require_metadata_profile: None,
            require_padding: None,
            require_recipient_count_min: 0,
            require_approval_signatures_min: 0,
            public_label_allowed: true,
            created_by_required: false,
        }
    }
}

impl CapsulePolicy {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let content = fs::read_to_string(path).map_err(|e| e.to_string())?;
        toml::from_str(&content).map_err(|e| e.to_string())
    }
    
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
        let content = toml::to_string_pretty(self).map_err(|e| e.to_string())?;
        fs::write(path, content).map_err(|e| e.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct PolicyViolation {
    pub rule: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct PolicyWarning {
    pub rule: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct PolicyResult {
    pub violations: Vec<PolicyViolation>,
    pub warnings: Vec<PolicyWarning>,
}

impl PolicyResult {
    pub fn new() -> Self {
        Self {
            violations: Vec::new(),
            warnings: Vec::new(),
        }
    }
    
    pub fn is_valid(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Lints an envelope against a capsule policy, returning any violations or warnings.
pub fn lint_envelope(envelope: &Envelope, policy: &CapsulePolicy) -> PolicyResult {
    let mut result = PolicyResult::new();

    // 1. Signature requirement
    if policy.require_signature && envelope.signature.is_none() {
        result.violations.push(PolicyViolation {
            rule: "require_signature".into(),
            message: "Policy requires a signature, but none was found.".into(),
        });
    }

    // 2. Recovery requirement
    if policy.require_recovery && envelope.recovery_metadata.is_none() {
        result.violations.push(PolicyViolation {
            rule: "require_recovery".into(),
            message: "Policy requires recovery metadata, but none was found.".into(),
        });
    }

    // 3. Min KDF Profile
    if let Some(ref min_kdf) = policy.min_kdf_profile {
        if let Some(KdfParams::Argon2id { m_cost, t_cost, p_cost, .. }) = &envelope.header.kdf {
            let is_interactive = *m_cost >= 65536 && *t_cost >= 2 && *p_cost >= 1;
            let is_moderate = *m_cost >= 262144 && *t_cost >= 3 && *p_cost >= 2;
            let is_strong = *m_cost >= 1048576 && *t_cost >= 4 && *p_cost >= 4;
            
            let actual_profile = if is_strong {
                MinKdfProfile::Strong
            } else if is_moderate {
                MinKdfProfile::Moderate
            } else {
                MinKdfProfile::Interactive
            };

            let fails = match min_kdf {
                MinKdfProfile::Strong => actual_profile != MinKdfProfile::Strong,
                MinKdfProfile::Moderate => actual_profile == MinKdfProfile::Interactive,
                MinKdfProfile::Interactive => !is_interactive,
            };

            if fails {
                result.violations.push(PolicyViolation {
                    rule: "min_kdf_profile".into(),
                    message: format!("Policy requires KDF profile {:?}, but the artifact's KDF is weaker.", min_kdf),
                });
            }
        }
    }

    // 4. Allowed Ciphers
    if let Some(ref allowed_ciphers) = policy.allowed_ciphers {
        let alg_str = match envelope.header.algorithm {
            AlgorithmId::XChaCha20Poly1305 => "XChaCha20Poly1305",
            AlgorithmId::CascadeAesGcmXChaCha => "CascadeAesGcmXChaCha",
            AlgorithmId::TripleCascadeAesXChaChaLco => "TripleCascadeAesXChaChaLco",
            AlgorithmId::X25519 => "X25519",
            AlgorithmId::Ed25519 => "Ed25519",
            AlgorithmId::X25519MlkemHybrid => "X25519MlkemHybrid",
            AlgorithmId::Ed25519MldsaHybrid => "Ed25519MldsaHybrid",
        };
        
        let allowed = allowed_ciphers.iter().any(|c| c.eq_ignore_ascii_case(alg_str));
        if !allowed {
            result.violations.push(PolicyViolation {
                rule: "allowed_ciphers".into(),
                message: format!("Algorithm {} is not in the allowed ciphers list.", alg_str),
            });
        }
    }

    // 5. Allowed KDFs
    if let Some(ref allowed_kdfs) = policy.allowed_kdfs {
        let kdf_str = match envelope.header.kdf {
            Some(KdfParams::Argon2id { .. }) => "Argon2id",
            None => "None",
        };
        
        let allowed = allowed_kdfs.iter().any(|k| k.eq_ignore_ascii_case(kdf_str));
        if !allowed {
            result.violations.push(PolicyViolation {
                rule: "allowed_kdfs".into(),
                message: format!("KDF {} is not in the allowed KDFs list.", kdf_str),
            });
        }
    }

    // 6. Allow LCO
    if !policy.allow_lco && envelope.header.algorithm == AlgorithmId::TripleCascadeAesXChaChaLco {
        result.violations.push(PolicyViolation {
            rule: "allow_lco".into(),
            message: "LCO obfuscation is disallowed by policy.".into(),
        });
    }

    // 7. Allow Experimental
    if !policy.allow_experimental {
        if envelope.header.profile == SecurityProfile::Extreme || envelope.header.profile == SecurityProfile::Paranoid {
            result.violations.push(PolicyViolation {
                rule: "allow_experimental".into(),
                message: "Experimental profiles (Cascade/LCO) are disallowed by policy.".into(),
            });
        }
    }

    // 8. Public label allowed
    if !policy.public_label_allowed && envelope.public_label.is_some() {
        result.violations.push(PolicyViolation {
            rule: "public_label_allowed".into(),
            message: "Public labels are disallowed by policy.".into(),
        });
    }

    // 9. Created by required
    if policy.created_by_required {
        if envelope.release_metadata.is_none() || envelope.release_metadata.as_ref().unwrap().project_name.is_none() {
            // "created_by" is effectively project_name or similar. We check release_metadata.
            result.violations.push(PolicyViolation {
                rule: "created_by_required".into(),
                message: "Policy requires author/project metadata, but none was found.".into(),
            });
        }
    }

    // 10. Recipient count
    let count = envelope.header.recipients.len() as u32;
    if count < policy.require_recipient_count_min {
        result.violations.push(PolicyViolation {
            rule: "require_recipient_count_min".into(),
            message: format!("Policy requires at least {} recipients, but found {}.", policy.require_recipient_count_min, count),
        });
    }

    // 11. Approval signatures
    let approvals_count = envelope.approvals.len() as u32;
    if approvals_count < policy.require_approval_signatures_min {
        result.violations.push(PolicyViolation {
            rule: "require_approval_signatures_min".into(),
            message: format!("Policy requires at least {} approvals, but found {}.", policy.require_approval_signatures_min, approvals_count),
        });
    }

    result
}
