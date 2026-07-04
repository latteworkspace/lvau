use crate::policy::{lint_envelope, CapsulePolicy, PolicyResult};
use crate::signing::{verify_signature, SigningError};
use ed25519_dalek::VerifyingKey;
use lvau_protocol::envelope::{ContentType, Envelope, SecurityProfile, AlgorithmId};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PreflightStatus {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightResult {
    pub status: PreflightStatus,
    pub parse_ok: bool,
    pub parse_error: Option<String>,
    pub version: u16,
    pub content_type: String,
    pub profile: String,
    pub algorithm: String,
    
    pub public_hash_ok: bool,
    pub signature_present: bool,
    pub signature_valid: Option<bool>,
    pub signer_fingerprint: Option<String>,
    
    pub policy_ok: Option<bool>,
    pub policy_violations: Vec<String>,
    pub policy_warnings: Vec<String>,
    pub policy_overridden: bool,
    
    pub approvals: Vec<String>,
    
    pub recipient_count: usize,
    pub has_recovery_metadata: bool,
    pub has_release_metadata: bool,
    
    pub experimental_flags: Vec<String>,
    
    pub file_size_ok: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

pub fn run_preflight(
    in_file: &Path,
    verify_key: Option<&VerifyingKey>,
    policy: Option<&CapsulePolicy>,
) -> PreflightResult {
    let mut res = PreflightResult {
        status: PreflightStatus::Ok,
        parse_ok: false,
        parse_error: None,
        version: 0,
        content_type: "Unknown".into(),
        profile: "Unknown".into(),
        algorithm: "Unknown".into(),
        public_hash_ok: false,
        signature_present: false,
        signature_valid: None,
        signer_fingerprint: None,
        policy_ok: None,
        policy_violations: vec![],
        policy_warnings: vec![],
        policy_overridden: false,
        approvals: vec![],
        recipient_count: 0,
        has_recovery_metadata: false,
        has_release_metadata: false,
        experimental_flags: vec![],
        file_size_ok: false,
        errors: vec![],
        warnings: vec![],
    };

    let data = match fs::read(in_file) {
        Ok(d) => d,
        Err(e) => {
            res.status = PreflightStatus::Fail;
            res.errors.push(format!("I/O Error reading file: {}", e));
            return res;
        }
    };

    if data.len() < 4 {
        res.status = PreflightStatus::Fail;
        res.errors.push("File is too small to contain an envelope length".into());
        return res;
    }

    let env_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    if data.len() < 4 + env_len {
        res.status = PreflightStatus::Fail;
        res.errors.push("File is truncated (envelope length exceeds file size)".into());
        return res;
    }
    
    res.file_size_ok = true;

    let envelope_bytes = &data[4..4 + env_len];
    let envelope: Envelope = match postcard::from_bytes(envelope_bytes) {
        Ok(e) => e,
        Err(e) => {
            res.status = PreflightStatus::Fail;
            res.parse_error = Some(e.to_string());
            res.errors.push("Failed to parse Envelope".into());
            return res;
        }
    };

    res.parse_ok = true;
    res.version = envelope.header.version;
    res.content_type = match envelope.effective_content_type() {
        ContentType::SingleFile => "SingleFile".into(),
        ContentType::Bundle => "Bundle".into(),
    };
    res.profile = format!("{:?}", envelope.header.profile);
    res.algorithm = format!("{:?}", envelope.header.algorithm);
    res.recipient_count = envelope.header.recipients.len();
    res.has_recovery_metadata = envelope.recovery_metadata.is_some();
    res.has_release_metadata = envelope.release_metadata.is_some();
    res.policy_overridden = envelope.policy_overridden;
    
    for approval in &envelope.approvals {
        let fp = approval.signer_fingerprint.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        res.approvals.push(fp);
    }

    // Check Magic and Version
    if let Err(e) = envelope.validate() {
        res.errors.push(e.to_string());
    }

    // Check AAD Hash
    match crate::crypto::verify_aad_hash(&envelope) {
        Ok(_) => res.public_hash_ok = true,
        Err(_) => {
            res.public_hash_ok = false;
            res.errors.push("Public envelope header hash mismatch (tampered)".into());
        }
    }

    // Experimental features
    if envelope.header.profile == SecurityProfile::Extreme || envelope.header.profile == SecurityProfile::Paranoid {
        res.experimental_flags.push("Cascade Cipher".into());
    }
    if envelope.header.algorithm == AlgorithmId::TripleCascadeAesXChaChaLco {
        res.experimental_flags.push("LCO Obfuscation".into());
    }

    // Signature
    if let Some(sig) = &envelope.signature {
        res.signature_present = true;
        res.signer_fingerprint = Some(sig.signer_fingerprint.iter().map(|b| format!("{:02x}", b)).collect());
        
        if let Some(key) = verify_key {
            match verify_signature(in_file, key) {
                Ok(_) => res.signature_valid = Some(true),
                Err(_) => {
                    res.signature_valid = Some(false);
                    res.errors.push("Signature verification failed".into());
                }
            }
        }
    } else {
        res.warnings.push("No author signature present".into());
    }

    // Policy
    if let Some(pol) = policy {
        let policy_res = lint_envelope(&envelope, pol);
        res.policy_ok = Some(policy_res.is_valid());
        
        for v in policy_res.violations {
            res.policy_violations.push(v.message);
        }
        for w in policy_res.warnings {
            res.policy_warnings.push(w.message);
        }
        
        if res.policy_ok == Some(false) {
            if envelope.policy_overridden {
                res.warnings.push("Artifact violates policy but was explicitly overridden by author".into());
            } else {
                res.errors.push("Artifact violates local policy".into());
            }
        }
    }

    // Compute Status
    if !res.errors.is_empty() {
        res.status = PreflightStatus::Fail;
    } else if !res.warnings.is_empty() || !res.policy_warnings.is_empty() || !res.experimental_flags.is_empty() {
        res.status = PreflightStatus::Warn;
    } else {
        res.status = PreflightStatus::Ok;
    }

    res
}
