use crate::bundle::list_bundle;
use crate::crypto::{verify_file_keypair, verify_file_password};
use crate::policy::CapsulePolicy;
use crate::preflight::{run_preflight, PreflightResult};
use ed25519_dalek::VerifyingKey;
use secrecy::Secret;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct FullReport {
    pub file_path: String,
    pub preflight: PreflightResult,
    pub decryption_successful: Option<bool>,
    pub file_count: Option<usize>,
    pub timestamp: String,
}

pub enum DecryptCredential {
    Password(Secret<String>, Option<Secret<String>>),
    Keypair(crate::crypto::keys::HybridPrivateKey),
}

pub fn generate_report(
    in_file: &Path,
    verify_key: Option<&VerifyingKey>,
    policy: Option<&CapsulePolicy>,
    credential: Option<&DecryptCredential>,
) -> FullReport {
    let preflight_res = run_preflight(in_file, verify_key, policy);

    let mut decryption_successful = None;
    let mut file_count = None;

    if let Some(cred) = credential {
        match cred {
            DecryptCredential::Password(pwd, seed) => {
                match verify_file_password(in_file, pwd.clone(), seed.clone(), None) {
                    Ok(_) => {
                        decryption_successful = Some(true);
                    }
                    Err(_) => {
                        decryption_successful = Some(false);
                    }
                }
            }
            DecryptCredential::Keypair(pk) => match verify_file_keypair(in_file, pk, None) {
                Ok(_) => {
                    decryption_successful = Some(true);
                }
                Err(_) => {
                    decryption_successful = Some(false);
                }
            },
        }

        // If it's a bundle and decryption succeeded, try to list it
        if decryption_successful == Some(true) && preflight_res.content_type == "Bundle" {
            if let DecryptCredential::Password(pwd, _) = cred {
                if let Ok(manifest) = list_bundle(in_file, pwd.clone()) {
                    file_count = Some(manifest.entries.len());
                }
            }
        }
    }

    let timestamp = {
        use std::time::SystemTime;
        match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(d) => format!("{}Z", d.as_secs()),
            Err(_) => "unknown".to_string(),
        }
    };

    FullReport {
        file_path: in_file.display().to_string(),
        preflight: preflight_res,
        decryption_successful,
        file_count,
        timestamp,
    }
}
