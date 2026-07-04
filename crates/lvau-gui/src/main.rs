#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use log::{LevelFilter, Log, Metadata, Record};
use lvau_core::crypto::{
    decrypt_file_keypair, decrypt_file_password, encrypt_file_keypairs, encrypt_file_password,
    keys::{generate_keypair, HybridPrivateKey, HybridPublicKey},
};
use lvau_core::preflight::run_preflight;
use lvau_protocol::envelope::SecurityProfile;
use secrecy::Secret;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

struct GuiLogger {
    logs: Arc<Mutex<String>>,
}

impl Log for GuiLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::Level::Debug
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let mut logs = self.logs.lock().unwrap();
            logs.push_str(&format!("[{}] {}\n", record.level(), record.args()));
        }
    }

    fn flush(&self) {}
}

#[derive(PartialEq)]
enum AuthMode {
    Password,
    KeyFile,
}

#[derive(PartialEq)]
enum OperationMode {
    Encrypt,
    Decrypt,
    Inspect,
}

struct LvauGuiApp {
    mode: OperationMode,
    auth_mode: AuthMode,
    in_file: Option<PathBuf>,
    secret: String,
    seed: String,
    keyfile_path: Option<PathBuf>,
    status: String,
    profile: SecurityProfile,
    sfx: bool,
    force_overwrite: bool,
    logs: Arc<Mutex<String>>,
}

impl LvauGuiApp {
    fn new(logs: Arc<Mutex<String>>) -> Self {
        Self {
            mode: OperationMode::Encrypt,
            auth_mode: AuthMode::Password,
            in_file: None,
            secret: String::new(),
            seed: String::new(),
            keyfile_path: None,
            status: String::new(),
            profile: SecurityProfile::Balanced,
            sfx: false,
            force_overwrite: false,
            logs,
        }
    }
}

impl eframe::App for LvauGuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Lvau - Local File Encryption");
            ui.add_space(20.0);

            ui.horizontal(|ui| {
                if ui
                    .button("Generate Experimental Hybrid Keypair...")
                    .clicked()
                {
                    let file_dialog = rfd::FileDialog::new()
                        .set_title("Save Private Key")
                        .add_filter("Lvau Key", &["lvau-key"]);

                    if let Some(priv_path) = file_dialog.save_file() {
                        let pub_path = priv_path.with_extension("lvau-pub");
                        let (priv_key, pub_key) = generate_keypair();

                        match priv_key.save_to_file(&priv_path) {
                            Ok(_) => match pub_key.save_to_file(&pub_path) {
                                Ok(_) => {
                                    self.status = format!(
                                        "Identity generated!\nPrivate Key: {}\nPublic Key: {}",
                                        priv_path.display(),
                                        pub_path.display()
                                    )
                                }
                                Err(_) => self.status = "Failed to save public key".into(),
                            },
                            Err(_) => self.status = "Failed to save private key".into(),
                        }
                    }
                }
            });
            ui.add_space(20.0);

            ui.horizontal(|ui| {
                ui.radio_value(&mut self.mode, OperationMode::Encrypt, "Encrypt");
                ui.radio_value(&mut self.mode, OperationMode::Decrypt, "Decrypt");
                ui.radio_value(&mut self.mode, OperationMode::Inspect, "Inspect");
            });

            ui.add_space(10.0);

            ui.horizontal(|ui| {
                if ui.button("Select Target File").clicked() {
                    let mut dialog = rfd::FileDialog::new();
                    if self.mode == OperationMode::Decrypt || self.mode == OperationMode::Inspect {
                        dialog = dialog.add_filter("Lvau Encrypted", &["lvau"]);
                    }
                    if let Some(path) = dialog.pick_file() {
                        self.in_file = Some(path);
                        self.status = String::new();
                    }
                }
                if let Some(path) = &self.in_file {
                    ui.label(path.display().to_string());
                }
            });

            ui.add_space(10.0);

            if self.mode != OperationMode::Inspect {
                ui.horizontal(|ui| {
                    ui.radio_value(&mut self.auth_mode, AuthMode::Password, "Use Password");
                    ui.radio_value(&mut self.auth_mode, AuthMode::KeyFile, "Use Key File");
                });

                if self.auth_mode == AuthMode::Password {
                    ui.horizontal(|ui| {
                        ui.label("Password:");
                        ui.add(egui::TextEdit::singleline(&mut self.secret).password(true));
                    });
                    ui.horizontal(|ui| {
                        ui.label("Seed (Pepper, Optional):");
                        ui.add(egui::TextEdit::singleline(&mut self.seed).password(true));
                    });
                } else {
                    ui.horizontal(|ui| {
                        if ui
                            .button(if self.mode == OperationMode::Encrypt {
                                "Select Public Key (.lvau-pub)"
                            } else {
                                "Select Private Key (.lvau-key)"
                            })
                            .clicked()
                        {
                            let mut dialog = rfd::FileDialog::new();
                            if self.mode == OperationMode::Encrypt {
                                dialog = dialog.add_filter("Public Key", &["lvau-pub"]);
                            } else {
                                dialog = dialog.add_filter("Private Key", &["lvau-key"]);
                            }
                            if let Some(path) = dialog.pick_file() {
                                self.keyfile_path = Some(path);
                            }
                        }
                        if let Some(path) = &self.keyfile_path {
                            ui.label(path.display().to_string());
                        }
                    });
                }
            }

            if self.mode == OperationMode::Encrypt {
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    ui.label("Security Profile:");
                    ui.radio_value(&mut self.profile, SecurityProfile::Fast, "Fast");
                    ui.radio_value(&mut self.profile, SecurityProfile::Balanced, "Balanced");
                    ui.radio_value(&mut self.profile, SecurityProfile::Archive, "Archive");
                    ui.radio_value(
                        &mut self.profile,
                        SecurityProfile::Paranoid,
                        "Paranoid (2-Layer)",
                    );
                    ui.radio_value(
                        &mut self.profile,
                        SecurityProfile::Extreme,
                        "Extreme (experimental)",
                    );
                });

                if self.profile == SecurityProfile::Paranoid || self.profile == SecurityProfile::Extreme {
                    ui.label(egui::RichText::new("⚠️ Warning: Cascade profiles are experimental.").color(egui::Color32::YELLOW));
                }

                ui.add_space(10.0);
                ui.checkbox(&mut self.sfx, "Create Self-Extracting Archive (SFX .exe)");
                if self.sfx {
                    ui.label(egui::RichText::new("⚠️ Warning: SFX is an experimental feature.").color(egui::Color32::YELLOW));
                }
            }

            if self.mode != OperationMode::Inspect {
                ui.add_space(10.0);
                ui.checkbox(&mut self.force_overwrite, "Force Overwrite (if file exists)");
            }

            ui.add_space(20.0);

            let can_proceed = self.in_file.is_some()
                && (self.mode == OperationMode::Inspect
                    || (self.auth_mode == AuthMode::Password && !self.secret.is_empty())
                    || (self.auth_mode == AuthMode::KeyFile && self.keyfile_path.is_some()));

            let action_text = match self.mode {
                OperationMode::Encrypt => "Encrypt & Save",
                OperationMode::Decrypt => "Decrypt & Save",
                OperationMode::Inspect => "Inspect Envelope",
            };

            if ui
                .add_enabled(can_proceed, egui::Button::new(action_text))
                .clicked()
            {
                if let Some(in_file) = &self.in_file {
                    if self.mode == OperationMode::Inspect {
                        let verify_path = in_file.with_extension("lvau-verify");
                        let v_key = if verify_path.exists() { lvau_core::signing::load_verify_key(&verify_path).ok() } else { None };
                        
                        let pol_path = std::path::Path::new(".lvau-policy.toml");
                        let p_key = if pol_path.exists() { lvau_core::policy::CapsulePolicy::load_from_file(pol_path).ok() } else { None };

                        let res = run_preflight(in_file, v_key.as_ref(), p_key.as_ref());
                        if res.parse_ok {
                            let mut details = format!(
                                "Version: {}\nProfile: {}\nAlgorithm: {}\nContent-Type: {}\n",
                                res.version, res.profile, res.algorithm, res.content_type
                            );
                            
                            details.push_str(&format!("Signed: {}\n", res.signature_present));
                            if let Some(true) = res.signature_valid {
                                let fp = res.signer_fingerprint.as_deref().unwrap_or("Unknown");
                                details.push_str(&format!("Signature Valid: Yes (Fingerprint: {})\n", fp));
                            } else if res.signature_present && v_key.is_some() {
                                details.push_str("Signature Valid: INVALID!\n");
                            } else if res.signature_present {
                                details.push_str("Signature Valid: Unchecked (No .lvau-verify found)\n");
                            }
                            
                            if p_key.is_some() {
                                details.push_str(&format!("\nPolicy Checked (.lvau-policy.toml): {}\n", res.policy_ok.unwrap_or(false)));
                                for v in res.policy_violations {
                                    details.push_str(&format!("  Violation: {}\n", v));
                                }
                            }
                            
                            self.status = format!("Inspect Successful:\n{}", details);
                        } else {
                            self.status = format!("Error inspecting file: {:?}", res.parse_error);
                        }
                    } else {
                        let mut file_dialog = rfd::FileDialog::new();
                        if self.mode == OperationMode::Encrypt {
                            if self.sfx {
                                file_dialog = file_dialog.add_filter("Executable", &["exe"]);
                            } else {
                                file_dialog = file_dialog.add_filter("Lvau", &["lvau"]);
                            }
                        }

                        if let Some(out_path) = file_dialog.save_file() {
                            if out_path.exists() && !self.force_overwrite {
                                self.status = "Error: File already exists. Check 'Force Overwrite' to proceed.".to_string();
                            } else {
                                let temp_out = if self.mode == OperationMode::Encrypt && self.sfx {
                                    in_file.with_extension("tmp.lvau")
                                } else {
                                    out_path.clone()
                                };

                                let result = match self.auth_mode {
                                    AuthMode::Password => {
                                        let pwd = Secret::new(self.secret.clone());
                                        let seed_val = if self.seed.is_empty() {
                                            None
                                        } else {
                                            Some(Secret::new(self.seed.clone()))
                                        };
                                        if self.mode == OperationMode::Encrypt {
                                            encrypt_file_password(
                                                in_file,
                                                &temp_out,
                                                pwd,
                                                seed_val,
                                                self.profile.clone(),
                                                None,
                                                None,
                                                false,
                                            )
                                        } else {
                                            decrypt_file_password(in_file, &temp_out, pwd, seed_val, None)
                                        }
                                    }
                                    AuthMode::KeyFile => {
                                        let kp = self.keyfile_path.as_ref().unwrap();
                                        if self.mode == OperationMode::Encrypt {
                                            if let Ok(pub_key) = HybridPublicKey::load_from_file(kp) {
                                                let pubs = vec![pub_key];
                                                encrypt_file_keypairs(
                                                    in_file,
                                                    &temp_out,
                                                    &pubs,
                                                    self.profile.clone(),
                                                    None,
                                                    None,
                                                    false,
                                                )
                                            } else {
                                                Err(lvau_core::crypto::CryptoError::DecryptionFailed)
                                            }
                                        } else if let Ok(priv_key) = HybridPrivateKey::load_from_file(kp) {
                                            decrypt_file_keypair(in_file, &temp_out, &priv_key, None)
                                        } else {
                                            Err(lvau_core::crypto::CryptoError::DecryptionFailed)
                                        }
                                    }
                                };

                                match result {
                                    Ok(_) => {
                                        if self.mode == OperationMode::Encrypt && self.sfx {
                                            let exe_dir = std::env::current_exe()
                                                .unwrap()
                                                .parent()
                                                .unwrap()
                                                .to_path_buf();
                                            let stub_path = exe_dir.join("lvau-stub.exe");

                                            if !stub_path.exists() {
                                                self.status = format!(
                                                    "Error: lvau-stub.exe not found in {}",
                                                    exe_dir.display()
                                                );
                                                std::fs::remove_file(&temp_out).ok();
                                            } else if let Err(e) = std::fs::copy(&stub_path, &out_path) {
                                                self.status = format!("SFX Copy Error: {:?}", e);
                                            } else {
                                                let mut out_f = std::fs::OpenOptions::new()
                                                    .append(true)
                                                    .open(&out_path)
                                                    .unwrap();
                                                let payload_bytes = std::fs::read(&temp_out).unwrap();
                                                out_f.write_all(&payload_bytes).unwrap();
                                                let payload_len = payload_bytes.len() as u64;
                                                out_f.write_all(&payload_len.to_le_bytes()).unwrap();
                                                out_f.write_all(b"LVAUSFX1").unwrap();
                                                self.status = format!(
                                                    "Success: SFX Output saved to {}",
                                                    out_path.display()
                                                );
                                                std::fs::remove_file(&temp_out).ok();
                                            }
                                        } else {
                                            self.status =
                                                format!("Success: Output saved to {}", out_path.display());
                                        }
                                    }
                                    Err(e) => {
                                        self.status = format!("Error: {:?}", e);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            ui.add_space(20.0);
            if !self.status.is_empty() {
                ui.label(egui::RichText::new(&self.status).color(
                    if self.status.starts_with("Error") {
                        egui::Color32::RED
                    } else if self.status.starts_with("Success") {
                        egui::Color32::GREEN
                    } else {
                        egui::Color32::LIGHT_BLUE
                    }
                ));
            }

            ui.add_space(20.0);
            ui.separator();
            ui.heading("Real-time Logs");
            egui::ScrollArea::vertical()
                .auto_shrink([false; 2])
                .max_height(150.0)
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    let logs = self.logs.lock().unwrap();
                    ui.label(logs.as_str());
                });
        });
    }
}

fn main() {
    let logs = Arc::new(Mutex::new(String::new()));
    let logger = GuiLogger { logs: logs.clone() };
    log::set_boxed_logger(Box::new(logger)).unwrap();
    log::set_max_level(LevelFilter::Debug);

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([700.0, 700.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Lvau Cryptography",
        options,
        Box::new(|_cc| Ok(Box::new(LvauGuiApp::new(logs)))),
    )
    .unwrap();
}
