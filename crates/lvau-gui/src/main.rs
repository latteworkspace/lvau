#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use log::{LevelFilter, Log, Metadata, Record};
use lvau_core::crypto::{
    decrypt_file_keypair, decrypt_file_password, encrypt_file_keypair, encrypt_file_password,
    keys::{HybridPrivateKey, HybridPublicKey, generate_keypair},
};
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

struct LvauGuiApp {
    mode_encrypt: bool,
    auth_mode: AuthMode,
    in_file: Option<PathBuf>,
    secret: String,
    seed: String,
    keyfile_path: Option<PathBuf>,
    status: String,
    profile: SecurityProfile,
    sfx: bool,
    logs: Arc<Mutex<String>>,
}

impl LvauGuiApp {
    fn new(logs: Arc<Mutex<String>>) -> Self {
        Self {
            mode_encrypt: true,
            auth_mode: AuthMode::Password,
            in_file: None,
            secret: String::new(),
            seed: String::new(),
            keyfile_path: None,
            status: String::new(),
            profile: SecurityProfile::Balanced,
            sfx: false,
            logs,
        }
    }
}

impl eframe::App for LvauGuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Lvau - Advanced Cryptography Toolkit (Post-Quantum Hybrid)");
            ui.add_space(20.0);

            ui.horizontal(|ui| {
                if ui.button("Generate Post-Quantum Identity...").clicked() {
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
                ui.radio_value(&mut self.mode_encrypt, true, "Encrypt");
                ui.radio_value(&mut self.mode_encrypt, false, "Decrypt");
            });

            ui.add_space(10.0);

            ui.horizontal(|ui| {
                if ui.button("Select Target File").clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                        self.in_file = Some(path);
                        self.status = String::new();
                    }
                }
                if let Some(path) = &self.in_file {
                    ui.label(path.display().to_string());
                }
            });

            ui.add_space(10.0);

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
                        .button(if self.mode_encrypt {
                            "Select Public Key (.lvau-pub)"
                        } else {
                            "Select Private Key (.lvau-key)"
                        })
                        .clicked()
                    {
                        let mut dialog = rfd::FileDialog::new();
                        if self.mode_encrypt {
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

            if self.mode_encrypt {
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
                        "Extreme (3-Layer Custom)",
                    );
                });

                ui.add_space(10.0);
                ui.checkbox(&mut self.sfx, "Create Self-Extracting Archive (SFX .exe)");
            }

            ui.add_space(20.0);

            let can_proceed = self.in_file.is_some()
                && ((self.auth_mode == AuthMode::Password && !self.secret.is_empty())
                    || (self.auth_mode == AuthMode::KeyFile && self.keyfile_path.is_some()));

            if ui
                .add_enabled(
                    can_proceed,
                    egui::Button::new(if self.mode_encrypt {
                        "Encrypt & Save"
                    } else {
                        "Decrypt & Save"
                    }),
                )
                .clicked()
            {
                if let Some(in_file) = &self.in_file {
                    let mut file_dialog = rfd::FileDialog::new();
                    if self.mode_encrypt {
                        if self.sfx {
                            file_dialog = file_dialog.add_filter("Executable", &["exe"]);
                        } else {
                            file_dialog = file_dialog.add_filter("Lvau", &["lvau"]);
                        }
                    }

                    if let Some(out_path) = file_dialog.save_file() {
                        let temp_out = if self.mode_encrypt && self.sfx {
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
                                if self.mode_encrypt {
                                    encrypt_file_password(
                                        in_file,
                                        &temp_out,
                                        pwd,
                                        seed_val,
                                        self.profile.clone(),
                                    )
                                } else {
                                    decrypt_file_password(in_file, &temp_out, pwd, seed_val)
                                }
                            }
                            AuthMode::KeyFile => {
                                let kp = self.keyfile_path.as_ref().unwrap();
                                if self.mode_encrypt {
                                    if let Ok(pub_key) = HybridPublicKey::load_from_file(kp) {
                                        encrypt_file_keypair(
                                            in_file,
                                            &temp_out,
                                            &pub_key,
                                            self.profile.clone(),
                                        )
                                    } else {
                                        Err(lvau_core::crypto::CryptoError::DecryptionFailed)
                                    }
                                } else {
                                    if let Ok(priv_key) = HybridPrivateKey::load_from_file(kp) {
                                        decrypt_file_keypair(in_file, &temp_out, &priv_key)
                                    } else {
                                        Err(lvau_core::crypto::CryptoError::DecryptionFailed)
                                    }
                                }
                            }
                        };

                        match result {
                            Ok(_) => {
                                if self.mode_encrypt && self.sfx {
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
                                    } else {
                                        if let Err(e) = std::fs::copy(&stub_path, &out_path) {
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
                                        }
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

            ui.add_space(20.0);
            if !self.status.is_empty() {
                ui.label(egui::RichText::new(&self.status).color(
                    if self.status.starts_with("Error") {
                        egui::Color32::RED
                    } else {
                        egui::Color32::GREEN
                    },
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
        viewport: egui::ViewportBuilder::default().with_inner_size([700.0, 600.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Lvau Cryptography",
        options,
        Box::new(|_cc| Box::new(LvauGuiApp::new(logs))),
    )
    .unwrap();
}
