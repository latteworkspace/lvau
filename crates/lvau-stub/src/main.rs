#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use lvau_core::crypto::{decrypt_memory_keypair, decrypt_memory_password, keys::HybridPrivateKey};
use secrecy::Secret;
use std::env;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

fn extract_payload() -> Result<Vec<u8>, String> {
    let exe_path = env::current_exe().map_err(|e| e.to_string())?;
    let mut file = File::open(&exe_path).map_err(|e| e.to_string())?;

    if file.seek(SeekFrom::End(-16)).is_err() {
        return Err("File too small to be an SFX.".to_string());
    }

    let mut trailer = [0u8; 16];
    if file.read_exact(&mut trailer).is_err() {
        return Err("Failed to read trailer.".to_string());
    }

    let magic = &trailer[8..16];
    if magic != b"LVAUSFX1" {
        return Err("This executable does not contain a valid Lvau SFX payload.".to_string());
    }

    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&trailer[0..8]);
    let payload_len = u64::from_le_bytes(len_bytes);

    if file
        .seek(SeekFrom::End(-(16 + payload_len as i64)))
        .is_err()
    {
        return Err("Failed to seek to payload.".to_string());
    }

    let mut payload = vec![0u8; payload_len as usize];
    if file.read_exact(&mut payload).is_err() {
        return Err("Failed to read payload bytes.".to_string());
    }

    Ok(payload)
}

#[derive(PartialEq)]
enum AuthMode {
    Password,
    KeyFile,
}

struct SfxExtractorApp {
    payload: Option<Vec<u8>>,
    payload_error: Option<String>,
    auth_mode: AuthMode,
    secret: String,
    seed: String,
    keyfile_path: Option<PathBuf>,
    out_file: Option<PathBuf>,
    status: String,
}

impl SfxExtractorApp {
    fn new() -> Self {
        let (payload, payload_error) = match extract_payload() {
            Ok(p) => (Some(p), None),
            Err(e) => (None, Some(e)),
        };

        Self {
            payload,
            payload_error,
            auth_mode: AuthMode::Password,
            secret: String::new(),
            seed: String::new(),
            keyfile_path: None,
            out_file: None,
            status: String::new(),
        }
    }
}

impl eframe::App for SfxExtractorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Lvau SFX Extractor");
            ui.add_space(20.0);

            if let Some(err) = &self.payload_error {
                ui.label(egui::RichText::new(format!("Error: {}", err)).color(egui::Color32::RED));
                return;
            }

            ui.horizontal(|ui| {
                ui.radio_value(&mut self.auth_mode, AuthMode::Password, "Use Password");
                ui.radio_value(&mut self.auth_mode, AuthMode::KeyFile, "Use Key File");
            });

            ui.add_space(10.0);

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
                    if ui.button("Select Private Key (.lvau-key)").clicked() {
                        let dialog =
                            rfd::FileDialog::new().add_filter("Private Key", &["lvau-key"]);
                        if let Some(path) = dialog.pick_file() {
                            self.keyfile_path = Some(path);
                        }
                    }
                    if let Some(path) = &self.keyfile_path {
                        ui.label(path.display().to_string());
                    }
                });
            }

            ui.add_space(20.0);

            ui.horizontal(|ui| {
                if ui.button("Select Output File").clicked() {
                    if let Some(path) = rfd::FileDialog::new().save_file() {
                        self.out_file = Some(path);
                    }
                }
                if let Some(path) = &self.out_file {
                    ui.label(path.display().to_string());
                }
            });

            ui.add_space(20.0);

            let can_proceed = self.out_file.is_some()
                && ((self.auth_mode == AuthMode::Password && !self.secret.is_empty())
                    || (self.auth_mode == AuthMode::KeyFile && self.keyfile_path.is_some()));

            if ui
                .add_enabled(can_proceed, egui::Button::new("Decrypt & Extract"))
                .clicked()
            {
              if let (Some(payload), Some(out_file)) = (&self.payload, &self.out_file) {
                let result = match self.auth_mode {
                    AuthMode::Password => {
                        let pwd = Secret::new(self.secret.clone());
                        let seed_val = if self.seed.is_empty() {
                            None
                        } else {
                            Some(Secret::new(self.seed.clone()))
                        };
                        decrypt_memory_password(payload, pwd, seed_val)
                    }
                    AuthMode::KeyFile => {
                        let kp = self.keyfile_path.as_ref().unwrap();
                        if let Ok(priv_key) = HybridPrivateKey::load_from_file(kp) {
                            decrypt_memory_keypair(payload, &priv_key)
                        } else {
                            Err(lvau_core::crypto::CryptoError::DecryptionFailed)
                        }
                    }
                };

                match result {
                    Ok(plaintext) => {
                        if let Ok(mut f) = std::fs::File::create(out_file) {
                            if f.write_all(&plaintext).is_ok() {
                                self.status = "Extraction Successful!".to_string();
                            } else {
                                self.status = "Failed to write to file.".to_string();
                            }
                        }
                    }
                    Err(_) => {
                        self.status =
                            "Decryption Failed! Wrong password or corrupted file.".to_string();
                    }
                }
              }
            }

            ui.add_space(20.0);
            if !self.status.is_empty() {
                let color = if self.status.contains("Successful") {
                    egui::Color32::GREEN
                } else {
                    egui::Color32::RED
                };
                ui.label(egui::RichText::new(&self.status).color(color));
            }
        });
    }
}

fn main() {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([500.0, 350.0]),
        ..Default::default()
    };
    let _ = eframe::run_native(
        "Lvau SFX Extractor",
        options,
        Box::new(|_cc| Ok(Box::new(SfxExtractorApp::new()))),
    );
}
