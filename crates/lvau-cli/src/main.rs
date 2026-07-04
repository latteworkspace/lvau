use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use lvau_core::bundle::{
    extract_bundle, inspect_bundle, list_bundle, pack_directory, verify_bundle, PaddingProfile,
};
use lvau_core::crypto::{
    decrypt_file_keypair, decrypt_file_password, encrypt_file_keypair, encrypt_file_password,
    keys::{generate_keypair, HybridPrivateKey, HybridPublicKey},
    verify_file_keypair, verify_file_password,
};
use lvau_core::signing::{
    generate_signing_keypair, key_fingerprint, load_signing_key, load_verify_key,
    save_signing_key, save_verify_key, sign_file, verify_signature,
};
use lvau_protocol::envelope::{KdfParams, Recipient, SecurityProfile};
use rpassword::read_password;
use secrecy::Secret;
use serde::Serialize;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "lvau-cli")]
#[command(version)]
#[command(about = "Boring, inspectable file encryption.", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging without printing secrets.
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new hybrid keypair (X25519 + ML-KEM-768, experimental).
    Keygen {
        /// Base path to save the key files (.lvau-key and .lvau-pub will be appended).
        #[arg(short, long)]
        out_base: PathBuf,

        /// Replace existing key files.
        #[arg(short, long)]
        force: bool,
    },
    /// Encrypt a file.
    Encrypt {
        /// Input file path.
        #[arg(short, long)]
        in_file: PathBuf,

        /// Output file path.
        #[arg(short, long)]
        out_file: PathBuf,

        /// Use password encryption.
        #[arg(long, default_value_t = false)]
        password: bool,

        /// Read the password from a local file instead of prompting.
        #[arg(long)]
        password_file: Option<PathBuf>,

        /// Use public key encryption.
        #[arg(long)]
        pub_key: Option<PathBuf>,

        /// Security profile (fast, balanced, archive, paranoid, extreme).
        #[arg(long, default_value = "balanced")]
        profile: String,

        /// Use an additional cryptographic seed (pepper).
        #[arg(long, default_value_t = false)]
        seed: bool,

        /// Read the seed from a local file instead of prompting.
        #[arg(long)]
        seed_file: Option<PathBuf>,

        /// Create an experimental Windows self-extracting archive.
        #[arg(long, default_value_t = false)]
        sfx: bool,

        /// Replace an existing output file.
        #[arg(short, long)]
        force: bool,
    },
    /// Decrypt a file.
    Decrypt {
        /// Input file path.
        #[arg(short, long)]
        in_file: PathBuf,

        /// Output file path.
        #[arg(short, long)]
        out_file: PathBuf,

        /// Use password decryption.
        #[arg(long, default_value_t = false)]
        password: bool,

        /// Read the password from a local file instead of prompting.
        #[arg(long)]
        password_file: Option<PathBuf>,

        /// Use private key decryption.
        #[arg(long)]
        priv_key: Option<PathBuf>,

        /// Use an additional cryptographic seed (pepper).
        #[arg(long, default_value_t = false)]
        seed: bool,

        /// Read the seed from a local file instead of prompting.
        #[arg(long)]
        seed_file: Option<PathBuf>,

        /// Replace an existing output file.
        #[arg(short, long)]
        force: bool,
    },
    /// Inspect public envelope metadata without decrypting the payload.
    Inspect {
        /// Input file path.
        #[arg(short, long)]
        in_file: PathBuf,

        /// Output in JSON format for automation.
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Verify file integrity without writing plaintext to disk.
    Verify {
        /// Input file path.
        #[arg(short, long)]
        in_file: PathBuf,

        /// Use password verification.
        #[arg(long, default_value_t = false)]
        password: bool,

        /// Read the password from a local file instead of prompting.
        #[arg(long)]
        password_file: Option<PathBuf>,

        /// Use private key verification.
        #[arg(long)]
        priv_key: Option<PathBuf>,

        /// Use an additional cryptographic seed (pepper).
        #[arg(long, default_value_t = false)]
        seed: bool,

        /// Read the seed from a local file instead of prompting.
        #[arg(long)]
        seed_file: Option<PathBuf>,

        /// Output in JSON format for automation.
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Pack, extract, inspect, or verify encrypted directory bundles.
    Bundle {
        #[command(subcommand)]
        action: BundleAction,
    },
    /// Generate an Ed25519 signing keypair.
    SignKeygen {
        /// Base path to save the key files (.lvau-sign and .lvau-verify will be appended).
        #[arg(short, long)]
        out_base: PathBuf,

        /// Replace existing key files.
        #[arg(short, long)]
        force: bool,
    },
    /// Sign an encrypted .lvau file with an Ed25519 signing key.
    Sign {
        /// Input .lvau file to sign.
        #[arg(short, long)]
        in_file: PathBuf,

        /// Path to the signing key (.lvau-sign).
        #[arg(long)]
        signing_key: PathBuf,

        /// Output signed .lvau file.
        #[arg(short, long)]
        out_file: PathBuf,

        /// Optional comment to include in the signature.
        #[arg(long)]
        comment: Option<String>,

        /// Replace an existing output file.
        #[arg(short, long)]
        force: bool,
    },
    /// Verify an Ed25519 signature on an .lvau file.
    VerifySignature {
        /// Input .lvau file to verify.
        #[arg(short, long)]
        in_file: PathBuf,

        /// Path to the verifying key (.lvau-verify).
        #[arg(long)]
        verify_key: PathBuf,
    },
    /// Run built-in integration tests to ensure cryptography is functioning correctly.
    SelfTest,
    /// Print environment diagnostics and check for required dependencies.
    Doctor,
}

#[derive(Subcommand)]
enum BundleAction {
    /// Pack a directory into a single encrypted .lvau bundle.
    Pack {
        /// Input directory to pack.
        #[arg(long)]
        in_dir: PathBuf,

        /// Output .lvau file.
        #[arg(long)]
        out_file: PathBuf,

        /// Use password encryption.
        #[arg(long, default_value_t = false)]
        password: bool,

        /// Read the password from a local file instead of prompting.
        #[arg(long)]
        password_file: Option<PathBuf>,

        /// Security profile.
        #[arg(long, default_value = "balanced")]
        profile: String,

        /// Allow packing symlinks (rejected by default).
        #[arg(long, default_value_t = false)]
        allow_symlinks: bool,

        /// Metadata privacy profile (minimal, balanced, verbose).
        #[arg(long, default_value = "minimal")]
        metadata_profile: String,

        /// Size padding profile (none, bucket, fixed:<SIZE>).
        #[arg(long, default_value = "none")]
        pad: String,

        /// Optional public label visible in inspect output.
        #[arg(long)]
        public_label: Option<String>,

        /// Replace an existing output file.
        #[arg(short, long)]
        force: bool,
    },
    /// Inspect public envelope metadata of a bundle.
    Inspect {
        /// Input .lvau bundle file.
        #[arg(long)]
        in_file: PathBuf,

        /// Output in JSON format.
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// List files in a bundle (requires password).
    List {
        /// Input .lvau bundle file.
        #[arg(long)]
        in_file: PathBuf,

        /// Use password.
        #[arg(long, default_value_t = false)]
        password: bool,

        /// Read the password from a local file instead of prompting.
        #[arg(long)]
        password_file: Option<PathBuf>,

        /// Output in JSON format.
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Extract files from a bundle.
    Extract {
        /// Input .lvau bundle file.
        #[arg(long)]
        in_file: PathBuf,

        /// Output directory.
        #[arg(long)]
        out_dir: PathBuf,

        /// Use password.
        #[arg(long, default_value_t = false)]
        password: bool,

        /// Read the password from a local file instead of prompting.
        #[arg(long)]
        password_file: Option<PathBuf>,

        /// Allow extracting symlinks.
        #[arg(long, default_value_t = false)]
        allow_symlinks: bool,

        /// Preview extraction without writing files.
        #[arg(long, default_value_t = false)]
        dry_run: bool,

        /// Replace existing files.
        #[arg(short, long)]
        force: bool,
    },
    /// Verify bundle integrity without extracting.
    Verify {
        /// Input .lvau bundle file.
        #[arg(long)]
        in_file: PathBuf,

        /// Use password.
        #[arg(long, default_value_t = false)]
        password: bool,

        /// Read the password from a local file instead of prompting.
        #[arg(long)]
        password_file: Option<PathBuf>,
    },
}

#[derive(Debug)]
enum CliError {
    Message(String),
    Io(std::io::Error),
    Crypto(lvau_core::crypto::CryptoError),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Message(message) => write!(f, "{message}"),
            CliError::Io(error) => write!(f, "{error}"),
            CliError::Crypto(error) => write!(f, "{error}"),
        }
    }
}

impl From<std::io::Error> for CliError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<lvau_core::crypto::CryptoError> for CliError {
    fn from(error: lvau_core::crypto::CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<lvau_core::bundle::BundleError> for CliError {
    fn from(error: lvau_core::bundle::BundleError) -> Self {
        Self::Message(error.to_string())
    }
}

impl From<lvau_core::signing::SigningError> for CliError {
    fn from(error: lvau_core::signing::SigningError) -> Self {
        Self::Message(error.to_string())
    }
}

fn prompt_password(prompt: &str) -> Result<String, CliError> {
    print!("{prompt}");
    io::stdout().flush()?;
    read_password().map_err(CliError::Io)
}

fn read_secret_file(path: &Path) -> Result<String, CliError> {
    let value = fs::read_to_string(path)?;
    Ok(value.trim_end_matches(['\r', '\n']).to_string())
}

fn password_secret(
    password: bool,
    password_file: Option<&Path>,
    confirm: bool,
) -> Result<Option<Secret<String>>, CliError> {
    if let Some(path) = password_file {
        return Ok(Some(Secret::new(read_secret_file(path)?)));
    }

    if !password {
        return Ok(None);
    }

    let first = prompt_password("Enter password: ")?;
    if confirm {
        let second = prompt_password("Confirm password: ")?;
        if first != second {
            return Err(CliError::Message("Passwords do not match".to_string()));
        }
    }
    Ok(Some(Secret::new(first)))
}

fn seed_secret(seed: bool, seed_file: Option<&Path>) -> Result<Option<Secret<String>>, CliError> {
    if let Some(path) = seed_file {
        return Ok(Some(Secret::new(read_secret_file(path)?)));
    }

    if seed {
        return Ok(Some(Secret::new(prompt_password("Enter seed (pepper): ")?)));
    }

    Ok(None)
}

fn parse_profile(profile: &str) -> Result<SecurityProfile, CliError> {
    match profile.to_lowercase().as_str() {
        "fast" => Ok(SecurityProfile::Fast),
        "balanced" => Ok(SecurityProfile::Balanced),
        "archive" => Ok(SecurityProfile::Archive),
        "paranoid" => Ok(SecurityProfile::Paranoid),
        "extreme" => Ok(SecurityProfile::Extreme),
        _ => Err(CliError::Message(
            "Invalid profile. Valid options: fast, balanced, archive, paranoid, extreme"
                .to_string(),
        )),
    }
}

fn parse_padding(pad: &str) -> Result<PaddingProfile, CliError> {
    match pad.to_lowercase().as_str() {
        "none" => Ok(PaddingProfile::None),
        "bucket" => Ok(PaddingProfile::Bucket),
        s if s.starts_with("fixed:") => {
            let size_str = &s[6..];
            let size: usize = size_str.parse().map_err(|_| {
                CliError::Message(format!("Invalid fixed padding size: {size_str}"))
            })?;
            Ok(PaddingProfile::Fixed(size))
        }
        _ => Err(CliError::Message(
            "Invalid padding. Valid options: none, bucket, fixed:<SIZE>".to_string(),
        )),
    }
}

fn ensure_input_file(path: &Path) -> Result<(), CliError> {
    if !path.is_file() {
        return Err(CliError::Message(format!(
            "Input file does not exist: {}",
            path.display()
        )));
    }
    Ok(())
}

fn ensure_output_available(path: &Path, force: bool) -> Result<(), CliError> {
    if path.exists() && !force {
        return Err(CliError::Message(format!(
            "Output file already exists: {}. Use --force to replace it.",
            path.display()
        )));
    }
    Ok(())
}

fn require_one_mode(
    password_selected: bool,
    password_file: Option<&Path>,
    key_file: bool,
    password_name: &str,
    key_name: &str,
) -> Result<(), CliError> {
    let has_password = password_selected || password_file.is_some();
    match (has_password, key_file) {
        (true, false) | (false, true) => Ok(()),
        (false, false) => Err(CliError::Message(format!(
            "Specify either {password_name} or {key_name}"
        ))),
        (true, true) => Err(CliError::Message(format!(
            "Specify only one of {password_name} or {key_name}"
        ))),
    }
}

fn create_sfx(temp_out: &Path, out_file: &Path) -> Result<(), CliError> {
    let exe_dir = std::env::current_exe()?
        .parent()
        .ok_or_else(|| CliError::Message("Could not locate current executable directory".into()))?
        .to_path_buf();
    let stub_path = exe_dir.join(if cfg!(windows) {
        "lvau-stub.exe"
    } else {
        "lvau-stub"
    });

    if !stub_path.exists() {
        let _ = fs::remove_file(temp_out);
        return Err(CliError::Message(format!(
            "SFX stub not found at {}. Build lvau-stub before creating SFX archives.",
            stub_path.display()
        )));
    }

    fs::copy(&stub_path, out_file)?;
    let mut out_f = fs::OpenOptions::new().append(true).open(out_file)?;
    let payload_bytes = fs::read(temp_out)?;
    out_f.write_all(&payload_bytes)?;
    out_f.write_all(&(payload_bytes.len() as u64).to_le_bytes())?;
    out_f.write_all(b"LVAUSFX1")?;
    fs::remove_file(temp_out)?;
    Ok(())
}

fn get_progress_bar(len: u64) -> ProgressBar {
    let pb = ProgressBar::new(len);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
            .unwrap()
            .progress_chars("#>-"),
    );
    pb
}

/// JSON-serializable inspect result.
#[derive(Serialize)]
struct InspectResult {
    magic: String,
    version: u16,
    profile: String,
    algorithm: String,
    kdf: Option<KdfInfo>,
    recipient_count: usize,
    recipients: Vec<RecipientInfo>,
    content_type: Option<String>,
    public_label: Option<String>,
    signed: bool,
    signer_fingerprint: Option<String>,
}

#[derive(Serialize)]
struct KdfInfo {
    algorithm: String,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

#[derive(Serialize)]
struct RecipientInfo {
    index: usize,
    kind: String,
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn run() -> Result<(), CliError> {
    let cli = Cli::parse();

    let mut builder = env_logger::Builder::new();
    builder.filter_level(if cli.verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    });
    builder.init();

    match cli.command {
        Commands::Keygen { out_base, force } => {
            let priv_path = out_base.with_extension("lvau-key");
            let pub_path = out_base.with_extension("lvau-pub");
            ensure_output_available(&priv_path, force)?;
            ensure_output_available(&pub_path, force)?;

            println!("Generating experimental X25519 + ML-KEM-768 hybrid keypair...");
            let (priv_key, pub_key) = generate_keypair();

            priv_key.save_to_file(&priv_path)?;
            pub_key.save_to_file(&pub_path)?;

            println!("Private key: {}", priv_path.display());
            println!("Public key:  {}", pub_path.display());
        }
        Commands::Encrypt {
            in_file,
            out_file,
            password,
            password_file,
            pub_key,
            profile,
            seed,
            seed_file,
            sfx,
            force,
        } => {
            ensure_input_file(&in_file)?;
            ensure_output_available(&out_file, force)?;
            require_one_mode(
                password,
                password_file.as_deref(),
                pub_key.is_some(),
                "--password/--password-file",
                "--pub-key",
            )?;

            let sec_profile = parse_profile(&profile)?;
            let temp_out = if sfx {
                let mut tmp = out_file.clone();
                tmp.set_extension("tmp.lvau");
                ensure_output_available(&tmp, true)?;
                tmp
            } else {
                out_file.clone()
            };

            let file_len = fs::metadata(&in_file).map(|m| m.len()).unwrap_or(0);
            let pb = get_progress_bar(file_len);
            let mut progress_callback = |bytes: u64| pb.set_position(bytes);

            if let Some(pub_path) = pub_key {
                let pk = HybridPublicKey::load_from_file(&pub_path)?;
                encrypt_file_keypair(
                    &in_file,
                    &temp_out,
                    &pk,
                    sec_profile,
                    Some(&mut progress_callback),
                )?;
            } else {
                let pwd = password_secret(password, password_file.as_deref(), true)?
                    .ok_or_else(|| CliError::Message("Missing password".into()))?;
                let seed_val = seed_secret(seed, seed_file.as_deref())?;
                encrypt_file_password(
                    &in_file,
                    &temp_out,
                    pwd,
                    seed_val,
                    sec_profile,
                    Some(&mut progress_callback),
                )?;
            }
            pb.finish_and_clear();

            if sfx {
                create_sfx(&temp_out, &out_file)?;
            }

            println!("Encrypted: {}", out_file.display());
        }
        Commands::Decrypt {
            in_file,
            out_file,
            password,
            password_file,
            priv_key,
            seed,
            seed_file,
            force,
        } => {
            ensure_input_file(&in_file)?;
            ensure_output_available(&out_file, force)?;
            require_one_mode(
                password,
                password_file.as_deref(),
                priv_key.is_some(),
                "--password/--password-file",
                "--priv-key",
            )?;

            let file_len = fs::metadata(&in_file).map(|m| m.len()).unwrap_or(0);
            let pb = get_progress_bar(file_len);
            let mut progress_callback = |bytes: u64| pb.set_position(bytes);

            if let Some(priv_path) = priv_key {
                let pk = HybridPrivateKey::load_from_file(&priv_path)?;
                decrypt_file_keypair(&in_file, &out_file, &pk, Some(&mut progress_callback))?;
            } else {
                let pwd = password_secret(password, password_file.as_deref(), false)?
                    .ok_or_else(|| CliError::Message("Missing password".into()))?;
                let seed_val = seed_secret(seed, seed_file.as_deref())?;
                decrypt_file_password(
                    &in_file,
                    &out_file,
                    pwd,
                    seed_val,
                    Some(&mut progress_callback),
                )?;
            }
            pb.finish_and_clear();

            println!("Decrypted: {}", out_file.display());
        }
        Commands::Inspect { in_file, json } => {
            ensure_input_file(&in_file)?;

            // Read full envelope for content_type, signature, and label
            let data = fs::read(&in_file)?;
            let env_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
            let envelope: lvau_protocol::envelope::Envelope =
                postcard::from_bytes(&data[4..4 + env_len])
                    .map_err(|e| CliError::Message(format!("Envelope parse error: {e}")))?;

            let header = &envelope.header;
            let sig_fingerprint = envelope
                .signature
                .as_ref()
                .map(|s| hex_encode(&s.signer_fingerprint));

            if json {
                let result = InspectResult {
                    magic: std::str::from_utf8(&header.magic)
                        .unwrap_or("????")
                        .to_string(),
                    version: header.version,
                    profile: format!("{:?}", header.profile),
                    algorithm: format!("{:?}", header.algorithm),
                    kdf: match &header.kdf {
                        Some(KdfParams::Argon2id {
                            m_cost,
                            t_cost,
                            p_cost,
                            ..
                        }) => Some(KdfInfo {
                            algorithm: "Argon2id".to_string(),
                            m_cost: *m_cost,
                            t_cost: *t_cost,
                            p_cost: *p_cost,
                        }),
                        None => None,
                    },
                    recipient_count: header.recipients.len(),
                    recipients: header
                        .recipients
                        .iter()
                        .enumerate()
                        .map(|(i, r)| RecipientInfo {
                            index: i,
                            kind: match r {
                                Recipient::Password { .. } => "Password".to_string(),
                                Recipient::X25519MlkemHybrid { .. } => {
                                    "X25519+ML-KEM-768".to_string()
                                }
                            },
                        })
                        .collect(),
                    content_type: envelope.content_type.as_ref().map(|ct| format!("{ct:?}")),
                    public_label: envelope.public_label.clone(),
                    signed: envelope.signature.is_some(),
                    signer_fingerprint: sig_fingerprint.clone(),
                };
                println!(
                    "{}",
                    serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!("Lvau envelope metadata");
                println!(
                    "Magic:     {}",
                    std::str::from_utf8(&header.magic).unwrap_or("????")
                );
                println!("Version:   {}", header.version);
                println!("Profile:   {:?}", header.profile);
                println!("Algorithm: {:?}", header.algorithm);
                match &header.kdf {
                    Some(KdfParams::Argon2id {
                        m_cost,
                        t_cost,
                        p_cost,
                        ..
                    }) => {
                        println!(
                            "KDF:       Argon2id (m={} KiB, t={}, p={})",
                            m_cost, t_cost, p_cost
                        );
                    }
                    None => {
                        println!("KDF:       None (keypair-based)");
                    }
                }
                println!("Recipients: {}", header.recipients.len());
                for (i, recipient) in header.recipients.iter().enumerate() {
                    match recipient {
                        Recipient::Password { .. } => println!("  [{i}] Password (FEK wrapped)"),
                        Recipient::X25519MlkemHybrid { .. } => {
                            println!("  [{i}] X25519 + ML-KEM-768 hybrid")
                        }
                    }
                }
                if let Some(ct) = &envelope.content_type {
                    println!("Content:   {ct:?}");
                }
                if let Some(label) = &envelope.public_label {
                    println!("Label:     {label}");
                }
                if envelope.signature.is_some() {
                    println!("Signed:    yes");
                    if let Some(fp) = &sig_fingerprint {
                        println!("Signer:    {fp}");
                    }
                } else {
                    println!("Signed:    no");
                }
            }
        }
        Commands::Verify {
            in_file,
            password,
            password_file,
            priv_key,
            seed,
            seed_file,
            json,
        } => {
            ensure_input_file(&in_file)?;
            require_one_mode(
                password,
                password_file.as_deref(),
                priv_key.is_some(),
                "--password/--password-file",
                "--priv-key",
            )?;

            let file_len = fs::metadata(&in_file).map(|m| m.len()).unwrap_or(0);
            let pb = get_progress_bar(file_len);
            let mut progress_callback = |bytes: u64| pb.set_position(bytes);

            if let Some(priv_path) = priv_key {
                let pk = HybridPrivateKey::load_from_file(&priv_path)?;
                verify_file_keypair(&in_file, &pk, Some(&mut progress_callback))?;
            } else {
                let pwd = password_secret(password, password_file.as_deref(), false)?
                    .ok_or_else(|| CliError::Message("Missing password".into()))?;
                let seed_val = seed_secret(seed, seed_file.as_deref())?;
                verify_file_password(&in_file, pwd, seed_val, Some(&mut progress_callback))?;
            }
            pb.finish_and_clear();

            if json {
                println!("{{\"status\":\"ok\",\"file\":\"{}\"}}", in_file.display());
            } else {
                println!("Verification successful: {}", in_file.display());
            }
        }
        Commands::Bundle { action } => match action {
            BundleAction::Pack {
                in_dir,
                out_file,
                password,
                password_file,
                profile,
                allow_symlinks,
                metadata_profile: _,
                pad,
                public_label: _,
                force,
            } => {
                if !in_dir.is_dir() {
                    return Err(CliError::Message(format!(
                        "Input directory does not exist: {}",
                        in_dir.display()
                    )));
                }
                ensure_output_available(&out_file, force)?;

                let pwd = password_secret(password, password_file.as_deref(), true)?
                    .ok_or_else(|| CliError::Message("Missing password".into()))?;
                let sec_profile = parse_profile(&profile)?;
                let padding = parse_padding(&pad)?;

                let manifest = pack_directory(
                    &in_dir,
                    &out_file,
                    pwd,
                    sec_profile,
                    allow_symlinks,
                    &padding,
                    force,
                )?;

                println!(
                    "Bundle created: {} ({} files)",
                    out_file.display(),
                    manifest.entries.len()
                );
            }
            BundleAction::Inspect { in_file, json } => {
                ensure_input_file(&in_file)?;
                let (header, content_type, public_label) = inspect_bundle(&in_file)?;

                if json {
                    let result = serde_json::json!({
                        "magic": std::str::from_utf8(&header.magic).unwrap_or("????"),
                        "version": header.version,
                        "profile": format!("{:?}", header.profile),
                        "algorithm": format!("{:?}", header.algorithm),
                        "content_type": content_type.map(|ct| format!("{ct:?}")),
                        "public_label": public_label,
                    });
                    println!("{}", serde_json::to_string_pretty(&result).unwrap());
                } else {
                    println!("Bundle envelope metadata");
                    println!(
                        "Magic:     {}",
                        std::str::from_utf8(&header.magic).unwrap_or("????")
                    );
                    println!("Version:   {}", header.version);
                    println!("Profile:   {:?}", header.profile);
                    println!("Algorithm: {:?}", header.algorithm);
                    if let Some(ct) = content_type {
                        println!("Content:   {ct:?}");
                    }
                    if let Some(label) = public_label {
                        println!("Label:     {label}");
                    }
                    println!("(File names are encrypted in the payload)");
                }
            }
            BundleAction::List {
                in_file,
                password,
                password_file,
                json,
            } => {
                ensure_input_file(&in_file)?;
                let pwd = password_secret(password, password_file.as_deref(), false)?
                    .ok_or_else(|| CliError::Message("Missing password".into()))?;
                let manifest = list_bundle(&in_file, pwd)?;

                if json {
                    let entries: Vec<serde_json::Value> = manifest
                        .entries
                        .iter()
                        .map(|e| {
                            serde_json::json!({
                                "path": e.relative_path,
                                "size": e.size,
                                "blake3": hex_encode(&e.blake3_hash),
                            })
                        })
                        .collect();
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "file_count": manifest.entries.len(),
                            "entries": entries,
                        }))
                        .unwrap()
                    );
                } else {
                    println!("Bundle contents ({} files):", manifest.entries.len());
                    for entry in &manifest.entries {
                        println!("  {} ({} bytes)", entry.relative_path, entry.size);
                    }
                }
            }
            BundleAction::Extract {
                in_file,
                out_dir,
                password,
                password_file,
                allow_symlinks,
                dry_run,
                force,
            } => {
                ensure_input_file(&in_file)?;
                let pwd = password_secret(password, password_file.as_deref(), false)?
                    .ok_or_else(|| CliError::Message("Missing password".into()))?;

                if !dry_run {
                    fs::create_dir_all(&out_dir)?;
                }

                let manifest =
                    extract_bundle(&in_file, &out_dir, pwd, allow_symlinks, force, dry_run)?;

                if dry_run {
                    println!(
                        "Dry run: would extract {} files to {}",
                        manifest.entries.len(),
                        out_dir.display()
                    );
                    for entry in &manifest.entries {
                        println!("  {} ({} bytes)", entry.relative_path, entry.size);
                    }
                } else {
                    println!(
                        "Extracted {} files to {}",
                        manifest.entries.len(),
                        out_dir.display()
                    );
                }
            }
            BundleAction::Verify {
                in_file,
                password,
                password_file,
            } => {
                ensure_input_file(&in_file)?;
                let pwd = password_secret(password, password_file.as_deref(), false)?
                    .ok_or_else(|| CliError::Message("Missing password".into()))?;
                let manifest = verify_bundle(&in_file, pwd)?;
                println!("Bundle verified: {} files", manifest.entries.len());
            }
        },
        Commands::SignKeygen { out_base, force } => {
            let sign_path = out_base.with_extension("lvau-sign");
            let verify_path = out_base.with_extension("lvau-verify");
            ensure_output_available(&sign_path, force)?;
            ensure_output_available(&verify_path, force)?;

            println!("Generating Ed25519 signing keypair...");
            let (signing_key, verify_key) = generate_signing_keypair();

            save_signing_key(&signing_key, &sign_path, force)?;
            save_verify_key(&verify_key, &verify_path, force)?;

            let fingerprint = key_fingerprint(&verify_key);
            println!("Signing key:  {}", sign_path.display());
            println!("Verify key:   {}", verify_path.display());
            println!("Fingerprint:  {}", hex_encode(&fingerprint));
        }
        Commands::Sign {
            in_file,
            signing_key,
            out_file,
            comment,
            force,
        } => {
            ensure_input_file(&in_file)?;
            ensure_input_file(&signing_key)?;
            ensure_output_available(&out_file, force)?;

            let key = load_signing_key(&signing_key)?;
            sign_file(&in_file, &out_file, &key, comment, force)?;

            println!("Signed: {}", out_file.display());
        }
        Commands::VerifySignature {
            in_file,
            verify_key,
        } => {
            ensure_input_file(&in_file)?;
            ensure_input_file(&verify_key)?;

            let key = load_verify_key(&verify_key)?;
            match verify_signature(&in_file, &key) {
                Ok(fingerprint) => {
                    println!("Signature valid.");
                    println!("Signer fingerprint: {}", hex_encode(&fingerprint));
                }
                Err(lvau_core::signing::SigningError::NotSigned) => {
                    println!("File is not signed.");
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("Signature verification failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        Commands::Doctor => {
            println!("Lvau Diagnostics");
            println!("----------------");
            println!("Version: {}", env!("CARGO_PKG_VERSION"));
            println!("OS: {}", std::env::consts::OS);
            println!("Arch: {}", std::env::consts::ARCH);

            let exe_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("unknown"));
            println!("Executable path: {}", exe_path.display());

            let exe_dir = exe_path.parent().unwrap_or_else(|| Path::new("."));
            let stub_name = if cfg!(windows) {
                "lvau-stub.exe"
            } else {
                "lvau-stub"
            };
            let stub_path = exe_dir.join(stub_name);
            println!("SFX Stub available: {}", stub_path.exists());

            let test_file = std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(".lvau-write-test");
            let writable = fs::write(&test_file, b"test").is_ok();
            if writable {
                let _ = fs::remove_file(&test_file);
            }
            println!("Current directory writable: {}", writable);
        }
        Commands::SelfTest => {
            println!("Running self-test...");
            run_self_test()?;
        }
    }
    Ok(())
}

fn run_self_test() -> Result<(), CliError> {
    let mut passed = 0;
    let mut failed = 0;

    let mut run_test = |name: &str, test: Box<dyn Fn() -> Result<(), CliError>>| {
        print!("Test {:<30} ... ", name);
        let _ = io::stdout().flush();
        match test() {
            Ok(_) => {
                println!("OK");
                passed += 1;
            }
            Err(e) => {
                println!("FAILED ({})", e);
                failed += 1;
            }
        }
    };

    run_test(
        "password_roundtrip",
        Box::new(|| {
            let in_path = std::env::temp_dir().join("lvau_test_in_pw.bin");
            let enc_path = std::env::temp_dir().join("lvau_test_enc_pw.lvau");
            let dec_path = std::env::temp_dir().join("lvau_test_dec_pw.bin");
            let data = b"hello world password test";
            fs::write(&in_path, data)?;

            encrypt_file_password(
                &in_path,
                &enc_path,
                Secret::new("testpass".into()),
                None,
                SecurityProfile::Fast,
                None,
            )?;
            decrypt_file_password(
                &enc_path,
                &dec_path,
                Secret::new("testpass".into()),
                None,
                None,
            )?;

            let dec_data = fs::read(&dec_path)?;
            let _ = fs::remove_file(&in_path);
            let _ = fs::remove_file(&enc_path);
            let _ = fs::remove_file(&dec_path);

            if dec_data == data {
                Ok(())
            } else {
                Err(CliError::Message("Data mismatch".into()))
            }
        }),
    );

    run_test(
        "wrong_password_rejection",
        Box::new(|| {
            let in_path = std::env::temp_dir().join("lvau_test_in_wp.bin");
            let enc_path = std::env::temp_dir().join("lvau_test_enc_wp.lvau");
            let dec_path = std::env::temp_dir().join("lvau_test_dec_wp.bin");
            let data = b"hello world password test";
            fs::write(&in_path, data)?;

            encrypt_file_password(
                &in_path,
                &enc_path,
                Secret::new("testpass".into()),
                None,
                SecurityProfile::Fast,
                None,
            )?;
            let res = decrypt_file_password(
                &enc_path,
                &dec_path,
                Secret::new("wrongpass".into()),
                None,
                None,
            );

            let _ = fs::remove_file(&in_path);
            let _ = fs::remove_file(&enc_path);
            let _ = fs::remove_file(&dec_path);

            if res.is_err() {
                Ok(())
            } else {
                Err(CliError::Message("Expected decryption to fail".into()))
            }
        }),
    );

    run_test(
        "tamper_detection",
        Box::new(|| {
            let in_path = std::env::temp_dir().join("lvau_test_in_t.bin");
            let enc_path = std::env::temp_dir().join("lvau_test_enc_t.lvau");
            let dec_path = std::env::temp_dir().join("lvau_test_dec_t.bin");
            let data = b"hello world password test";
            fs::write(&in_path, data)?;

            encrypt_file_password(
                &in_path,
                &enc_path,
                Secret::new("testpass".into()),
                None,
                SecurityProfile::Fast,
                None,
            )?;

            let mut enc_data = fs::read(&enc_path)?;
            let len = enc_data.len();
            if len > 0 {
                enc_data[len - 1] ^= 1; // flip a bit in ciphertext
            }
            fs::write(&enc_path, enc_data)?;

            let res = decrypt_file_password(
                &enc_path,
                &dec_path,
                Secret::new("testpass".into()),
                None,
                None,
            );

            let _ = fs::remove_file(&in_path);
            let _ = fs::remove_file(&enc_path);
            let _ = fs::remove_file(&dec_path);

            if res.is_err() {
                Ok(())
            } else {
                Err(CliError::Message(
                    "Expected tamper detection to fail".into(),
                ))
            }
        }),
    );

    run_test(
        "streaming_large_file",
        Box::new(|| {
            let in_path = std::env::temp_dir().join("lvau_test_in_lf.bin");
            let enc_path = std::env::temp_dir().join("lvau_test_enc_lf.lvau");
            let dec_path = std::env::temp_dir().join("lvau_test_dec_lf.bin");
            let data = vec![0x42u8; 2_500_000]; // 2.5 MB to force multi-chunk
            fs::write(&in_path, &data)?;

            encrypt_file_password(
                &in_path,
                &enc_path,
                Secret::new("testpass".into()),
                None,
                SecurityProfile::Fast,
                None,
            )?;
            decrypt_file_password(
                &enc_path,
                &dec_path,
                Secret::new("testpass".into()),
                None,
                None,
            )?;

            let dec_data = fs::read(&dec_path)?;
            let _ = fs::remove_file(&in_path);
            let _ = fs::remove_file(&enc_path);
            let _ = fs::remove_file(&dec_path);

            if dec_data == data {
                Ok(())
            } else {
                Err(CliError::Message("Data mismatch on large file".into()))
            }
        }),
    );

    run_test(
        "keypair_roundtrip",
        Box::new(|| {
            let in_path = std::env::temp_dir().join("lvau_test_in_kp.bin");
            let enc_path = std::env::temp_dir().join("lvau_test_enc_kp.lvau");
            let dec_path = std::env::temp_dir().join("lvau_test_dec_kp.bin");
            let data = b"hello world keypair test";
            fs::write(&in_path, data)?;

            let (priv_key, pub_key) = generate_keypair();

            encrypt_file_keypair(&in_path, &enc_path, &pub_key, SecurityProfile::Fast, None)?;
            decrypt_file_keypair(&enc_path, &dec_path, &priv_key, None)?;

            let dec_data = fs::read(&dec_path)?;
            let _ = fs::remove_file(&in_path);
            let _ = fs::remove_file(&enc_path);
            let _ = fs::remove_file(&dec_path);

            if dec_data == data {
                Ok(())
            } else {
                Err(CliError::Message("Data mismatch".into()))
            }
        }),
    );

    println!("\nSelf-test summary: {} passed, {} failed", passed, failed);
    if failed > 0 {
        Err(CliError::Message("One or more self-tests failed".into()))
    } else {
        Ok(())
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
