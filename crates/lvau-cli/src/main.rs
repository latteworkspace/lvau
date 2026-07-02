use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use lvau_core::crypto::{
    decrypt_file_keypair, decrypt_file_password, encrypt_file_keypair, encrypt_file_password,
    inspect_envelope,
    keys::{generate_keypair, HybridPrivateKey, HybridPublicKey},
};
use lvau_protocol::envelope::{KdfParams, Recipient, SecurityProfile};
use rpassword::read_password;
use secrecy::Secret;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "lvau-cli")]
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
        Commands::Inspect { in_file } => {
            ensure_input_file(&in_file)?;
            let header = inspect_envelope(&in_file)?;
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
        }
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
