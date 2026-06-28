use clap::{Parser, Subcommand};
use lvau_core::crypto::{
    decrypt_file_password, encrypt_file_password, decrypt_file_keypair, encrypt_file_keypair,
    keys::{generate_keypair, HybridPublicKey, HybridPrivateKey},
    inspect_envelope
};
use lvau_protocol::envelope::SecurityProfile;
use rpassword::read_password;
use secrecy::Secret;
use std::io::{self, Write};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "Lvau")]
#[command(about = "Lvau CLI - Standard, robust, Post-Quantum cryptography.", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging for visual debugging
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new Post-Quantum Hybrid Identity Keypair
    Keygen {
        /// Base path to save the key files (.lvau-key and .lvau-pub will be appended)
        #[arg(short, long)]
        out_base: PathBuf,
    },
    /// Encrypt a file
    Encrypt {
        /// Input file path
        #[arg(short, long)]
        in_file: PathBuf,

        /// Output file path
        #[arg(short, long)]
        out_file: PathBuf,

        /// Use password encryption
        #[arg(long, default_value_t = false)]
        password: bool,

        /// Use public key encryption
        #[arg(long)]
        pub_key: Option<PathBuf>,

        /// Security profile (fast, balanced, archive, paranoid, extreme)
        #[arg(long, default_value = "balanced")]
        profile: String,

        /// Use an additional cryptographic seed (pepper)
        #[arg(long, default_value_t = false)]
        seed: bool,

        /// Create a Self-Extracting Archive (SFX) executable
        #[arg(long, default_value_t = false)]
        sfx: bool,
    },
    /// Decrypt a file
    Decrypt {
        /// Input file path
        #[arg(short, long)]
        in_file: PathBuf,

        /// Output file path
        #[arg(short, long)]
        out_file: PathBuf,

        /// Use password decryption
        #[arg(long, default_value_t = false)]
        password: bool,

        /// Use private key decryption
        #[arg(long)]
        priv_key: Option<PathBuf>,

        /// Use an additional cryptographic seed (pepper)
        #[arg(long, default_value_t = false)]
        seed: bool,
    },
    /// Inspect an encrypted file
    Inspect {
        /// Input file path
        #[arg(short, long)]
        in_file: PathBuf,
    },
}

fn prompt_password(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    read_password().unwrap()
}

fn main() {
    let cli = Cli::parse();
    
    let mut builder = env_logger::Builder::new();
    if cli.verbose {
        builder.filter_level(log::LevelFilter::Debug);
    } else {
        builder.filter_level(log::LevelFilter::Info);
    }
    builder.init();

    match cli.command {
        Commands::Keygen { out_base } => {
            let priv_path = out_base.with_extension("lvau-key");
            let pub_path = out_base.with_extension("lvau-pub");
            
            println!("Generating ML-KEM-768 + X25519 Hybrid Keypair...");
            let (priv_key, pub_key) = generate_keypair();
            
            priv_key.save_to_file(&priv_path).unwrap();
            pub_key.save_to_file(&pub_path).unwrap();
            
            println!("Identity saved!");
            println!("Private Key: {}", priv_path.display());
            println!("Public Key:  {}", pub_path.display());
        }
        Commands::Encrypt {
            in_file,
            out_file,
            password,
            pub_key,
            profile,
            seed,
            sfx,
        } => {
            let sec_profile = match profile.to_lowercase().as_str() {
                "fast" => SecurityProfile::Fast,
                "balanced" => SecurityProfile::Balanced,
                "archive" => SecurityProfile::Archive,
                "paranoid" => SecurityProfile::Paranoid,
                "extreme" => SecurityProfile::Extreme,
                _ => {
                    eprintln!("Invalid profile. Valid options: fast, balanced, archive, paranoid, extreme");
                    std::process::exit(1);
                }
            };

            let temp_out = if sfx {
                in_file.with_extension("tmp.lvau")
            } else {
                out_file.clone()
            };

            if let Some(pub_path) = pub_key {
                let pk = HybridPublicKey::load_from_file(&pub_path).expect("Failed to load public key");
                encrypt_file_keypair(&in_file, &temp_out, &pk, sec_profile).expect("Encryption failed");
            } else if password {
                let p1 = prompt_password("Enter password: ");
                let p2 = prompt_password("Confirm password: ");
                if p1 != p2 {
                    eprintln!("Passwords do not match!");
                    std::process::exit(1);
                }

                let seed_val = if seed {
                    let s = prompt_password("Enter seed (pepper): ");
                    Some(Secret::new(s))
                } else {
                    None
                };
                
                encrypt_file_password(&in_file, &temp_out, Secret::new(p1), seed_val, sec_profile)
                    .expect("Encryption failed");
            } else {
                eprintln!("Must specify either --password or --pub-key");
                std::process::exit(1);
            }

            if sfx {
                let exe_dir = std::env::current_exe().unwrap().parent().unwrap().to_path_buf();
                let stub_path = exe_dir.join("lvau-stub.exe");
                
                if !stub_path.exists() {
                    eprintln!("Error: lvau-stub.exe not found. SFX creation failed.");
                    std::fs::remove_file(&temp_out).ok();
                    std::process::exit(1);
                }
                
                std::fs::copy(&stub_path, &out_file).expect("Failed to copy stub");
                let mut out_f = std::fs::OpenOptions::new().append(true).open(&out_file).unwrap();
                let payload_bytes = std::fs::read(&temp_out).unwrap();
                out_f.write_all(&payload_bytes).unwrap();
                let payload_len = payload_bytes.len() as u64;
                out_f.write_all(&payload_len.to_le_bytes()).unwrap();
                out_f.write_all(b"LVAUSFX1").unwrap();
                std::fs::remove_file(&temp_out).ok();
            }

            println!("Successfully encrypted file to {:?}", out_file);
        }
        Commands::Decrypt {
            in_file,
            out_file,
            password,
            priv_key,
            seed,
        } => {
            if let Some(priv_path) = priv_key {
                let pk = HybridPrivateKey::load_from_file(&priv_path).expect("Failed to load private key");
                decrypt_file_keypair(&in_file, &out_file, &pk).expect("Decryption failed");
            } else if password {
                let p = prompt_password("Enter password: ");
                let seed_val = if seed {
                    let s = prompt_password("Enter seed (pepper): ");
                    Some(Secret::new(s))
                } else {
                    None
                };

                decrypt_file_password(&in_file, &out_file, Secret::new(p), seed_val)
                    .expect("Decryption failed");
            } else {
                eprintln!("Must specify either --password or --priv-key");
                std::process::exit(1);
            }
            println!("Successfully decrypted file to {:?}", out_file);
        }
        Commands::Inspect { in_file } => {
            inspect_envelope(&in_file).expect("Inspection failed");
        }
    }
}
