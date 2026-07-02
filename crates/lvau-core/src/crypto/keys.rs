use base64::Engine;
use kem::Kem as KemTrait;
use kem::KeyExport;
use ml_kem::{DecapsulationKey768, EncapsulationKey768, MlKem768};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::Path;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::crypto::CryptoError;

type Kem = MlKem768;

#[derive(Serialize, Deserialize, Debug)]
pub struct HybridPublicKeyFormat {
    pub x25519_pub: String,
    pub mlkem_pub: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HybridPrivateKeyFormat {
    pub x25519_priv: String,
    pub mlkem_priv: String,
}

pub struct HybridPublicKey {
    pub x25519: X25519PublicKey,
    pub mlkem: EncapsulationKey768,
}

pub struct HybridPrivateKey {
    pub x25519: StaticSecret,
    pub mlkem: DecapsulationKey768,
}

#[cfg(windows)]
fn set_windows_acl(path: &Path) -> Result<(), std::io::Error> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenUser, TOKEN_QUERY,
        Authorization::SetNamedSecurityInfoW, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
        Authorization::EXPLICIT_ACCESS_W, Authorization::SET_ACCESS, NO_INHERITANCE,
        Authorization::SetEntriesInAclW,
        TRUSTEE_IS_SID, TRUSTEE_IS_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows_sys::Win32::Foundation::{HANDLE, LocalFree, ERROR_SUCCESS};
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
    use std::ptr::null_mut;

    unsafe {
        let mut token: HANDLE = 0;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(std::io::Error::last_os_error());
        }

        let mut ret_len = 0;
        GetTokenInformation(token, TokenUser, null_mut(), 0, &mut ret_len);
        
        let mut token_user_buf = vec![0u8; ret_len as usize];
        if GetTokenInformation(
            token,
            TokenUser,
            token_user_buf.as_mut_ptr() as *mut core::ffi::c_void,
            ret_len,
            &mut ret_len,
        ) == 0 {
            return Err(std::io::Error::last_os_error());
        }

        let token_user = &*(token_user_buf.as_ptr() as *const windows_sys::Win32::Security::TOKEN_USER);
        let user_sid = token_user.User.Sid;

        let mut ea = std::mem::zeroed::<EXPLICIT_ACCESS_W>();
        ea.grfAccessPermissions = FILE_ALL_ACCESS;
        ea.grfAccessMode = SET_ACCESS;
        ea.grfInheritance = NO_INHERITANCE;
        ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
        ea.Trustee.ptstrName = user_sid as *mut u16;

        let mut new_dacl = null_mut();
        if SetEntriesInAclW(1, &ea, null_mut(), &mut new_dacl) != ERROR_SUCCESS {
            return Err(std::io::Error::last_os_error());
        }

        let mut path_w: Vec<u16> = path.as_os_str().encode_wide().collect();
        path_w.push(0);

        let res = SetNamedSecurityInfoW(
            path_w.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            new_dacl,
            null_mut(),
        );

        LocalFree(new_dacl as _);

        if res != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(res as i32));
        }
    }
    Ok(())
}

fn write_key_file<P: AsRef<Path>>(
    path: P,
    contents: &str,
    private: bool,
) -> Result<(), CryptoError> {
    let path = path.as_ref();
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        if private {
            options.mode(0o600);
        }
    }

    let mut file = options.open(path)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;

    #[cfg(windows)]
    {
        if private {
            // Apply ACL to restrict file to the current user only
            if let Err(e) = set_windows_acl(path) {
                log::warn!("Failed to set strict ACL on key file: {}", e);
            }
        }
    }

    Ok(())
}

pub fn generate_keypair() -> (HybridPrivateKey, HybridPublicKey) {
    let rng = OsRng;

    let x25519_priv = StaticSecret::random_from_rng(rng);
    let x25519_pub = X25519PublicKey::from(&x25519_priv);

    let (mlkem_priv, mlkem_pub) = Kem::generate_keypair();

    let priv_key = HybridPrivateKey {
        x25519: x25519_priv,
        mlkem: mlkem_priv,
    };

    let pub_key = HybridPublicKey {
        x25519: x25519_pub,
        mlkem: mlkem_pub,
    };

    (priv_key, pub_key)
}

impl HybridPublicKey {
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), CryptoError> {
        let x25519_b64 = base64::engine::general_purpose::STANDARD.encode(self.x25519.as_bytes());

        let mlkem_b64 =
            base64::engine::general_purpose::STANDARD.encode(self.mlkem.to_bytes().as_slice());

        let format = HybridPublicKeyFormat {
            x25519_pub: x25519_b64,
            mlkem_pub: mlkem_b64,
        };

        let json =
            serde_json::to_string_pretty(&format).map_err(|_| CryptoError::DecryptionFailed)?;
        write_key_file(path, &json, false)?;
        Ok(())
    }

    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, CryptoError> {
        let json = fs::read_to_string(path)
            .map_err(|_| CryptoError::Io(std::io::Error::other("IO Error")))?;
        let format: HybridPublicKeyFormat =
            serde_json::from_str(&json).map_err(|_| CryptoError::DecryptionFailed)?;

        let x25519_bytes = base64::engine::general_purpose::STANDARD
            .decode(&format.x25519_pub)
            .map_err(|_| CryptoError::DecryptionFailed)?;
        let mlkem_bytes = base64::engine::general_purpose::STANDARD
            .decode(&format.mlkem_pub)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        if x25519_bytes.len() != 32 {
            return Err(CryptoError::DecryptionFailed);
        }

        let mut x_arr = [0u8; 32];
        x_arr.copy_from_slice(&x25519_bytes);
        let x25519 = X25519PublicKey::from(x_arr);

        let enc_arr: [u8; 1184] = mlkem_bytes
            .try_into()
            .map_err(|_| CryptoError::DecryptionFailed)?;
        let mlkem =
            EncapsulationKey768::new(&enc_arr.into()).map_err(|_| CryptoError::DecryptionFailed)?;

        Ok(Self { x25519, mlkem })
    }
}

impl HybridPrivateKey {
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), CryptoError> {
        let x25519_b64 = base64::engine::general_purpose::STANDARD.encode(self.x25519.to_bytes());

        let mlkem_b64 =
            base64::engine::general_purpose::STANDARD.encode(self.mlkem.to_bytes().as_slice());

        let format = HybridPrivateKeyFormat {
            x25519_priv: x25519_b64,
            mlkem_priv: mlkem_b64,
        };

        let json =
            serde_json::to_string_pretty(&format).map_err(|_| CryptoError::DecryptionFailed)?;
        write_key_file(path, &json, true)?;
        Ok(())
    }

    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, CryptoError> {
        let json = fs::read_to_string(path)
            .map_err(|_| CryptoError::Io(std::io::Error::other("IO Error")))?;
        let format: HybridPrivateKeyFormat =
            serde_json::from_str(&json).map_err(|_| CryptoError::DecryptionFailed)?;

        let x25519_bytes = base64::engine::general_purpose::STANDARD
            .decode(&format.x25519_priv)
            .map_err(|_| CryptoError::DecryptionFailed)?;
        let mlkem_bytes = base64::engine::general_purpose::STANDARD
            .decode(&format.mlkem_priv)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        if x25519_bytes.len() != 32 {
            return Err(CryptoError::DecryptionFailed);
        }

        let mut x_arr = [0u8; 32];
        x_arr.copy_from_slice(&x25519_bytes);
        let x25519 = StaticSecret::from(x_arr);

        let seed_arr: [u8; 64] = mlkem_bytes
            .try_into()
            .map_err(|_| CryptoError::DecryptionFailed)?;
        let mlkem = DecapsulationKey768::from_seed(seed_arr.into());

        Ok(Self { x25519, mlkem })
    }
}
