#!/usr/bin/env python3
"""Replace unsupported Windows metadata link-count access with Win32 handle inspection."""

from pathlib import Path

root = Path(__file__).resolve().parents[1]
path = root / "crates/lvau-core/src/bundle_stream.rs"
text = path.read_text(encoding="utf-8")
old = '''    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(BundleError::SymlinkRejected(path.display().to_string()));
        }
        if metadata.number_of_links() != 1 {
            return Err(BundleError::HardlinkRejected(path.display().to_string()));
        }
    }
'''
new = '''    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT,
            FILE_FLAG_OPEN_REPARSE_POINT,
        };

        let mut options = fs::OpenOptions::new();
        options.write(true).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        let file = options.open(path)?;
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        let ok = unsafe {
            GetFileInformationByHandle(file.as_raw_handle() as isize, std::ptr::addr_of_mut!(info))
        };
        if ok == 0 {
            return Err(BundleError::Io(std::io::Error::last_os_error()));
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(BundleError::SymlinkRejected(path.display().to_string()));
        }
        if info.nNumberOfLinks != 1 {
            return Err(BundleError::HardlinkRejected(path.display().to_string()));
        }
    }
'''
if old not in text and new not in text:
    raise SystemExit("expected Windows validation block was not found")
path.write_text(text.replace(old, new), encoding="utf-8")
