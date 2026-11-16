//! Private Windows objects are created with an explicit DACL, then verified by
//! handle. POSIX mode bits and the DOS read-only attribute are not access checks.
use super::PrivateFileMode;
use std::{
    ffi::{OsStr, OsString, c_void},
    fs::File,
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::{Component, Path, PathBuf},
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_ALREADY_EXISTS, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE, LocalFree,
    },
    Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
        },
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetLengthSid, GetTokenInformation, IsValidAcl,
        IsValidSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        TOKEN_QUERY, TOKEN_USER, TokenUser,
    },
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateDirectoryW, CreateFileW,
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE,
        GetFileInformationByHandle, OPEN_ALWAYS, OPEN_EXISTING, READ_CONTROL,
    },
    System::{
        Com::CoTaskMemFree,
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
    UI::Shell::{FOLDERID_LocalAppData, FOLDERID_Profile, SHGetKnownFolderPath},
};

struct LocalAllocation(*mut c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: these allocations come from APIs documented to use LocalFree.
        unsafe {
            LocalFree(self.0);
        }
    }
}

fn last_error(context: &str) -> String {
    format!("{context}: {}", std::io::Error::last_os_error())
}

fn wide(value: &OsStr) -> Result<Vec<u16>, String> {
    let mut text: Vec<_> = value.encode_wide().collect();
    if text.contains(&0) {
        return Err("Windows path contains NUL".into());
    }
    text.push(0);
    Ok(text)
}

fn private_path(path: &Path) -> Result<Vec<u16>, String> {
    if !path.is_absolute()
        || path.components().any(|part| match part {
            Component::ParentDir => true,
            Component::Normal(name) => name.encode_wide().any(|c| c == b':' as u16),
            // Private state is local. UNC/device namespaces require different
            // trust and I/O bounds and are not accepted by this foundation.
            Component::Prefix(prefix) => !matches!(
                prefix.kind(),
                std::path::Prefix::Disk(_) | std::path::Prefix::VerbatimDisk(_)
            ),
            _ => false,
        })
    {
        return Err("Private state requires an absolute local drive path without traversal, device names, or alternate streams".into());
    }
    wide(path.as_os_str())
}

fn known_folder(id: &windows_sys::core::GUID) -> Option<PathBuf> {
    let mut value = null_mut();
    // SAFETY: id and the output pointer remain valid throughout the call.
    if unsafe { SHGetKnownFolderPath(id, 0, null_mut(), &mut value) } < 0 {
        return None;
    }
    if value.is_null() {
        return None;
    }
    // SAFETY: SHGetKnownFolderPath returned a NUL-terminated allocated string.
    let path = unsafe {
        let mut length = 0;
        while *value.add(length) != 0 {
            length += 1;
        }
        let path = PathBuf::from(OsString::from_wide(std::slice::from_raw_parts(
            value, length,
        )));
        CoTaskMemFree(value.cast());
        path
    };
    path.is_absolute().then_some(path)
}

pub(super) fn home_dir() -> Option<PathBuf> {
    known_folder(&FOLDERID_Profile)
}
pub(super) fn data_directory() -> Option<PathBuf> {
    known_folder(&FOLDERID_LocalAppData).map(|path| path.join("Distill"))
}

/// Own the aligned token buffer so pointers to its variable-length SID stay valid.
struct UserSid(Vec<usize>);
impl UserSid {
    fn current() -> Result<Self, String> {
        let mut token = null_mut();
        // SAFETY: current-process pseudo handle is valid and token is an out pointer.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(last_error("Cannot open user token"));
        }
        // SAFETY: the successful API call transferred ownership of this handle.
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let mut size = 0;
        // SAFETY: the first call asks only for the required buffer size.
        unsafe {
            GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut size);
        }
        if (size as usize) < std::mem::size_of::<TOKEN_USER>() || size > 65536 {
            return Err("Invalid user token size".into());
        }
        let mut buffer = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
        // SAFETY: buffer is aligned and has at least size writable bytes.
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                buffer.as_mut_ptr().cast(),
                size,
                &mut size,
            )
        } == 0
        {
            return Err(last_error("Cannot read user identity"));
        }
        let user = Self(buffer);
        // SAFETY: the successful TokenUser call initialized a TOKEN_USER and SID.
        if unsafe { IsValidSid(user.sid()) } == 0 {
            return Err("Invalid user SID".into());
        }
        Ok(user)
    }

    fn sid(&self) -> *mut c_void {
        // SAFETY: current() retains the aligned, API-initialized token buffer.
        unsafe { (*self.0.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }

    fn text(&self) -> Result<String, String> {
        let mut text = null_mut();
        // SAFETY: self retains a valid SID and text is an out pointer.
        if unsafe { ConvertSidToStringSidW(self.sid(), &mut text) } == 0 {
            return Err(last_error("Cannot encode user SID"));
        }
        let _allocation = LocalAllocation(text.cast());
        // SAFETY: the API returns an allocated, NUL-terminated SID string.
        unsafe {
            let mut length = 0;
            while *text.add(length) != 0 {
                length += 1;
            }
            String::from_utf16(std::slice::from_raw_parts(text, length)).map_err(|e| e.to_string())
        }
    }
}

fn descriptor(user: &UserSid) -> Result<LocalAllocation, String> {
    let sid = user.text()?;
    // Protected, inheritable DACL: grant only the current user, including when
    // the containing temp directory has broad inherited permissions.
    let text = wide(OsStr::new(&format!("O:{sid}D:P(A;OICI;FA;;;{sid})")))?;
    let mut descriptor = null_mut();
    // SAFETY: text is NUL terminated and descriptor is a valid out pointer.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(last_error("Cannot create private security descriptor"));
    }
    Ok(LocalAllocation(descriptor))
}

fn attributes(descriptor: &LocalAllocation) -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    }
}

fn file_from_handle(handle: *mut c_void) -> Result<File, String> {
    if handle == INVALID_HANDLE_VALUE {
        return Err(last_error("Cannot open private state"));
    }
    // SAFETY: CreateFileW returned a newly owned, non-invalid handle.
    Ok(File::from(unsafe { OwnedHandle::from_raw_handle(handle) }))
}

pub(super) fn private_directory(path: &Path) -> Result<(), String> {
    let name = private_path(path)?;
    if !path.try_exists().map_err(|error| error.to_string())? {
        let parent = path.parent().ok_or("Private directory has no parent")?;
        if !parent.try_exists().map_err(|error| error.to_string())? {
            private_directory(parent)?;
        }
        let user = UserSid::current()?;
        let descriptor = descriptor(&user)?;
        // SAFETY: name and attributes remain valid through synchronous creation.
        if unsafe { CreateDirectoryW(name.as_ptr(), &attributes(&descriptor)) } == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
                return Err(error.to_string());
            }
        }
    }
    validate_private_directory(path)
}

pub(super) fn validate_private_directory(path: &Path) -> Result<(), String> {
    let name = private_path(path)?;
    // Open the reparse point itself, never its target. Deny delete sharing while
    // checking the handle so a path replacement cannot change the checked object.
    let file = file_from_handle(unsafe {
        CreateFileW(
            name.as_ptr(),
            READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            null_mut(),
        )
    })?;
    validate_private_handle(&file, true)
}

pub(super) fn open_private(path: &Path, mode: PrivateFileMode) -> Result<File, String> {
    let name = private_path(path)?;
    let user = UserSid::current()?;
    let descriptor = descriptor(&user)?;
    let (access, disposition) = match mode {
        PrivateFileMode::Read => (GENERIC_READ, OPEN_EXISTING),
        PrivateFileMode::ReadWrite => (GENERIC_READ | GENERIC_WRITE, OPEN_ALWAYS),
        PrivateFileMode::CreateNew => (GENERIC_READ | GENERIC_WRITE, CREATE_NEW),
    };
    // SAFETY: all input buffers remain alive for this synchronous call. Existing
    // objects are not re-ACL'd: unsafe pre-existing permissions cause rejection.
    let file = file_from_handle(unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &attributes(&descriptor),
            disposition,
            FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    })?;
    validate_private_handle(&file, false)?;
    Ok(file)
}

pub(super) fn validate_private_handle(file: &File, directory: bool) -> Result<(), String> {
    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: file owns a valid handle and information is writable.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(last_error("Cannot inspect private state handle"));
    }
    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        || (!directory && !file.metadata().map_err(|e| e.to_string())?.is_file())
    {
        return Err(
            "Private state must have the expected type and cannot be a reparse point".into(),
        );
    }
    let mut owner = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: handle is valid; requested pointers belong to returned descriptor.
    let error = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    let _allocation = LocalAllocation(descriptor);
    if error != 0 {
        return Err(std::io::Error::from_raw_os_error(error as i32).to_string());
    }
    let user = UserSid::current()?;
    // SAFETY: GetSecurityInfo initialized these pointers into its live descriptor.
    unsafe {
        if owner.is_null()
            || IsValidSid(owner) == 0
            || EqualSid(owner, user.sid()) == 0
            || dacl.is_null()
            || IsValidAcl(dacl) == 0
            || (*dacl).AceCount == 0
        {
            return Err("State must be privately owned by the current Windows user".into());
        }
        for index in 0..(*dacl).AceCount {
            let mut ace = null_mut();
            if GetAce(dacl, u32::from(index), &mut ace) == 0 {
                return Err(last_error("Cannot inspect private ACL"));
            }
            let header = &*ace.cast::<ACE_HEADER>();
            let sid_offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
            // Reject all other ACE types conservatively, including conditional
            // grants and grants that only propagate to newly created children.
            if header.AceType != 0 || usize::from(header.AceSize) < sid_offset + 8 {
                return Err("Unsupported ACE in private state ACL".into());
            }
            let sid = ace.cast::<u8>().add(sid_offset).cast();
            if IsValidSid(sid) == 0
                || GetLengthSid(sid) as usize > usize::from(header.AceSize) - sid_offset
                || EqualSid(sid, user.sid()) == 0
            {
                return Err("State ACL grants access to another Windows principal".into());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_folders_and_sid_are_native_and_absolute() {
        assert!(home_dir().unwrap().is_absolute());
        assert!(data_directory().unwrap().is_absolute());
        assert!(
            UserSid::current()
                .unwrap()
                .text()
                .unwrap()
                .starts_with("S-1-")
        );
    }

    #[test]
    fn state_paths_reject_drive_relative_traversal_nul_and_streams() {
        for path in [
            "C:relative",
            "\\root-relative",
            "C:\\state\\..\\key",
            "C:\\state\\key:stream",
            "C:\\bad\0name",
            "\\\\.\\pipe\\name",
            "\\\\?\\pipe\\name",
            "\\\\server\\share\\key",
        ] {
            assert!(private_path(Path::new(path)).is_err(), "{path:?}");
        }
        assert!(private_path(Path::new("C:\\Users\\Test User\\资料\\key")).is_ok());
    }

    #[test]
    fn broad_acl_is_rejected_without_repairing_it() {
        use std::io::Write;
        let root = std::env::temp_dir().join(crate::new_id("distill-broad-acl"));
        let name = wide(root.as_os_str()).unwrap();
        let sid = UserSid::current().unwrap().text().unwrap();
        let text = wide(OsStr::new(&format!(
            "O:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;GR;;;WD)"
        )))
        .unwrap();
        let mut descriptor = null_mut();
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    text.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    null_mut(),
                )
            },
            0
        );
        let descriptor = LocalAllocation(descriptor);
        assert_ne!(
            unsafe { CreateDirectoryW(name.as_ptr(), &attributes(&descriptor)) },
            0
        );
        assert!(private_directory(&root).is_err());
        let path = root.join("public");
        File::create(&path).unwrap().write_all(b"public").unwrap();
        assert!(open_private(&path, PrivateFileMode::Read).is_err());
        // Both checks leave the pre-existing objects intact.
        assert_eq!(std::fs::read(&path).unwrap(), b"public");
        std::fs::remove_dir_all(root).unwrap();
    }
}
