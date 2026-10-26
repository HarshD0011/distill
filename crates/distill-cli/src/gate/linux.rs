//! Native unprivileged Linux containment: Landlock ABI >= 3 plus an architecture-checked seccomp floor.
#[cfg(target_os = "linux")]
pub fn apply(
    command: &mut std::process::Command,
    roots: &[std::path::PathBuf],
    writable: &[std::path::PathBuf],
    scratch: &std::path::Path,
) -> Result<(), String> {
    use std::{
        ffi::CString,
        fs::File,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{ffi::OsStrExt, process::CommandExt},
        },
    };
    #[repr(C)]
    struct Ruleset {
        handled_access_fs: u64,
    }
    #[repr(C, packed)]
    struct PathRule {
        allowed_access: u64,
        parent_fd: i32,
    }
    const READ: u64 = 1 | (1 << 2) | (1 << 3);
    const ALL: u64 = (1 << 15) - 1;
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0,
            1,
        )
    };
    if abi < 3 {
        return Err("Landlock ABI 3 or later is required; execution remains blocked".into());
    }
    let attr = Ruleset {
        handled_access_fs: ALL,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr,
            std::mem::size_of::<Ruleset>(),
            0,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let ruleset = unsafe { File::from_raw_fd(fd as i32) };
    let mut grants = [
        "/bin",
        "/usr/bin",
        "/usr/lib",
        "/usr/lib64",
        "/lib",
        "/lib64",
        "/usr/share",
        "/etc/ld.so.cache",
        "/dev/null",
        "/dev/urandom",
    ]
    .into_iter()
    .map(|path| (std::path::PathBuf::from(path), READ))
    .collect::<Vec<_>>();
    // Landlock grants are additive: writable workspace roots may expose secrets. Deny broad grants containing sensitive entries.
    for root in roots.iter().chain(writable) {
        let mut stack = vec![root.clone()];
        let mut count = 0;
        while let Some(path) = stack.pop() {
            count += 1;
            if count > 4096 {
                return Err("Linux grant inspection exceeds 4096 paths; choose a smaller clean staging workspace".into());
            }
            let metadata = std::fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            if metadata.file_type().is_symlink()
                || [
                    ".ssh",
                    ".aws",
                    ".git",
                    ".codex",
                    ".claude",
                    ".gnupg",
                    ".kube",
                    ".npmrc",
                    ".netrc",
                    "id_rsa",
                    "id_ed25519",
                ]
                .contains(&name)
                || name == ".env"
                || name.starts_with(".env.")
            {
                return Err("Linux containment refuses grants containing credentials, control directories, or symlinks; choose a clean staging workspace".into());
            }
            if metadata.is_dir() {
                for entry in std::fs::read_dir(&path).map_err(|e| e.to_string())? {
                    if stack.len() + count >= 4096 {
                        return Err("Linux grant inspection exceeds 4096 paths".into());
                    }
                    stack.push(entry.map_err(|e| e.to_string())?.path());
                }
            }
        }
    }
    grants.extend(roots.iter().cloned().map(|path| (path, READ)));
    grants.extend(
        writable
            .iter()
            .cloned()
            .chain([scratch.to_path_buf()])
            .map(|path| (path, ALL)),
    );
    for (path, access) in grants {
        if !path.exists() {
            continue;
        }
        let name = CString::new(path.as_os_str().as_bytes()).map_err(|_| "NUL in sandbox path")?;
        let fd = unsafe { libc::open(name.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let access = if path.is_dir() {
            access
        } else {
            access & (1 | (1 << 1) | (1 << 2) | (1 << 14))
        };
        let rule = PathRule {
            allowed_access: access,
            parent_fd: file.as_raw_fd(),
        };
        if unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset.as_raw_fd(),
                1,
                &rule,
                0,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    let arch = if cfg!(target_arch = "x86_64") {
        0xc000003e
    } else if cfg!(target_arch = "aarch64") {
        0xc00000b7
    } else {
        return Err("Seccomp backend supports x86_64 and aarch64".into());
    };
    let statement = |code, k| libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    };
    let mut filter = vec![
        statement(0x20, 4),
        libc::sock_filter {
            code: 0x15,
            jt: 1,
            jf: 0,
            k: arch,
        },
        statement(0x06, 0x80000000),
        statement(0x20, 0),
    ];
    for syscall in [
        libc::SYS_ioctl,
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_ptrace,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_bpf,
        libc::SYS_open_by_handle_at,
        libc::SYS_pidfd_getfd,
        libc::SYS_io_uring_setup,
        libc::SYS_kill,
        libc::SYS_tkill,
        libc::SYS_tgkill,
    ] {
        filter.push(libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: syscall as u32,
        });
        filter.push(statement(0x06, 0x00050000 | libc::EPERM as u32));
    }
    // x32 changes syscall numbers while retaining the x86_64 audit architecture.
    filter.push(libc::sock_filter {
        code: 0x45,
        jt: 0,
        jf: 1,
        k: 0x40000000,
    });
    filter.push(statement(0x06, 0x80000000));
    filter.push(statement(0x06, 0x7fff0000));
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                || libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            let program = libc::sock_fprog {
                len: filter.len() as u16,
                filter: filter.as_ptr() as *mut _,
            };
            if libc::prctl(libc::PR_SET_SECCOMP, 2, &program) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(())
}
#[cfg(not(target_os = "linux"))]
pub fn apply(
    _: &mut std::process::Command,
    _: &[std::path::PathBuf],
    _: &[std::path::PathBuf],
    _: &std::path::Path,
) -> Result<(), String> {
    Err("Linux containment is unavailable on this platform".into())
}
