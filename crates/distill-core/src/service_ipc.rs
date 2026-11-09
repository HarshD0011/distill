//! Bounded authenticated IPC. Static analysis does not depend on this service.
use crate::Config;
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
pub const MAX_MESSAGE: usize = 2 * 1024 * 1024;

pub fn directory(config: &Config) -> Result<PathBuf, String> {
    config
        .service
        .directory
        .clone()
        .or_else(|| {
            std::env::var_os("HOME").map(|v| PathBuf::from(v).join(".config/distill/service"))
        })
        .ok_or_else(|| "Service directory unavailable".into())
}

pub fn endpoint(config: &Config) -> Result<Value, String> {
    let dir = directory(config)?;
    let meta = fs::symlink_metadata(&dir).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !meta.is_dir()
            || meta.file_type().is_symlink()
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.mode() & 0o077 != 0
        {
            return Err("Service directory is not private".into());
        }
    }
    let bytes = crate::integrity::read_private(&dir.join("endpoint.json"), 16384)?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if value["v"] != 1
        || value["token"].as_str().is_none_or(|v| v.len() != 64)
        || value["socket"]
            .as_str()
            .is_none_or(|v| Path::new(v).parent() != Some(dir.as_path()))
    {
        return Err("Invalid service endpoint".into());
    }
    Ok(value)
}

pub fn request(
    config: &Config,
    method: &str,
    params: Value,
    timeout: Duration,
) -> Result<Value, String> {
    let started = Instant::now();
    let endpoint = endpoint(config)?;
    let remaining = || {
        timeout
            .checked_sub(started.elapsed())
            .filter(|v| !v.is_zero())
            .ok_or_else(|| "Service deadline exhausted".to_owned())
    };
    let mut bytes=serde_json::to_vec(&json!({"v":1,"id":crate::new_id("rpc"),"method":method,"params":params,"token":endpoint["token"]})).map_err(|e|e.to_string())?;
    if bytes.len() > MAX_MESSAGE {
        return Err("Service message exceeds limit".into());
    }
    bytes.push(b'\n');
    #[cfg(unix)]
    let mut stream = connect_socket(
        Path::new(
            endpoint["socket"]
                .as_str()
                .ok_or("Missing service socket")?,
        ),
        remaining()?,
    )
    .map_err(|e| format!("Service connect: {e}"))?;
    #[cfg(not(unix))]
    return Err("Service requires Unix".into());
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        verify_peer(stream.as_raw_fd()).map_err(|e| format!("Service peer: {e}"))?;
        // Nonblocking I/O plus poll keeps one absolute deadline and avoids
        // repeatedly changing Unix kernel socket timeouts while replies arrive.
        let mut sent = 0;
        while sent < bytes.len() {
            let timeout = remaining()?;
            match stream.write(&bytes[sent..]) {
                Ok(0) => return Err("Service closed during request".into()),
                Ok(n) => sent += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    wait_io(stream.as_raw_fd(), libc::POLLOUT, timeout)?
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(format!("Service write: {e}")),
            }
        }
        let mut response = Vec::new();
        loop {
            let timeout = remaining()?;
            let mut chunk = [0; 8192];
            let count = match stream.read(&mut chunk) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    wait_io(stream.as_raw_fd(), libc::POLLIN, timeout)?;
                    continue;
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(format!("Service read: {e}")),
            };
            if count == 0 {
                break;
            }
            response.extend_from_slice(&chunk[..count]);
            if response.len() > MAX_MESSAGE {
                return Err("Service response exceeds limit".into());
            }
            if response.contains(&b'\n') {
                break;
            }
        }
        let response: Value = serde_json::from_slice(&response).map_err(|e| e.to_string())?;
        if response["ok"] != true {
            return Err(response["error"]
                .as_str()
                .unwrap_or("Service rejected request")
                .into());
        }
        Ok(response["result"].clone())
    }
}

pub fn record(config: &Config, mut event: Value) -> Result<(), String> {
    if !config.service.history_enabled {
        return Ok(());
    }
    crate::privacy::redact_value(&mut event);
    if request(
        config,
        "record",
        json!({"event":event}),
        Duration::from_millis(30),
    )
    .is_ok()
    {
        return Ok(());
    }
    // Opt-in bounded per-event spool. Names contain no command or argument data.
    let dir = directory(config)?.join("spool");
    crate::integrity::private_directory(&dir)?;
    let entries: Vec<_> = fs::read_dir(&dir)
        .map_err(|e| e.to_string())?
        .take(257)
        .filter_map(Result::ok)
        .collect();
    let total: u64 = entries
        .iter()
        .filter_map(|v| v.metadata().ok().map(|v| v.len()))
        .sum();
    let bytes = serde_json::to_vec(&event).map_err(|e| e.to_string())?;
    if entries.len() >= 256
        || bytes.len() > MAX_MESSAGE
        || total + bytes.len() as u64 > config.service.max_bytes.min(16 * 1024 * 1024)
    {
        return Err("Persistent event spool capacity reached".into());
    }
    let path = dir.join(format!("{}.json", crate::new_id("event")));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options
        .open(path)
        .and_then(|mut v| v.write_all(&bytes))
        .map_err(|e| e.to_string())
}

#[cfg(unix)]
fn connect_socket(
    path: &Path,
    timeout: Duration,
) -> Result<std::os::unix::net::UnixStream, String> {
    use std::os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    };
    let bytes = path.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.len() >= address.sun_path.len() {
        return Err("Trace socket path is too long".into());
    }
    address.sun_family = libc::AF_UNIX as _;
    for (target, byte) in address.sun_path.iter_mut().zip(bytes) {
        *target = *byte as _;
    }
    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(raw) };
    stream.set_nonblocking(true).map_err(|e| e.to_string())?;
    let result = unsafe {
        libc::connect(
            stream.as_raw_fd(),
            &address as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_un>() as _,
        )
    };
    if result < 0 {
        let error = std::io::Error::last_os_error();
        if !matches!(error.raw_os_error(), Some(libc::EINPROGRESS | libc::EAGAIN)) {
            return Err(error.to_string());
        }
        let mut descriptor = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        if unsafe { libc::poll(&mut descriptor, 1, timeout.as_millis().max(1) as i32) } <= 0 {
            return Err("Trace connection deadline exhausted".into());
        }
        if let Some(error) = stream.take_error().map_err(|e| e.to_string())? {
            return Err(error.to_string());
        }
    }
    Ok(stream)
}

#[cfg(unix)]
fn wait_io(fd: i32, events: i16, timeout: Duration) -> Result<(), String> {
    let mut descriptor = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    let ready = unsafe {
        libc::poll(
            &mut descriptor,
            1,
            timeout.as_millis().clamp(1, i32::MAX as u128) as i32,
        )
    };
    if ready == 0 {
        return Err("Service deadline exhausted".into());
    }
    if ready < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::Interrupted {
            return Ok(());
        }
        return Err(format!("Service poll: {error}"));
    }
    if descriptor.revents & libc::POLLNVAL != 0 {
        return Err("Service socket is invalid".into());
    }
    Ok(())
}

#[cfg(unix)]
pub fn verify_peer(fd: i32) -> Result<(), String> {
    let uid = unsafe { libc::geteuid() };
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    {
        let mut peer_uid = 0;
        let mut peer_gid = 0;
        if unsafe { libc::getpeereid(fd, &mut peer_uid, &mut peer_gid) } != 0 || peer_uid != uid {
            return Err("Unix peer credentials do not match the current user".into());
        }
    }
    #[cfg(target_os = "linux")]
    {
        let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut credentials as *mut _ as *mut _,
                &mut length,
            )
        } != 0
            || credentials.uid != uid
        {
            return Err("Unix peer credentials do not match the current user".into());
        }
    }
    Ok(())
}
#[cfg(not(unix))]
pub fn verify_peer(_: i32) -> Result<(), String> {
    Err("Unix peer verification unavailable".into())
}
