use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString, c_void};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, PathBuf, Prefix};
use std::process::Command;
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS};
use windows_sys::Win32::Networking::WinHttp::*;
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileInformationByHandle,
    MoveFileW,
};

#[derive(Deserialize)]
struct Lock {
    schema_version: u32,
    version: String,
    platforms: BTreeMap<String, VendorBinary>,
}

#[derive(Deserialize)]
struct VendorBinary {
    sha256: String,
    size_bytes: u64,
}

pub struct AcquiredNode {
    pub path: PathBuf,
    // Keep the verified file and its parent chain open through process launch.
    _file: File,
    _directories: Vec<File>,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

pub fn launch_arguments(args: Vec<OsString>) -> io::Result<(Vec<OsString>, Option<String>)> {
    if args.first().is_none_or(|arg| arg != "--mcpb-workspace") {
        return Ok((args, None));
    }
    let [_, value] = args.as_slice() else {
        return Err(invalid("Select one workspace directory in extension settings."));
    };
    let workspace = Path::new(value);
    if !workspace.is_absolute() {
        return Err(invalid("Choose an absolute workspace directory."));
    }
    let info = fs::symlink_metadata(workspace)?;
    if !info.is_dir() || info.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(invalid("Workspace must be a real directory."));
    }
    let value = value.to_str().ok_or_else(|| invalid("Workspace path must be valid Unicode."))?;
    Ok((vec!["mcp".into()], Some(serde_json::to_string(&[value])?)))
}

fn open_directory(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new().read(true).share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).open(path)?;
    let info = file.metadata()?;
    if !info.is_dir() || info.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(invalid("Node cache directory must be an ordinary directory."));
    }
    Ok(file)
}

fn private_directory(package: &Path, directory: &Path) -> io::Result<()> {
    let guard = package.join("bin/ud-agent-guard.exe");
    let output = Command::new(&guard).arg("identity").arg("--root").arg(directory).output()?;
    if !output.status.success() {
        return Err(invalid(format!("Cannot inspect Node cache ownership: {}", String::from_utf8_lossy(&output.stderr).trim())));
    }
    let identity: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let device = identity["device"].as_str().ok_or_else(|| invalid("Missing Node cache device identity."))?;
    let inode = identity["inode"].as_str().ok_or_else(|| invalid("Missing Node cache inode identity."))?;
    let output = Command::new(guard).arg("state-private-init").arg("--root").arg(directory)
        .args(["--path", ".", "--root-device", device, "--root-inode", inode]).output()?;
    if !output.status.success() {
        return Err(invalid(format!("Cannot verify private Node cache: {}", String::from_utf8_lossy(&output.stderr).trim())));
    }
    Ok(())
}

fn cache_directory(package: &Path) -> io::Result<(PathBuf, Vec<File>)> {
    let local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
        .ok_or_else(|| invalid("LOCALAPPDATA is required for the Node cache."))?;
    let mut parts = local.components();
    let (Some(Component::Prefix(prefix)), Some(Component::RootDir)) = (parts.next(), parts.next()) else {
        return Err(invalid("LOCALAPPDATA must be an absolute local path."));
    };
    if !matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)) {
        return Err(invalid("LOCALAPPDATA must be an absolute local path."));
    }
    let mut path = PathBuf::from(prefix.as_os_str());
    path.push("\\");
    let mut held = Vec::new();
    for component in parts {
        let Component::Normal(name) = component else { return Err(invalid("Invalid LOCALAPPDATA component.")); };
        path.push(name);
        held.push(open_directory(&path)?);
    }
    if held.is_empty() {
        return Err(invalid("LOCALAPPDATA must identify a user directory."));
    }
    for segment in ["ud-agent", "data", "node-cache"] {
        path.push(segment);
        match fs::create_dir(&path) {
            Ok(()) => (),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
            Err(error) => return Err(error),
        }
        held.push(open_directory(&path)?);
    }
    private_directory(package, &path)?;
    Ok((path, held))
}

fn checked_file(path: &Path, pin: &VendorBinary) -> io::Result<File> {
    let mut file = OpenOptions::new().read(true).share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(path)?;
    let info = file.metadata()?;
    let mut identity = BY_HANDLE_FILE_INFORMATION::default();
    win(unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut identity) })?;
    if !info.is_file() || info.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || info.len() != pin.size_bytes || identity.nNumberOfLinks != 1 {
        return Err(invalid(format!("Pinned Node cache file is invalid: {}", path.display())));
    }
    let mut hash = Sha256::new();
    let mut input = (&mut file).take(pin.size_bytes + 1);
    let mut buffer = [0u8; 65_536];
    let mut copied = 0u64;
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 { break; }
        hash.update(&buffer[..read]);
        copied += read as u64;
    }
    if copied != pin.size_bytes || checksum(hash) != pin.sha256 {
        return Err(invalid(format!("Pinned Node checksum differs: {}", path.display())));
    }
    Ok(file)
}

fn checksum(hash: Sha256) -> String {
    hash.finalize().iter().map(|byte| format!("{byte:02x}")).collect()
}

struct Internet(*mut c_void);
impl Internet {
    fn new(value: *mut c_void) -> io::Result<Self> {
        if value.is_null() { Err(io::Error::last_os_error()) } else { Ok(Self(value)) }
    }
}
impl Drop for Internet {
    fn drop(&mut self) { unsafe { WinHttpCloseHandle(self.0); } }
}

fn win(result: i32) -> io::Result<()> {
    if result == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

fn download(resource: &str, pin: &VendorBinary, output: &mut File) -> io::Result<()> {
    let session = Internet::new(unsafe {
        WinHttpOpen(wide("UD Agent Node bootstrap").as_ptr(), WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, null(), null(), 0)
    })?;
    win(unsafe { WinHttpSetTimeouts(session.0, 15_000, 15_000, 15_000, 15_000) })?;
    let server = Internet::new(unsafe { WinHttpConnect(session.0, wide("nodejs.org").as_ptr(), 443, 0) })?;
    let request = Internet::new(unsafe {
        WinHttpOpenRequest(server.0, wide("GET").as_ptr(), wide(resource).as_ptr(), null(), null(), null(), WINHTTP_FLAG_SECURE)
    })?;
    let policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    win(unsafe { WinHttpSetOption(request.0, WINHTTP_OPTION_REDIRECT_POLICY, (&raw const policy).cast(), 4) })?;
    win(unsafe { WinHttpSendRequest(request.0, null(), 0, null(), 0, 0, 0) })?;
    win(unsafe { WinHttpReceiveResponse(request.0, null_mut()) })?;
    let mut status = 0u32;
    let mut size = 4;
    win(unsafe { WinHttpQueryHeaders(request.0, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        null(), (&raw mut status).cast(), &mut size, null_mut()) })?;
    if status != 200 { return Err(invalid(format!("Node publisher returned HTTP {status}."))); }
    let mut hash = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 65_536];
    let started = Instant::now();
    loop {
        if started.elapsed() > Duration::from_secs(180) {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "Pinned Node download timed out."));
        }
        let mut read = 0;
        win(unsafe { WinHttpReadData(request.0, buffer.as_mut_ptr().cast(), buffer.len() as u32, &mut read) })?;
        if read == 0 { break; }
        bytes += u64::from(read);
        if bytes > pin.size_bytes { return Err(invalid("Pinned Node download exceeded the expected size.")); }
        let chunk = &buffer[..read as usize];
        hash.update(chunk);
        output.write_all(chunk)?;
    }
    if bytes != pin.size_bytes || checksum(hash) != pin.sha256 {
        return Err(invalid("Pinned Node download size or checksum differs from the publisher lock."));
    }
    output.sync_all()
}

struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) { let _ = fs::remove_file(&self.0); }
}

fn deposit(path: &Path, resource: &str, pin: &VendorBinary) -> io::Result<()> {
    let unique = SystemTime::now().duration_since(UNIX_EPOCH).map_err(io::Error::other)?.as_nanos();
    let temporary = path.with_extension(format!("{}-{unique}.part", std::process::id()));
    let mut output = OpenOptions::new().write(true).create_new(true).share_mode(0).open(&temporary)?;
    let cleanup = Temporary(temporary);
    let downloaded = download(resource, pin, &mut output);
    drop(output);
    downloaded?;
    if unsafe { MoveFileW(wide(&cleanup.0).as_ptr(), wide(path).as_ptr()) } == 0 {
        let error = io::Error::last_os_error();
        if !matches!(error.raw_os_error(), Some(code) if code == ERROR_ALREADY_EXISTS as i32 || code == ERROR_FILE_EXISTS as i32) {
            return Err(error);
        }
    }
    Ok(())
}

pub fn acquire(package: &Path, offline: bool) -> io::Result<AcquiredNode> {
    let architecture = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x64",
        _ => return Err(invalid("The Windows Node bootstrap requires x64 or ARM64.")),
    };
    let lock: Lock = serde_json::from_str(include_str!("windows-node.json"))?;
    let pin = lock.platforms.get(&format!("win32-{architecture}")).ok_or_else(|| invalid("Pinned Node architecture is missing."))?;
    if lock.schema_version != 1 || lock.version.split('.').count() != 3
        || !lock.version.bytes().all(|byte| byte.is_ascii_digit() || byte == b'.')
        || pin.sha256.len() != 64 || !pin.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) || pin.size_bytes == 0 {
        return Err(invalid("Pinned Node acquisition format is invalid."));
    }
    let (directory, held) = cache_directory(package)?;
    let path = directory.join(format!("node-{}.exe", pin.sha256));
    let file = match checked_file(&path, pin) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if offline { return Err(invalid(format!("Offline Windows Node executable is missing: {}", path.display()))); }
            let resource = format!("/dist/v{}/win-{architecture}/node.exe", lock.version);
            deposit(&path, &resource, pin).map_err(|error| invalid(format!("Cannot download pinned Node from https://nodejs.org{resource}: {error}")))?;
            checked_file(&path, pin)?
        }
        Err(error) => return Err(error),
    };
    Ok(AcquiredNode { path, _file: file, _directories: held })
}
