//! Bounded, directory-handle-relative input access for the workspace broker.
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use cap_fs_ext::MetadataExt as PortableMetadataExt;
#[cfg(unix)]
use cap_std::fs::MetadataExt as UnixMetadataExt;
#[cfg(any(unix, windows))]
use cap_std::fs::OpenOptionsExt;
#[cfg(windows)]
use cap_std::fs::MetadataExt as WindowsMetadataExt;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::io::{self, BufRead, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

const MAX_FILE_SIZE: u64 = 256 * 1024 * 1024;
const MAX_STREAM_FILE_SIZE: u64 = 20 * 1024 * 1024 * 1024;
const MAX_ENTRIES: usize = 100_000;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod fs_metadata;
#[cfg(any(target_os = "macos", target_os = "linux", windows))]
mod fs_owned;
#[cfg(windows)]
mod fs_windows;
#[cfg(windows)]
mod wsl_session;
#[cfg(windows)]
mod windows_job;
#[cfg(any(target_os = "macos", target_os = "linux", windows))]
mod stream_supervisor;
#[cfg(target_os = "linux")]
mod linux_setup;
#[cfg(any(windows, test))]
mod windows_metadata_policy;
#[cfg(any(windows, test))]
mod windows_transaction_policy;
#[cfg(any(windows, test))]
mod windows_job_policy;
#[cfg(windows)]
use fs_windows::{create_file, metadata_file, remove_file};

fn checked_directory(dir: Dir) -> io::Result<Dir> {
    #[cfg(windows)]
    if WindowsMetadataExt::file_attributes(&dir.dir_metadata()?) & 0x400 != 0 { return Err(fail("reparse-point directories are not permitted")); }
    Ok(dir)
}

#[derive(Serialize)]
struct Entry {
    name: String,
    kind: &'static str,
    size: u64,
}

#[derive(Serialize)]
struct Identity {
    device: String,
    inode: String,
}

fn identity(dir: &Dir) -> io::Result<Identity> {
    let metadata = dir.dir_metadata()?;
    #[cfg(any(unix, windows))]
    return Ok(Identity { device: PortableMetadataExt::dev(&metadata).to_string(), inode: PortableMetadataExt::ino(&metadata).to_string() });
    #[cfg(not(any(unix, windows)))]
    Err(io::Error::other("root identity unsupported on this platform"))
}

fn fail(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn absolute_root(path: &Path) -> io::Result<Dir> {
    if !path.is_absolute() {
        return Err(fail("root must be an absolute path"));
    }
    let mut anchor = PathBuf::new();
    let mut current: Option<Dir> = None;
    for component in path.components() {
        match component {
            Component::Prefix(prefix) if current.is_none() => anchor.push(prefix.as_os_str()),
            Component::RootDir if current.is_none() => {
                anchor.push(component.as_os_str());
                current = Some(checked_directory(Dir::open_ambient_dir(&anchor, ambient_authority())?)?);
            }
            Component::Normal(name) => {
                let dir = current.take().ok_or_else(|| fail("invalid absolute root"))?;
                current = Some(checked_directory(dir.open_dir_nofollow(name)?)?);
            }
            _ => return Err(fail("invalid root component")),
        }
    }
    current.ok_or_else(|| fail("invalid absolute root"))
}

fn components(path: &Path, allow_dot: bool) -> io::Result<Vec<OsString>> {
    if allow_dot && path == Path::new(".") {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => out.push(name.to_os_string()),
            _ => return Err(fail("path must contain only relative normal components")),
        }
    }
    if out.is_empty() {
        return Err(fail("empty relative path"));
    }
    Ok(out)
}

fn open_directory(mut dir: Dir, path: &[OsString]) -> io::Result<Dir> {
    for name in path {
        dir = checked_directory(dir.open_dir_nofollow(name)?)?;
    }
    Ok(dir)
}

fn read_file(dir: Dir, path: &Path, max_bytes: u64) -> io::Result<Vec<u8>> {
    if max_bytes > MAX_FILE_SIZE {
        return Err(fail("requested file limit exceeds helper maximum"));
    }
    let mut names = components(path, false)?;
    let name = names.pop().ok_or_else(|| fail("missing filename"))?;
    let parent = open_directory(dir, &names)?;
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = parent.open_with(name, &options)?;
    let before = file.metadata()?;
    #[cfg(windows)]
    if WindowsMetadataExt::file_attributes(&before) & 0x400 != 0 { return Err(fail("reparse-point files are not permitted")); }
    if !before.is_file() {
        return Err(fail("input is not a regular file"));
    }
    if before.len() > max_bytes {
        return Err(fail("input exceeds requested limit"));
    }
    let mut bytes = Vec::new();
    let mut bounded = file.take(max_bytes.saturating_add(1));
    bounded.read_to_end(&mut bytes)?;
    let after = bounded.into_inner().metadata()?;
    if (bytes.len() as u64) > max_bytes || before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
    {
        return Err(io::Error::other("WORKTREE_CHANGED_DURING_SNAPSHOT"));
    }
    Ok(bytes)
}

fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Stream from one no-follow, directory-relative FD with bounded memory. The
/// receiver must reject partial bytes unless this command exits successfully.
fn stream_file(dir: Dir, path: &Path, max_bytes: u64) -> io::Result<()> {
    if max_bytes == 0 || max_bytes > MAX_STREAM_FILE_SIZE { return Err(fail("requested stream limit exceeds helper maximum")); }
    let mut names = components(path, false)?;
    let name = names.pop().ok_or_else(|| fail("missing filename"))?;
    let parent = open_directory(dir, &names)?;
    let mut options = OpenOptions::new(); options.read(true).follow(FollowSymlinks::No);
    // Deny concurrent Windows writers/deleters, including preexisting handles.
    #[cfg(windows)] options.share_mode(1);
    let mut file = parent.open_with(&name, &options)?;
    let before = file.metadata()?;
    #[cfg(windows)]
    if WindowsMetadataExt::file_attributes(&before) & 0x400 != 0 { return Err(fail("reparse-point files are not permitted")); }
    if !before.is_file() { return Err(fail("input is not a regular file")); }
    if before.len() > max_bytes { return Err(fail("input exceeds requested stream limit")); }
    #[cfg(windows)] let windows_identity = { use std::os::windows::io::AsRawHandle; fs_windows::file_identity(file.as_raw_handle())? };
    let mut stdout = io::stdout().lock(); let mut buffer = [0u8; 65536]; let mut total = 0u64;
    loop {
        let size = file.read(&mut buffer)?;
        if size == 0 { break; }
        total = total.checked_add(size as u64).ok_or_else(|| fail("stream byte count overflow"))?;
        if total > max_bytes { return Err(fail("input exceeds requested stream limit")); }
        stdout.write_all(&buffer[..size])?;
    }
    let after = file.metadata()?;
    let current = parent.open_with(&name, &options)?;
    let present = current.metadata()?;
    if total != before.len() || before.len() != after.len() || before.len() != present.len()
        || before.modified().ok() != after.modified().ok() || before.modified().ok() != present.modified().ok()
        || PortableMetadataExt::dev(&before) != PortableMetadataExt::dev(&present)
        || PortableMetadataExt::ino(&before) != PortableMetadataExt::ino(&present) {
        return Err(io::Error::other("WORKTREE_CHANGED_DURING_SNAPSHOT"));
    }
    #[cfg(unix)]
    if before.ctime() != after.ctime() || before.ctime_nsec() != after.ctime_nsec()
        || before.ctime() != present.ctime() || before.ctime_nsec() != present.ctime_nsec() {
        return Err(io::Error::other("WORKTREE_CHANGED_DURING_SNAPSHOT"));
    }
    #[cfg(windows)] {
        use std::os::windows::io::AsRawHandle;
        if fs_windows::file_identity(file.as_raw_handle())? != windows_identity || fs_windows::file_identity(current.as_raw_handle())? != windows_identity {
            return Err(io::Error::other("WORKTREE_CHANGED_DURING_SNAPSHOT"));
        }
    }
    stdout.flush()?; Ok(())
}

fn replace_file(dir: Dir, path: &Path, max_bytes: u64, expected: &str, replacement: &[u8]) -> io::Result<()> {
    if max_bytes > MAX_FILE_SIZE || (replacement.len() as u64) > max_bytes {
        return Err(fail("replacement exceeds permitted limit"));
    }
    if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(fail("before hash must be a lowercase SHA-256"));
    }
    let mut names = components(path, false)?;
    let name = names.pop().ok_or_else(|| fail("missing filename"))?;
    let parent = open_directory(dir, &names)?;
    let before = read_file(parent.try_clone()?, Path::new(&name), max_bytes)?;
    if hash(&before) != expected {
        return Err(io::Error::other("STALE_INPUT"));
    }
    #[cfg(windows)]
    return fs_windows::replace_file(parent, Path::new(&name), max_bytes, expected, replacement);
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    return Err(io::Error::other("REPLACEMENT_UNAVAILABLE: metadata preservation is unsupported on this platform"));
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let mut read_options = OpenOptions::new();
        read_options.read(true).follow(FollowSymlinks::No);
        // A capability directory can be backed by O_PATH on Linux, which is
        // suitable for relative operations but cannot be fsynced. Open a
        // readable handle to the same directory before touching the target.
        let sync_directory = parent.open_with(".", &read_options)?;
        let sync_metadata = sync_directory.metadata()?;
        let parent_metadata = parent.dir_metadata()?;
        if !sync_metadata.is_dir()
            || PortableMetadataExt::dev(&sync_metadata) != PortableMetadataExt::dev(&parent_metadata)
            || PortableMetadataExt::ino(&sync_metadata) != PortableMetadataExt::ino(&parent_metadata) {
            return Err(io::Error::other("WORKSPACE_ROOT_CHANGED"));
        }
        let original = parent.open_with(&name, &read_options)?;
        let original_metadata = original.metadata()?;
        if !original_metadata.is_file() || PortableMetadataExt::nlink(&original_metadata) != 1 {
            return Err(fail("destination must be a regular file without hard links"));
        }
        let original_attributes = fs_metadata::Metadata::read(&original)?;
        let mut temp_name = None;
        let mut temp_file = None;
        for attempt in 0..100u32 {
            let candidate = format!(".ud-agent-{}-{attempt}.tmp", std::process::id());
            let mut options = OpenOptions::new();
            options.write(true).create_new(true).follow(FollowSymlinks::No);
            options.mode(0o600);
            match parent.open_with(&candidate, &options) {
                Ok(file) => { temp_name = Some(candidate); temp_file = Some(file); break; }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        let temp_name = temp_name.ok_or_else(|| io::Error::other("temporary filename exhaustion"))?;
        let mut temp_file = temp_file.ok_or_else(|| io::Error::other("temporary file unavailable"))?;
        let result = (|| {
            temp_file.write_all(replacement)?;
            original_attributes.apply(&temp_file)?;
            temp_file.sync_all()?;
            let current = parent.open_with(&name, &read_options)?;
            let current_metadata = current.metadata()?;
            if PortableMetadataExt::dev(&current_metadata) != PortableMetadataExt::dev(&original_metadata)
                || PortableMetadataExt::ino(&current_metadata) != PortableMetadataExt::ino(&original_metadata)
                || PortableMetadataExt::nlink(&current_metadata) != 1
                || current_metadata.uid() != original_metadata.uid() || current_metadata.gid() != original_metadata.gid()
                || current_metadata.mode() != original_metadata.mode() || fs_metadata::Metadata::read(&current)? != original_attributes
                || hash(&read_file(parent.try_clone()?, Path::new(&name), max_bytes)?) != expected {
                return Err(io::Error::other("STALE_INPUT"));
            }
            drop(temp_file);
            // Atomic rename provides recoverable per-file replacement, not a
            // compare-and-swap against writers that ignore the workspace lock.
            parent.rename(&temp_name, &parent, &name)?;
            sync_directory.sync_all()?;
            Ok(())
        })();
        if result.is_err() { let _ = parent.remove_file(&temp_name); }
        result
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn file_parent(dir: Dir, path: &Path) -> io::Result<(Dir, OsString, cap_std::fs::File)> {
    let mut parts = components(path, false)?;
    let name = parts.pop().ok_or_else(|| fail("missing filename"))?;
    let parent = open_directory(dir, &parts)?;
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let sync = parent.open_with(".", &options)?;
    let actual = sync.metadata()?;
    let expected = parent.dir_metadata()?;
    if !actual.is_dir() || PortableMetadataExt::dev(&actual) != PortableMetadataExt::dev(&expected)
        || PortableMetadataExt::ino(&actual) != PortableMetadataExt::ino(&expected) {
        return Err(io::Error::other("WORKSPACE_ROOT_CHANGED"));
    }
    Ok((parent, name, sync))
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn metadata_file(dir: Dir, path: &Path, max_bytes: u64, expected: &str) -> io::Result<fs_metadata::Metadata> {
    let (parent, name, _) = file_parent(dir, path)?;
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = parent.open_with(&name, &options)?;
    if !file.metadata()?.is_file() || PortableMetadataExt::nlink(&file.metadata()?) != 1 { return Err(fail("destination must be a regular file without hard links")); }
    let metadata = fs_metadata::Metadata::read(&file)?;
    if hash(&read_file(parent.try_clone()?, Path::new(&name), max_bytes)?) != expected || fs_metadata::Metadata::read(&file)? != metadata {
        return Err(io::Error::other("STALE_INPUT"));
    }
    Ok(metadata)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn create_file(dir: Dir, path: &Path, max_bytes: u64, bytes: &[u8], metadata: Option<fs_metadata::Metadata>) -> io::Result<()> {
    use std::ffi::{c_char, c_int, CString};
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    unsafe extern "C" {
        #[cfg(target_os = "macos")]
        fn renameatx_np(from: c_int, old: *const c_char, to: c_int, new: *const c_char, flags: u32) -> c_int;
        #[cfg(target_os = "linux")]
        fn renameat2(from: c_int, old: *const c_char, to: c_int, new: *const c_char, flags: u32) -> c_int;
    }
    if max_bytes > MAX_FILE_SIZE || (bytes.len() as u64) > max_bytes { return Err(fail("creation exceeds permitted limit")); }
    let (parent, name, sync) = file_parent(dir, path)?;
    let mut temporary = None;
    for attempt in 0..100 {
        let name = format!(".ud-agent-create-{}-{attempt}.tmp", std::process::id());
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600).follow(FollowSymlinks::No);
        match parent.open_with(&name, &options) {
            Ok(file) => { temporary = Some((name, file)); break; }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    let (temp_name, mut file) = temporary.ok_or_else(|| io::Error::other("temporary filename exhaustion"))?;
    let result = (|| {
        file.write_all(bytes)?;
        if let Some(metadata) = metadata { metadata.apply(&file)?; }
        file.sync_all()?;
        let old = CString::new(temp_name.as_bytes()).map_err(|_| fail("invalid temporary name"))?;
        let new = CString::new(name.as_bytes()).map_err(|_| fail("invalid destination name"))?;
        #[cfg(target_os = "macos")]
        let status = unsafe { renameatx_np(parent.as_raw_fd(), old.as_ptr(), parent.as_raw_fd(), new.as_ptr(), 0x4) };
        #[cfg(target_os = "linux")]
        let status = unsafe { renameat2(parent.as_raw_fd(), old.as_ptr(), parent.as_raw_fd(), new.as_ptr(), 1) };
        if status != 0 { return Err(io::Error::last_os_error()); }
        sync.sync_all()?;
        Ok(())
    })();
    if result.is_err() { let _ = parent.remove_file(&temp_name); }
    result
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn remove_file(dir: Dir, path: &Path, max_bytes: u64, expected: &str) -> io::Result<()> {
    let (parent, name, sync) = file_parent(dir, path)?;
    metadata_file(parent.try_clone()?, Path::new(&name), max_bytes, expected)?;
    parent.remove_file(&name)?;
    sync.sync_all()
}

fn list_directory(dir: Dir, path: &Path) -> io::Result<Vec<Entry>> {
    let parent = open_directory(dir, &components(path, true)?)?;
    let mut result = Vec::new();
    for entry in parent.entries()? {
        let entry = entry?;
        let name = entry.file_name().into_string().map_err(|_| fail("non-UTF-8 filename"))?;
        let metadata = parent.symlink_metadata(&name)?;
        let kind = if metadata.file_type().is_symlink() {
            "symlink"
        } else if metadata.is_file() {
            "file"
        } else if metadata.is_dir() {
            "directory"
        } else {
            "other"
        };
        result.push(Entry { name, kind, size: metadata.len() });
        if result.len() > MAX_ENTRIES {
            return Err(fail("directory has too many entries"));
        }
    }
    result.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(result)
}

#[cfg(any(unix, windows))]
fn state_lock(dir: Dir, path: &Path, create: bool) -> io::Result<()> {
    let mut names = components(path, false)?;
    let name = names.pop().ok_or_else(|| fail("missing state lock filename"))?;
    let parent = open_directory(dir, &names)?;
    // Create the inode separately, then open an existing name. cap-std's
    // portable no-follow O_CREAT path can otherwise race another creator's
    // existence probe on macOS and report NotFound for a present parent.
    if create {
        let mut fresh = OpenOptions::new(); fresh.write(true).create_new(true).follow(FollowSymlinks::No);
        #[cfg(unix)] fresh.mode(0o600);
        match parent.open_with(&name, &fresh) { Ok(file) => drop(file), Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (), Err(error) => {
            #[cfg(windows)] if error.raw_os_error() == Some(32) { return Err(io::Error::new(io::ErrorKind::WouldBlock, "state lock is held")); }
            return Err(error);
        } }
    }
    let mut options = OpenOptions::new(); options.read(true).write(create).follow(FollowSymlinks::No);
    #[cfg(unix)] options.mode(0o600);
    #[cfg(windows)] { use cap_std::fs::OpenOptionsExt; options.share_mode(0); }
    let file = parent.open_with(name, &options).map_err(|error| {
        #[cfg(windows)]
        if error.raw_os_error() == Some(32) { return io::Error::new(io::ErrorKind::WouldBlock, "state lock is held"); }
        error
    })?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || PortableMetadataExt::nlink(&metadata) != 1 { return Err(fail("state lock must be a regular file without hard links")); }
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        unsafe extern "C" { fn getuid() -> u32; fn flock(fd: i32, operation: i32) -> i32; }
        if metadata.uid() != unsafe { getuid() } || metadata.mode() & 0o077 != 0 { return Err(fail("state lock must be private and current-user-owned")); }
        if unsafe { flock(file.as_raw_fd(), 2 | 4) } != 0 { return Err(io::Error::last_os_error()); }
    }
    #[cfg(windows)]
    fs_windows::verify_private_file(&file)?;
    let mut output = io::stdout().lock();
    writeln!(output, "{{\"schema_version\":1,\"locked\":true}}")?; output.flush()?; drop(output);
    // Parent pipe closure releases the kernel lock even after a coordinator
    // crash; persistent lock files never serve as ownership evidence.
    let mut byte = [0u8; 1];
    if io::stdin().lock().read(&mut byte)? != 0 { return Err(fail("state lock control pipe accepts only EOF")); }
    drop(file);
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn private_directory(dir: &Dir, initialize: bool) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    unsafe extern "C" { fn getuid() -> u32; fn fchmod(fd: i32, mode: u32) -> i32; }
    let before = dir.dir_metadata()?;
    if !before.is_dir() || before.uid() != unsafe { getuid() } { return Err(fail("private state must be current-user-owned directory")); }
    #[cfg(target_os = "macos")]
    fs_metadata::verify_private_directory_acl(dir.as_raw_fd())?;
    if initialize && before.mode() & 0o7777 != 0o700 {
        // Linux capability directories can use O_PATH, which cannot be
        // fchmod'ed or flushed. Reopen '.' relative to that exact handle and
        // verify the inode before changing permissions through the new FD.
        let mut options = OpenOptions::new(); options.read(true).follow(FollowSymlinks::No);
        let readable = dir.open_with(".", &options)?; let opened = readable.metadata()?;
        if !opened.is_dir() || PortableMetadataExt::dev(&opened) != PortableMetadataExt::dev(&before) || PortableMetadataExt::ino(&opened) != PortableMetadataExt::ino(&before) || opened.uid() != before.uid() { return Err(fail("private state directory identity changed")); }
        if unsafe { fchmod(readable.as_raw_fd(), 0o700) } != 0 { return Err(io::Error::last_os_error()); }
        readable.sync_all()?;
    }
    let after = dir.dir_metadata()?;
    if PortableMetadataExt::dev(&after) != PortableMetadataExt::dev(&before) || PortableMetadataExt::ino(&after) != PortableMetadataExt::ino(&before) || after.uid() != before.uid() || after.mode() & 0o7777 != 0o700 { return Err(fail("private state permissions are not verified")); }
    Ok(())
}

fn run(args: Vec<OsString>) -> io::Result<()> {
    let mut iter = args.into_iter();
    let command = iter.next().ok_or_else(|| fail("missing command"))?;
    let mut root = None;
    let mut path = None;
    let mut max_bytes = None;
    let mut root_device = None;
    let mut root_inode = None;
    let mut before_sha256 = None;
    let mut workspace = None;
    let mut workspace_device = None;
    let mut workspace_inode = None;
    let mut owner_token = None;
    let mut entry_device = None;
    let mut entry_inode = None;
    while let Some(arg) = iter.next() {
        let value = iter.next().ok_or_else(|| fail("missing argument value"))?;
        match arg.to_str() {
            Some("--root") if root.is_none() => root = Some(PathBuf::from(value)),
            Some("--path") if path.is_none() => path = Some(PathBuf::from(value)),
            Some("--max-bytes") if max_bytes.is_none() => {
                max_bytes = Some(value.to_str().ok_or_else(|| fail("invalid limit"))?
                    .parse::<u64>().map_err(|_| fail("invalid limit"))?);
            }
            Some("--root-device") if root_device.is_none() => root_device = Some(value),
            Some("--root-inode") if root_inode.is_none() => root_inode = Some(value),
            Some("--before-sha256") if before_sha256.is_none() => before_sha256 = Some(value),
            Some("--workspace") if workspace.is_none() => workspace = Some(PathBuf::from(value)),
            Some("--workspace-device") if workspace_device.is_none() => workspace_device = Some(value),
            Some("--workspace-inode") if workspace_inode.is_none() => workspace_inode = Some(value),
            Some("--owner-token") if owner_token.is_none() => owner_token = Some(value),
            Some("--entry-device") if entry_device.is_none() => entry_device = Some(value),
            Some("--entry-inode") if entry_inode.is_none() => entry_inode = Some(value),
            _ => return Err(fail("unknown or repeated option")),
        }
    }
    if (owner_token.is_some() || entry_device.is_some() || entry_inode.is_some()) && !["mkdir-owned", "release-owned", "rmdir-owned"].iter().any(|value| command == *value) { return Err(fail("incompatible directory ownership options")); }
    let dir = absolute_root(&root.ok_or_else(|| fail("missing root"))?)?;
    let current_identity = identity(&dir)?;
    match (&root_device, &root_inode) {
        (Some(device), Some(inode)) if device.to_str() == Some(&current_identity.device) && inode.to_str() == Some(&current_identity.inode) => (),
        (None, None) => (),
        _ => return Err(io::Error::other("WORKSPACE_ROOT_CHANGED")),
    }
    // The pair contract above establishes that either both identities are
    // present and verified, or neither is present. Admit commands from this
    // single invariant rather than repeating correlated option conditions.
    let root_bound = root_device.is_some();
    if command == "bind" {
        if root_bound || workspace_device.is_some() || workspace_inode.is_some() || path.is_some() || max_bytes.is_some() || before_sha256.is_some() {
            return Err(fail("incompatible bind options"));
        }
        let relative = workspace.ok_or_else(|| fail("missing workspace"))?;
        let workspace_dir = open_directory(dir, &components(&relative, true)?)?;
        serde_json::to_writer(io::stdout().lock(), &serde_json::json!({ "grant": current_identity, "workspace": identity(&workspace_dir)? }))?;
        return Ok(());
    }
    let dir = if let Some(relative) = workspace {
        if !root_bound || workspace_device.is_none() || workspace_inode.is_none() {
            return Err(fail("workspace and grant identities are required"));
        }
        let workspace_dir = open_directory(dir, &components(&relative, true)?)?;
        let current = identity(&workspace_dir)?;
        if workspace_device.as_ref().and_then(|value| value.to_str()) != Some(&current.device)
            || workspace_inode.as_ref().and_then(|value| value.to_str()) != Some(&current.inode) {
            return Err(io::Error::other("WORKSPACE_ROOT_CHANGED"));
        }
        workspace_dir
    } else {
        if workspace_device.is_some() || workspace_inode.is_some() { return Err(fail("workspace identity without workspace")); }
        dir
    };
    match command.to_str() {
        #[cfg(any(unix, windows))]
        Some("state-lock" | "state-lock-existing") if root_bound && max_bytes.is_none() && before_sha256.is_none() => {
            state_lock(dir, &path.ok_or_else(|| fail("missing path"))?, command == "state-lock")?;
        }
        #[cfg(any(target_os = "macos", target_os = "linux", windows))]
        Some("mkdir-owned" | "release-owned" | "rmdir-owned") if root_bound && max_bytes.is_none() && before_sha256.is_none() => {
            let path = path.ok_or_else(|| fail("missing path"))?;
            let token = owner_token.as_ref().and_then(|value| value.to_str()).ok_or_else(|| fail("missing directory owner token"))?;
            let expected = match (&entry_device, &entry_inode) {
                (Some(device), Some(inode)) => Some((device.to_str().ok_or_else(|| fail("invalid directory identity"))?, inode.to_str().ok_or_else(|| fail("invalid directory identity"))?)),
                (None, None) => None,
                _ => return Err(fail("incomplete directory identity")),
            };
            serde_json::to_writer(io::stdout().lock(), &fs_owned::operate(dir, &path, token, expected, command.to_str().ok_or_else(|| fail("invalid command"))?)?)?;
        }
        Some("capabilities") if path.is_none() && max_bytes.is_none() && before_sha256.is_none() => {
            #[cfg(windows)] let (metadata_preservation, metadata_model) = fs_windows::metadata_capability(&dir)?;
            #[cfg(not(windows))] let (metadata_preservation, metadata_model) = (cfg!(any(target_os = "macos", target_os = "linux")), "native-metadata-capture");
            serde_json::to_writer(io::stdout().lock(), &serde_json::json!({
                "schema_version": 1,
                "metadata_preservation": metadata_preservation,
                "metadata_model": metadata_model,
                "create_exclusive": cfg!(any(target_os = "macos", target_os = "linux", windows)),
                "remove_checked": cfg!(any(target_os = "macos", target_os = "linux", windows)),
            }))?;
        }
        Some("identity") if path.is_none() && max_bytes.is_none() && before_sha256.is_none() => {
            serde_json::to_writer(io::stdout().lock(), &current_identity)?;
        }
        Some("read" | "private-read") if before_sha256.is_none() => {
            let path = path.ok_or_else(|| fail("missing path"))?;
            #[cfg(windows)]
            if command == "private-read" { fs_windows::verify_private_target(dir.try_clone()?, &path)?; }
            let bytes = read_file(dir, &path, max_bytes.ok_or_else(|| fail("missing limit"))?)?;
            io::stdout().lock().write_all(&bytes)?;
        }
        Some("read-stream") if root_bound && before_sha256.is_none() => {
            stream_file(dir, &path.ok_or_else(|| fail("missing path"))?, max_bytes.ok_or_else(|| fail("missing limit"))?)?;
        }
        Some("list") if max_bytes.is_none() && before_sha256.is_none() => {
            let path = path.ok_or_else(|| fail("missing path"))?;
            serde_json::to_writer(io::stdout().lock(), &list_directory(dir, &path)?)?;
        }
        #[cfg(windows)]
        Some("state-private-init" | "state-private-check") if root_bound && max_bytes.is_none() && before_sha256.is_none() => {
            let directory = open_directory(dir, &components(&path.unwrap_or_else(|| PathBuf::from(".")), true)?)?;
            fs_windows::private_state(&directory, command == "state-private-init")?;
        }
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        Some("state-private-init" | "state-private-check") if root_bound && max_bytes.is_none() && before_sha256.is_none() => {
            let directory = open_directory(dir, &components(&path.unwrap_or_else(|| PathBuf::from(".")), true)?)?;
            private_directory(&directory, command == "state-private-init")?;
        }
        #[cfg(windows)]
        Some("flush-directory") if root_bound && max_bytes.is_none() && before_sha256.is_none() => {
            let directory = open_directory(dir, &components(&path.unwrap_or_else(|| PathBuf::from(".")), true)?)?;
            fs_windows::flush_directory(directory)?;
        }
        Some("replace") if root_bound => {
            let path = path.ok_or_else(|| fail("missing path"))?;
            let limit = max_bytes.ok_or_else(|| fail("missing limit"))?;
            if limit > MAX_FILE_SIZE { return Err(fail("requested limit exceeds helper maximum")); }
            let expected = before_sha256.ok_or_else(|| fail("missing before hash"))?;
            let expected = expected.to_str().ok_or_else(|| fail("invalid before hash"))?;
            let mut bytes = Vec::new();
            io::stdin().lock().take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
            replace_file(dir, &path, limit, expected, &bytes)?;
        }
        #[cfg(any(target_os = "macos", target_os = "linux", windows))]
        Some("flush-parent") if root_bound && max_bytes.is_none() && before_sha256.is_none() => {
            let path = path.ok_or_else(|| fail("missing path"))?;
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            file_parent(dir, &path)?.2.sync_all()?;
            #[cfg(windows)]
            fs_windows::flush_parent(dir, &path)?;
        }
        #[cfg(any(target_os = "macos", target_os = "linux", windows))]
        Some("metadata") if root_bound => {
            let path = path.ok_or_else(|| fail("missing path"))?;
            let expected = before_sha256.ok_or_else(|| fail("missing before hash"))?;
            serde_json::to_writer(io::stdout().lock(), &metadata_file(dir, &path, max_bytes.ok_or_else(|| fail("missing limit"))?, expected.to_str().ok_or_else(|| fail("invalid before hash"))?)?)?;
        }
        #[cfg(any(target_os = "macos", target_os = "linux", windows))]
        Some("create" | "restore") if root_bound && before_sha256.is_none() => {
            let path = path.ok_or_else(|| fail("missing path"))?;
            let limit = max_bytes.ok_or_else(|| fail("missing limit"))?;
            if limit > MAX_FILE_SIZE { return Err(fail("requested limit exceeds helper maximum")); }
            let mut input = io::stdin().lock();
            let metadata = if command == "restore" {
                let mut header = Vec::new();
                input.by_ref().take(2 * 1024 * 1024 + 1).read_until(b'\n', &mut header)?;
                if header.len() > 2 * 1024 * 1024 || header.last() != Some(&b'\n') { return Err(fail("invalid restore metadata")); }
                Some(serde_json::from_slice(&header).map_err(|_| fail("invalid restore metadata"))?)
            } else { None };
            let mut bytes = Vec::new();
            input.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
            create_file(dir, &path, limit, &bytes, metadata)?;
        }
        #[cfg(any(target_os = "macos", target_os = "linux", windows))]
        Some("remove") if root_bound => {
            let path = path.ok_or_else(|| fail("missing path"))?;
            let expected = before_sha256.ok_or_else(|| fail("missing before hash"))?;
            remove_file(dir, &path, max_bytes.ok_or_else(|| fail("missing limit"))?, expected.to_str().ok_or_else(|| fail("invalid before hash"))?)?;
        }
        #[cfg(windows)]
        Some("remove-preserved" | "release-metadata") if root_bound => {
            let path = path.ok_or_else(|| fail("missing path"))?; let limit = max_bytes.ok_or_else(|| fail("missing limit"))?;
            if limit > MAX_FILE_SIZE { return Err(fail("requested limit exceeds helper maximum")); }
            let mut bytes = Vec::new(); io::stdin().lock().take(2 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
            if bytes.len() > 2 * 1024 * 1024 { return Err(fail("Windows recovery metadata exceeds limit")); }
            let metadata = serde_json::from_slice(&bytes).map_err(|_| fail("invalid Windows recovery metadata"))?;
            if command == "remove-preserved" { let before = before_sha256.ok_or_else(|| fail("missing before hash"))?; fs_windows::remove_preserved(dir, &path, limit, before.to_str().ok_or_else(|| fail("invalid before hash"))?, metadata)?; }
            else { if before_sha256.is_some() { return Err(fail("unexpected before hash")); } fs_windows::release_metadata(dir, &path, limit, metadata)?; }
        }
        _ => return Err(fail("unknown command or incompatible option")),
    }
    Ok(())
}

fn main() -> ExitCode {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    #[cfg(any(target_os = "macos", target_os = "linux", windows))]
    if arguments.first().is_some_and(|value| value == "stream-supervise") {
        return match stream_supervisor::run(arguments.into_iter().skip(1).collect()) { Ok(()) => ExitCode::SUCCESS, Err(error) => { eprintln!("ud-agent-guard: stream supervision rejected: {error}"); ExitCode::FAILURE } };
    }
    #[cfg(target_os = "linux")]
    if arguments.first().is_some_and(|value| value == "contained-setup" || value == "contained-run") {
        let setup = arguments[0] == "contained-setup";
        let args = arguments.into_iter().skip(1).collect();
        return match if setup { linux_setup::run(args) } else { linux_setup::worker(args) } { Ok(code) => ExitCode::from(code), Err(error) => { eprintln!("ud-agent-guard: contained process rejected: {error}"); ExitCode::FAILURE } };
    }
    #[cfg(windows)]
    if arguments.first().is_some_and(|value| value == "wsl-session") {
        return match wsl_session::run(arguments.into_iter().skip(1).collect()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => { eprintln!("ud-agent-guard: WSL session rejected: {error}"); ExitCode::FAILURE }
        };
    }
    #[cfg(windows)]
    if arguments.first().is_some_and(|value| value == "contained-run" || value == "contained-setup") {
        let setup = arguments[0] == "contained-setup";
        let options = arguments.into_iter().skip(1).collect();
        return match if setup { windows_job::setup(options) } else { windows_job::run(options) } {
            Ok(code) => ExitCode::from(code),
            Err(error) => { eprintln!("ud-agent-guard: contained worker rejected: {error}"); ExitCode::FAILURE }
        };
    }
    match run(arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ud-agent-guard: {error}");
            eprintln!("ud-agent-guard-error: {}", serde_json::json!({ "kind": format!("{:?}", error.kind()), "os_code": error.raw_os_error() }));
            ExitCode::FAILURE
        }
    }
}
