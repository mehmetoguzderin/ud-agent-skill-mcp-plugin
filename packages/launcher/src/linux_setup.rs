//! Owned setup process trees, including subreaper cleanup in PID1-less runners.
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_fs_ext::MetadataExt as PortableMetadataExt;
use cap_std::fs::{MetadataExt, OpenOptions};

static CANCELLED: AtomicBool = AtomicBool::new(false);
unsafe extern "C" {
    fn prctl(option: i32, ...) -> i32;
    fn signal(signal: i32, handler: usize) -> usize;
    fn kill(pid: i32, signal: i32) -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    fn getppid() -> i32;
    fn fcntl(fd: i32, operation: i32, ...) -> i32;
    fn geteuid() -> u32;
}
extern "C" fn cancel(_: i32) { CANCELLED.store(true, Ordering::SeqCst); }

/// Follow only a coordinator-verified executable alias (for example uv's venv
/// Python). Hash the exact no-follow FD that will be executed, never a second
/// pathname open. Bootstrap files retain the stricter no-alias policy.
fn pin_file(filename: &Path, expected: &str, limit: u64, executable_alias: bool) -> io::Result<cap_std::fs::File> {
    if !filename.is_absolute() || expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) { return Err(super::fail("invalid contained file identity")); }
    let resolved = if executable_alias { std::fs::canonicalize(filename)? } else { filename.to_path_buf() };
    let parent = super::absolute_root(resolved.parent().ok_or_else(|| super::fail("missing contained file parent"))?)?;
    let name = resolved.file_name().ok_or_else(|| super::fail("missing contained file name"))?;
    let mut options = OpenOptions::new(); options.read(true).follow(FollowSymlinks::No);
    let mut file = parent.open_with(name, &options)?; let before = file.metadata()?;
    if !before.is_file() || before.len() > limit || PortableMetadataExt::nlink(&before) != 1 || before.uid() != 0 && before.uid() != unsafe { geteuid() } || before.mode() & 0o022 != 0 || executable_alias && before.mode() & 0o111 == 0 { return Err(super::fail("CONTAINED_FILE_UNSAFE")); }
    let mut bytes = Vec::new(); (&mut file).take(limit + 1).read_to_end(&mut bytes)?; let after = file.metadata()?;
    if bytes.len() as u64 != before.len() || bytes.len() as u64 > limit || before.len() != after.len() || before.uid() != after.uid() || before.gid() != after.gid() || before.mode() != after.mode() || before.mtime() != after.mtime() || before.mtime_nsec() != after.mtime_nsec() || before.ctime() != after.ctime() || before.ctime_nsec() != after.ctime_nsec() || super::hash(&bytes) != expected || executable_alias && !bytes.starts_with(b"\x7fELF") { return Err(super::fail("CONTAINED_FILE_IDENTITY_CHANGED")); }
    let current = parent.open_with(name, &options)?.metadata()?;
    if PortableMetadataExt::dev(&current) != PortableMetadataExt::dev(&before) || PortableMetadataExt::ino(&current) != PortableMetadataExt::ino(&before) || executable_alias && std::fs::canonicalize(filename)? != resolved { return Err(super::fail("CONTAINED_FILE_IDENTITY_CHANGED")); }
    Ok(file)
}

pub fn run(args: Vec<OsString>) -> io::Result<u8> {
    let mut values = BTreeMap::new(); let mut input = args.into_iter();
    while let Some(option) = input.next() {
        let value = input.next().ok_or_else(|| super::fail("missing contained-setup option"))?;
        let option = option.into_string().map_err(|_| super::fail("invalid contained-setup option"))?;
        if !["--executable", "--executable-sha256", "--arguments-json", "--staging"].contains(&option.as_str()) || values.insert(option, value).is_some() { return Err(super::fail("unknown or repeated contained-setup option")); }
    }
    if values.len() != 4 { return Err(super::fail("contained-setup needs every command identity")); }
    let get = |name: &str| -> io::Result<&OsString> { values.get(name).ok_or_else(|| super::fail("missing contained-setup identity")) };
    let executable = PathBuf::from(get("--executable")?); let staging = PathBuf::from(get("--staging")?);
    let expected = get("--executable-sha256")?.to_str().ok_or_else(|| super::fail("invalid executable hash"))?;
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) { return Err(super::fail("invalid executable hash")); }
    let pinned = pin_file(&executable, expected, 256 * 1024 * 1024, true)?;
    super::private_directory(&super::absolute_root(&staging)?, false)?;
    let json = get("--arguments-json")?.to_str().ok_or_else(|| super::fail("invalid setup arguments"))?;
    if json.len() > 65536 { return Err(super::fail("setup arguments exceed byte budget")); }
    let args: Vec<String> = serde_json::from_str(json).map_err(|_| super::fail("invalid setup argument array"))?;
    if args.len() > 128 || args.iter().any(|argument| argument.contains('\0')) { return Err(super::fail("invalid setup arguments")); }
    execute(executable, staging, pinned, None, args, true)
}

/// Fixed worker entry point. POSIX preserves the public request-on-stdin,
/// snapshot-on-fd3 framing while the supervisor owns every descendant.
pub fn worker(args: Vec<OsString>) -> io::Result<u8> {
    let mut values = BTreeMap::new(); let mut input = args.into_iter();
    while let Some(option) = input.next() {
        let value = input.next().ok_or_else(|| super::fail("missing contained-run option"))?;
        let option = option.into_string().map_err(|_| super::fail("invalid contained-run option"))?;
        if !["--executable", "--executable-sha256", "--bootstrap", "--bootstrap-sha256", "--worker", "--upstream", "--context", "--snapshot-sha256", "--staging"].contains(&option.as_str()) || values.insert(option, value).is_some() { return Err(super::fail("unknown or repeated contained-run option")); }
    }
    if values.len() != 9 { return Err(super::fail("contained-run needs every fixed-worker identity")); }
    let get = |name: &str| -> io::Result<&OsString> { values.get(name).ok_or_else(|| super::fail("missing contained-run identity")) };
    let executable = PathBuf::from(get("--executable")?); let bootstrap = PathBuf::from(get("--bootstrap")?); let staging = PathBuf::from(get("--staging")?);
    let pinned = pin_file(&executable, get("--executable-sha256")?.to_str().ok_or_else(|| super::fail("invalid worker hash"))?, 256 * 1024 * 1024, true)?;
    let pinned_bootstrap = pin_file(&bootstrap, get("--bootstrap-sha256")?.to_str().ok_or_else(|| super::fail("invalid worker hash"))?, 1024 * 1024, false)?;
    for name in ["--worker", "--upstream"] { super::absolute_root(Path::new(get(name)?))?; }
    super::private_directory(&super::absolute_root(&staging)?, false)?;
    let mut arguments = vec!["-I".to_owned(), "-B".to_owned(), format!("/proc/self/fd/{}", pinned_bootstrap.as_raw_fd())];
    for name in ["--worker", "--upstream", "--context", "--snapshot-sha256", "--staging"] { arguments.push(get(name)?.to_str().ok_or_else(|| super::fail("worker identity must be Unicode"))?.to_owned()); }
    execute(executable, staging, pinned, Some(pinned_bootstrap), arguments, false)
}

fn execute(executable: PathBuf, staging: PathBuf, pinned: cap_std::fs::File, bootstrap: Option<cap_std::fs::File>, args: Vec<String>, setup: bool) -> io::Result<u8> {
    if unsafe { prctl(36, 1i32, 0i32, 0i32, 0i32) } != 0 { return Err(io::Error::last_os_error()); }
    for number in [2, 15] { if unsafe { signal(number, cancel as *const () as usize) } == usize::MAX { return Err(io::Error::last_os_error()); } }
    // The coordinator holds this pipe open. Its crash or explicit EOF revokes
    // setup even when no signal can be delivered to this supervisor.
    if setup { std::thread::spawn(|| { let mut byte = [0u8; 1]; let _ = io::stdin().read(&mut byte); CANCELLED.store(true, Ordering::SeqCst); }); }
    let coordinator = unsafe { getppid() };
    if unsafe { prctl(1, 15i32, 0i32, 0i32, 0i32) } != 0 || unsafe { getppid() } != coordinator { return Err(super::fail("coordinator changed during containment")); }
    let mut command = Command::new(format!("/proc/self/fd/{}", pinned.as_raw_fd()));
    command.arg0(&executable).args(args).current_dir(staging).stdin(if setup { Stdio::null() } else { Stdio::inherit() }).stdout(Stdio::inherit()).stderr(Stdio::inherit()).process_group(0);
    let owner = std::process::id() as i32;
    let bootstrap_fd = bootstrap.as_ref().map(AsRawFd::as_raw_fd);
    unsafe { command.pre_exec(move || { if prctl(1, 9i32, 0i32, 0i32, 0i32) != 0 || getppid() != owner { return Err(io::Error::other("setup supervisor changed")); } if !setup { for fd in [Some(3), bootstrap_fd].into_iter().flatten() { let flags = fcntl(fd, 1); if flags < 0 || fcntl(fd, 2, flags & !1) < 0 { return Err(io::Error::last_os_error()); } } } Ok(()) }); }
    let mut child = command.spawn()?; let group = child.id() as i32; let started = Instant::now(); let mut result = None;
    loop {
        if CANCELLED.load(Ordering::SeqCst) || started.elapsed() >= Duration::from_secs(300) { break; }
        if let Some(status) = child.try_wait()? { result = Some(status); break; }
        std::thread::sleep(Duration::from_millis(5));
    }
    // Stop all descendants before waiting. Subreaping makes orphaned children
    // waitable here instead of leaving zombies under an unrelated container PID1.
    if unsafe { kill(-group, 9) } != 0 && io::Error::last_os_error().raw_os_error() != Some(3) { return Err(io::Error::last_os_error()); }
    if result.is_none() { result = Some(child.wait()?); }
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        // A dependency helper may deliberately start a new process group.
        // Subreaping still owns it after its parent dies; kill only these
        // unreaped child PIDs, whose identities cannot be reused before wait.
        let children = std::fs::read_to_string(format!("/proc/self/task/{}/children", std::process::id()))?;
        for value in children.split_whitespace() { let pid = value.parse::<i32>().map_err(|_| super::fail("invalid adopted setup child"))?; if pid <= 0 { return Err(super::fail("invalid adopted setup child")); } if unsafe { kill(pid, 9) } != 0 && io::Error::last_os_error().raw_os_error() != Some(3) { return Err(io::Error::last_os_error()); } }
        let waited = unsafe { waitpid(-1, std::ptr::null_mut(), 1) };
        if waited == -1 { let error = io::Error::last_os_error(); if error.raw_os_error() == Some(10) { break; } if error.raw_os_error() != Some(4) { return Err(error); } }
        if Instant::now() >= deadline { return Err(io::Error::other("CONTAINED_SETUP_REAP_TIMEOUT")); }
        if waited <= 0 { std::thread::sleep(Duration::from_millis(5)); }
    }
    if CANCELLED.load(Ordering::SeqCst) { return Ok(125); }
    if started.elapsed() >= Duration::from_secs(300) { return Ok(124); }
    Ok(result.and_then(|status| status.code()).and_then(|code| u8::try_from(code).ok()).unwrap_or(1))
}
