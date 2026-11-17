#[cfg(target_os = "macos")]
use std::ffi::{CString, OsString};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
#[cfg(target_os = "macos")]
use std::os::fd::FromRawFd;
#[cfg(target_os = "macos")]
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::ExitStatusExt;
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::process::Child;
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::OpenOptions;
use super::Options;

type Pipes = (Box<dyn Write + Send>, Box<dyn Read + Send>, Box<dyn Read + Send>);
pub(super) struct Process { pid: i32, child: Option<Child>, handles: Option<Pipes>, held: bool, _pinned: File }
fn pin(options: &Options) -> io::Result<File> {
    let resolved = std::fs::canonicalize(&options.executable)?; let parent = super::super::absolute_root(resolved.parent().ok_or_else(|| super::super::fail("missing stream executable parent"))?)?;
    let name = resolved.file_name().ok_or_else(|| super::super::fail("missing stream executable name"))?; let mut open = OpenOptions::new(); open.read(true).follow(FollowSymlinks::No); let mut file = parent.open_with(name, &open)?.into_std(); let before = file.metadata()?;
    if !before.is_file() || before.nlink() != 1 || before.len() > 512 * 1024 * 1024 || before.mode() & 0o022 != 0 || before.mode() & 0o111 == 0 || before.uid() != 0 && before.uid() != unsafe { libc::geteuid() } { return Err(super::super::fail("STREAM_EXECUTABLE_UNSAFE")); }
    let mut bytes = Vec::new(); (&mut file).take(512 * 1024 * 1024 + 1).read_to_end(&mut bytes)?; let after = file.metadata()?;
    if bytes.len() as u64 != before.len() || super::super::hash(&bytes) != options.expected || before.dev() != after.dev() || before.ino() != after.ino() || before.len() != after.len() || before.mode() != after.mode() || before.mtime() != after.mtime() || before.mtime_nsec() != after.mtime_nsec() || before.ctime() != after.ctime() || before.ctime_nsec() != after.ctime_nsec() || std::fs::canonicalize(&options.executable)? != resolved { return Err(super::super::fail("STREAM_EXECUTABLE_IDENTITY_CHANGED")); }
    #[cfg(target_os = "linux")]
    if !bytes.starts_with(b"\x7fELF") { return Err(super::super::fail("stream executable must be native ELF")); }
    #[cfg(target_os = "macos")]
    if ![b"\xcf\xfa\xed\xfe".as_slice(), b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"].iter().any(|magic| bytes.starts_with(magic)) { return Err(super::super::fail("stream executable must be native Mach-O")); }
    file.seek(SeekFrom::Start(0))?; Ok(file)
}
pub(super) fn spawn(options: &Options) -> io::Result<Process> {
    let pinned = pin(options)?;
    if unsafe { libc::signal(libc::SIGCHLD, libc::SIG_DFL) } == libc::SIG_ERR { return Err(io::Error::last_os_error()); }
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 { return Err(io::Error::last_os_error()); }
        let owner = std::process::id() as i32;
        let mut command = Command::new(format!("/proc/self/fd/{}", pinned.as_raw_fd())); command.arg0(&options.executable).args(&options.arguments).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).process_group(0);
        unsafe { command.pre_exec(move || { if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 || libc::getppid() != owner { return Err(io::Error::other("stream supervisor changed")); } Ok(()) }); }
        let mut child = command.spawn()?; let pid = child.id() as i32; let handles: Pipes = (Box::new(child.stdin.take().ok_or_else(|| super::super::fail("missing stream stdin"))?), Box::new(child.stdout.take().ok_or_else(|| super::super::fail("missing stream stdout"))?), Box::new(child.stderr.take().ok_or_else(|| super::super::fail("missing stream stderr"))?));
        Ok(Process { pid, child: Some(child), handles: Some(handles), held: true, _pinned: pinned })
    }
    #[cfg(target_os = "macos")]
    { suspended(options, pinned) }
}
impl Process {
    pub(super) fn pipes(&mut self) -> io::Result<Pipes> { self.handles.take().ok_or_else(|| super::super::fail("stream pipes already transferred")) }
    pub(super) fn exited(&mut self) -> io::Result<bool> { let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() }; loop { let result = unsafe { libc::waitid(libc::P_PID, self.pid as libc::id_t, &mut info, libc::WEXITED | libc::WNOWAIT | libc::WNOHANG) }; if result == 0 { return Ok(unsafe { info.si_pid() } == self.pid); } let error = io::Error::last_os_error(); if error.raw_os_error() == Some(libc::EINTR) { continue; } if error.raw_os_error() == Some(libc::ECHILD) { self.held = false; } return Err(error); } }
    pub(super) fn finish(&mut self) -> io::Result<(Option<i64>, Option<i32>)> {
        if !self.held { return Err(super::super::fail("STREAM_LEADER_IDENTITY_UNVERIFIED")); }
        if unsafe { libc::kill(-self.pid, libc::SIGKILL) } != 0 { let error = io::Error::last_os_error(); if error.raw_os_error() != Some(libc::ESRCH) {
            // Darwin can return EPERM for an entirely zombie group. Its
            // leader must be observed exited with WNOWAIT; the complete group
            // inventory is checked for quiescence below before any reap.
            #[cfg(target_os = "macos")]
            let empty = error.raw_os_error() == Some(libc::EPERM) && self.exited()?;
            #[cfg(not(target_os = "macos"))]
            let empty = false;
            if !empty { return Err(io::Error::other(format!("STREAM_GROUP_KILL: {error}"))); }
        } }
        #[cfg(target_os = "macos")]
        { let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3); loop {
            if self.exited()? && group_quiescent(self.pid)? { break; }
            if std::time::Instant::now() >= deadline { return Err(io::Error::other("STREAM_GROUP_QUIESCENCE_UNVERIFIED")); }
            // Keep the group leader unreaped during every repeated signal and
            // inventory: the private PGID cannot be reassigned to another job.
            if unsafe { libc::kill(-self.pid, libc::SIGKILL) } != 0 && ![libc::ESRCH, libc::EPERM].contains(&io::Error::last_os_error().raw_os_error().unwrap_or(0)) { return Err(io::Error::last_os_error()); }
            std::thread::sleep(std::time::Duration::from_millis(5));
        } }
        let status = if let Some(child) = self.child.as_mut() { child.wait()? } else { let mut status = 0; loop { if unsafe { libc::waitpid(self.pid, &mut status, 0) } == self.pid { break; } if io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) { return Err(io::Error::last_os_error()); } } std::process::ExitStatus::from_raw(status) };
        self.held = false;
        #[cfg(target_os = "linux")]
        { let deadline = Instant::now() + Duration::from_secs(3); loop { let children = std::fs::read_to_string(format!("/proc/self/task/{}/children", std::process::id()))?; for value in children.split_whitespace() { let pid = value.parse::<i32>().map_err(|_| super::super::fail("invalid adopted stream child"))?; if pid <= 0 { return Err(super::super::fail("invalid adopted stream child")); } if unsafe { libc::kill(pid, libc::SIGKILL) } != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) { return Err(io::Error::last_os_error()); } } let mut waited = false; loop { let result = unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) }; if result > 0 { waited = true; continue; } if result < 0 { let error = io::Error::last_os_error(); if error.raw_os_error() == Some(libc::ECHILD) { return Ok((status.code().map(i64::from), status.signal())); } if error.raw_os_error() != Some(libc::EINTR) { return Err(error); } } break; } if Instant::now() >= deadline { return Err(io::Error::other("STREAM_DESCENDANT_REAP_UNVERIFIED")); } if !waited { std::thread::sleep(Duration::from_millis(5)); } } }
        #[cfg(target_os = "macos")]
        Ok((status.code().map(i64::from), status.signal()))
    }
}
impl Drop for Process { fn drop(&mut self) { if self.held { let _ = self.finish(); } } }

#[cfg(target_os = "macos")]
fn group_members(leader: i32) -> io::Result<Vec<i32>> {
    let mut members = [0i32; 16384]; unsafe { *libc::__error() = 0; }
    let bytes = unsafe { libc::proc_listpids(2, leader as u32, members.as_mut_ptr().cast(), std::mem::size_of_val(&members) as i32) };
    if bytes < 0 || bytes as usize >= std::mem::size_of_val(&members) || bytes % 4 != 0 || bytes == 0 && io::Error::last_os_error().raw_os_error() != Some(0) { return Err(io::Error::other("STREAM_GROUP_INVENTORY_UNVERIFIED")); }
    Ok(members[..bytes as usize / 4].to_vec())
}
#[cfg(target_os = "macos")]
fn group_quiescent(leader: i32) -> io::Result<bool> {
    for pid in group_members(leader)? {
        if pid == leader { continue; }
        if pid <= 0 { return Err(super::super::fail("invalid stream group member")); }
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let bytes = unsafe { libc::proc_pidinfo(pid, 3, 0, (&mut info as *mut libc::proc_bsdinfo).cast(), std::mem::size_of::<libc::proc_bsdinfo>() as i32) };
        // A vanished process is re-enumerated on the next round. No numeric
        // PID is signalled here, including if its identity has already exited.
        if bytes != std::mem::size_of::<libc::proc_bsdinfo>() as i32 || info.pbi_pid != pid as u32 || info.pbi_pgid != leader as u32 || info.pbi_status != 5 { return Ok(false); }
    }
    Ok(true)
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct Region { protection: u32, maximum: u32, inheritance: u32, flags: u32, offset: u64, details: [u32; 14], address: u64, size: u64 }
#[cfg(target_os = "macos")]
#[repr(C)]
struct RegionPath { region: Region, vnode: libc::vnode_info_path }
#[cfg(target_os = "macos")]
fn suspended(options: &Options, pinned: File) -> io::Result<Process> {
    let pipes = || -> io::Result<(File, File)> { let mut pair = [-1i32; 2]; if unsafe { libc::pipe(pair.as_mut_ptr()) } != 0 { return Err(io::Error::last_os_error()); } let read = unsafe { File::from_raw_fd(pair[0]) }; let write = unsafe { File::from_raw_fd(pair[1]) }; for file in [&read, &write] { if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } != 0 { return Err(io::Error::last_os_error()); } } Ok((read, write)) };
    let (input, parent_input) = pipes()?; let (parent_output, output) = pipes()?; let (parent_error, error) = pipes()?;
    let mut actions: libc::posix_spawn_file_actions_t = unsafe { std::mem::zeroed() }; let mut attributes: libc::posix_spawnattr_t = unsafe { std::mem::zeroed() };
    let checked = |code| if code == 0 { Ok(()) } else { Err(io::Error::from_raw_os_error(code)) };
    checked(unsafe { libc::posix_spawn_file_actions_init(&mut actions) })?;
    struct Actions(*mut libc::posix_spawn_file_actions_t); impl Drop for Actions { fn drop(&mut self) { unsafe { libc::posix_spawn_file_actions_destroy(self.0); } } } let _actions = Actions(&mut actions);
    checked(unsafe { libc::posix_spawnattr_init(&mut attributes) })?;
    struct Attributes(*mut libc::posix_spawnattr_t); impl Drop for Attributes { fn drop(&mut self) { unsafe { libc::posix_spawnattr_destroy(self.0); } } } let _attributes = Attributes(&mut attributes);
    for (file, descriptor) in [(&input, 0), (&output, 1), (&error, 2)] { checked(unsafe { libc::posix_spawn_file_actions_adddup2(&mut actions, file.as_raw_fd(), descriptor) })?; }
    checked(unsafe { libc::posix_spawnattr_setflags(&mut attributes, (libc::POSIX_SPAWN_SETPGROUP | libc::POSIX_SPAWN_START_SUSPENDED | libc::POSIX_SPAWN_CLOEXEC_DEFAULT) as i16) })?;
    checked(unsafe { libc::posix_spawnattr_setpgroup(&mut attributes, 0) })?;
    let executable = CString::new(options.executable.as_os_str().as_bytes()).map_err(|_| super::super::fail("invalid stream executable"))?;
    let arguments = std::iter::once(OsString::from(&options.executable)).chain(options.arguments.iter().map(OsString::from)).map(|value| CString::new(value.as_bytes()).map_err(|_| super::super::fail("invalid stream argument"))).collect::<io::Result<Vec<_>>>()?;
    let environment = std::env::vars_os().map(|(key, value)| { let mut combined = key; combined.push("="); combined.push(value); CString::new(combined.as_bytes()).map_err(|_| super::super::fail("invalid stream environment")) }).collect::<io::Result<Vec<_>>>()?;
    let mut argv = arguments.iter().map(|value| value.as_ptr().cast_mut()).collect::<Vec<_>>(); argv.push(std::ptr::null_mut()); let mut envp = environment.iter().map(|value| value.as_ptr().cast_mut()).collect::<Vec<_>>(); envp.push(std::ptr::null_mut()); let mut pid = 0;
    checked(unsafe { libc::posix_spawn(&mut pid, executable.as_ptr(), &actions, &attributes, argv.as_ptr(), envp.as_ptr()) })?;
    drop(input); drop(output); drop(error);
    let mut process = Process { pid, child: None, handles: Some((Box::new(parent_input), Box::new(parent_output), Box::new(parent_error))), held: true, _pinned: pinned };
    let expected = process._pinned.metadata()?; let mut address = 0u64; let mut matched = false;
    for _ in 0..4096 { let mut region: RegionPath = unsafe { std::mem::zeroed() }; let bytes = unsafe { libc::proc_pidinfo(pid, 8, address, (&mut region as *mut RegionPath).cast(), std::mem::size_of::<RegionPath>() as i32) }; if bytes != std::mem::size_of::<RegionPath>() as i32 { break; } if region.region.protection & 4 != 0 && region.vnode.vip_vi.vi_stat.vst_ino != 0 { matched = region.vnode.vip_vi.vi_stat.vst_dev as u64 == expected.dev() && region.vnode.vip_vi.vi_stat.vst_ino == expected.ino() && region.vnode.vip_vi.vi_stat.vst_size as u64 == expected.len(); break; } address = region.region.address.checked_add(region.region.size).ok_or_else(|| super::super::fail("invalid suspended stream region"))?; if address == 0 { break; } }
    process._pinned.seek(SeekFrom::Start(0))?; let mut bytes = Vec::new(); (&mut process._pinned).take(512 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if !matched || super::super::hash(&bytes) != options.expected { return Err(super::super::fail("STREAM_SUSPENDED_IMAGE_IDENTITY_CHANGED")); }
    if unsafe { libc::kill(pid, libc::SIGCONT) } != 0 { return Err(io::Error::last_os_error()); }
    // Keep the owner active before returning handles to the framed pumps.
    let _ = &mut process; Ok(process)
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    #[test]
    fn kernel_group_inventory_distinguishes_live_members_from_quiescence() {
        struct Held(Child);
        impl Drop for Held { fn drop(&mut self) { unsafe { libc::kill(-(self.0.id() as i32), libc::SIGKILL); } let _ = self.0.wait(); } }
        use std::os::unix::process::CommandExt;
        let mut command = std::process::Command::new("/bin/sh"); command.args(["-c", "sleep 60 & wait"]).process_group(0).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()); let child = Held(command.spawn().unwrap()); let group = child.0.id() as i32; let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while group_members(group).unwrap().len() < 2 { assert!(std::time::Instant::now() < deadline); std::thread::sleep(std::time::Duration::from_millis(5)); }
        assert!(!group_quiescent(group).unwrap()); assert_eq!(unsafe { libc::kill(-group, libc::SIGKILL) }, 0);
        while !group_quiescent(group).unwrap() { assert!(std::time::Instant::now() < deadline); std::thread::sleep(std::time::Duration::from_millis(5)); }
        assert!(group_quiescent(group).unwrap());
    }
}
