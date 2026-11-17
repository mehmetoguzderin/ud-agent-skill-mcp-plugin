//! Fixed built-in Python worker execution inside an owned Windows Job Object.
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{File, OpenOptions, OpenOptionsExt};
use std::collections::BTreeMap;
use std::ffi::{c_void, OsString};
use std::io::{self, Read};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
use windows_sys::Win32::System::JobObjects::*;
use windows_sys::Win32::System::Threading::*;
use super::windows_job_policy::*;

pub(super) struct Handle(pub(super) HANDLE);
impl Drop for Handle { fn drop(&mut self) { unsafe { CloseHandle(self.0); } } }
fn error() -> io::Error { io::Error::last_os_error() }
fn wide(value: &std::ffi::OsStr) -> Vec<u16> { value.encode_wide().chain(Some(0)).collect() }
pub(super) fn pinned(path: &Path, expected: &str, limit: u64) -> io::Result<File> {
    if !path.is_absolute() || expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) { return Err(super::fail("invalid contained worker identity")); }
    let parent = super::absolute_root(path.parent().ok_or_else(|| super::fail("missing worker parent"))?)?;
    let name = path.file_name().ok_or_else(|| super::fail("missing worker filename"))?;
    let mut options = OpenOptions::new(); options.read(true).share_mode(1).follow(FollowSymlinks::No);
    let mut file = parent.open_with(name, &options)?; let before = file.metadata()?;
    if !before.is_file() || before.len() > limit { return Err(super::fail("CONTAINED_WORKER_IDENTITY_CHANGED")); }
    let mut bytes = Vec::new(); (&mut file).take(limit + 1).read_to_end(&mut bytes)?; let after = file.metadata()?;
    if bytes.len() as u64 != before.len() || before.len() != after.len() || before.modified()? != after.modified()? || super::hash(&bytes) != expected { return Err(super::fail("CONTAINED_WORKER_IDENTITY_CHANGED")); }
    Ok(file)
}
fn set_job<T>(job: HANDLE, kind: JOBOBJECTINFOCLASS, value: &T) -> io::Result<()> {
    if unsafe { SetInformationJobObject(job, kind, (value as *const T).cast(), std::mem::size_of::<T>() as u32) } == 0 { return Err(error()); }
    Ok(())
}
pub(super) fn reap(job: HANDLE) -> io::Result<()> {
    if unsafe { TerminateJobObject(job, 137) } == 0 { return Err(error()); }
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        if unsafe { QueryInformationJobObject(job, JobObjectBasicAccountingInformation, (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(), std::mem::size_of_val(&info) as u32, std::ptr::null_mut()) } == 0 { return Err(error()); }
        if info.ActiveProcesses == 0 { return Ok(()); }
        if Instant::now() >= deadline { return Err(io::Error::other("CONTAINED_WORKER_REAP_TIMEOUT")); }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn pin_venv(values: &BTreeMap<String, OsString>, launcher_override: Option<OsString>) -> io::Result<Option<(File, File)>> {
    let get = |name: &str| -> io::Result<&OsString> { values.get(name).ok_or_else(|| super::fail("missing contained venv identity")) };
    Ok(if values.keys().any(|key| key.starts_with("--venv-")) {
        let launcher = PathBuf::from(get("--venv-executable")?);
        let config = PathBuf::from(get("--venv-config")?);
        if launcher_override.as_deref() != Some(launcher.as_os_str())
            || !launcher.file_name().and_then(|name| name.to_str()).is_some_and(|name| name.eq_ignore_ascii_case("python.exe"))
            || config.file_name() != Some(std::ffi::OsStr::new("pyvenv.cfg"))
            || !(config.parent() == launcher.parent() || config.parent() == launcher.parent().and_then(Path::parent)) {
            return Err(super::fail("invalid contained venv identity"));
        }
        Some((pinned(&launcher, get("--venv-executable-sha256")?.to_str().ok_or_else(|| super::fail("invalid venv launcher hash"))?, 256 * 1024 * 1024)?,
            pinned(&config, get("--venv-config-sha256")?.to_str().ok_or_else(|| super::fail("invalid venv configuration hash"))?, 64 * 1024)?))
    } else {
        if launcher_override.is_some() { return Err(super::fail("unbound contained venv override")); }
        None
    })
}

pub fn run(args: Vec<OsString>) -> io::Result<u8> {
    let mut values = BTreeMap::new(); let mut input = args.into_iter();
    while let Some(option) = input.next() {
        let value = input.next().ok_or_else(|| super::fail("missing contained-run option"))?;
        let option = option.into_string().map_err(|_| super::fail("invalid contained-run option"))?;
        if !["--executable", "--executable-sha256", "--bootstrap", "--bootstrap-sha256", "--worker", "--upstream", "--context", "--snapshot-sha256", "--staging", "--venv-executable", "--venv-executable-sha256", "--venv-config", "--venv-config-sha256"].contains(&option.as_str()) || values.insert(option, value).is_some() { return Err(super::fail("unknown or repeated contained-run option")); }
    }
    if values.len() != 9 && values.len() != 13 { return Err(super::fail("contained-run needs every fixed-worker identity")); }
    let get = |name: &str| -> io::Result<&OsString> { values.get(name).ok_or_else(|| super::fail("missing contained-run identity")) };
    let executable = PathBuf::from(get("--executable")?); let bootstrap = PathBuf::from(get("--bootstrap")?);
    let _executable = pinned(&executable, get("--executable-sha256")?.to_str().ok_or_else(|| super::fail("invalid executable hash"))?, 256 * 1024 * 1024)?;
    let _bootstrap = pinned(&bootstrap, get("--bootstrap-sha256")?.to_str().ok_or_else(|| super::fail("invalid bootstrap hash"))?, 1024 * 1024)?;
    // Keep the override's exact launcher/config read-only through launch(),
    // while the direct base remains in this supervisor's resource-limited Job.
    let _venv = pin_venv(&values, std::env::var_os("__PYVENV_LAUNCHER__"))?;
    for option in ["--worker", "--upstream", "--staging"] { super::absolute_root(Path::new(get(option)?))?; }
    let staging = PathBuf::from(get("--staging")?);
    super::fs_windows::private_state(&super::absolute_root(&staging)?, true)?;
    let arguments = [executable.as_os_str().to_os_string(), OsString::from("-I"), OsString::from("-B"), bootstrap.into_os_string(), get("--worker")?.clone(), get("--upstream")?.clone(), get("--context")?.clone(), get("--snapshot-sha256")?.clone(), get("--staging")?.clone(), OsString::from("--framed-stdin")];
    launch(&executable, &arguments, &staging)
}

/// Coordinator-only dependency setup. The caller pins the complete executable
/// bytes and supplies fixed built-in setup arguments, never project code.
pub fn setup(args: Vec<OsString>) -> io::Result<u8> {
    let mut values = BTreeMap::new(); let mut input = args.into_iter();
    while let Some(option) = input.next() {
        let value = input.next().ok_or_else(|| super::fail("missing contained-setup option"))?;
        let option = option.into_string().map_err(|_| super::fail("invalid contained-setup option"))?;
        if !["--executable", "--executable-sha256", "--arguments-json", "--staging"].contains(&option.as_str()) || values.insert(option, value).is_some() { return Err(super::fail("unknown or repeated contained-setup option")); }
    }
    if values.len() != 4 { return Err(super::fail("contained-setup needs every command identity")); }
    let get = |name: &str| -> io::Result<&OsString> { values.get(name).ok_or_else(|| super::fail("missing contained-setup identity")) };
    let executable = PathBuf::from(get("--executable")?); let staging = PathBuf::from(get("--staging")?);
    let _executable = pinned(&executable, get("--executable-sha256")?.to_str().ok_or_else(|| super::fail("invalid executable hash"))?, 256 * 1024 * 1024)?;
    super::fs_windows::private_state(&super::absolute_root(&staging)?, false)?;
    let json = get("--arguments-json")?.to_str().ok_or_else(|| super::fail("invalid setup arguments"))?;
    if json.len() > 65536 { return Err(super::fail("setup arguments exceed byte budget")); }
    let args: Vec<String> = serde_json::from_str(json).map_err(|_| super::fail("invalid setup argument array"))?;
    if args.len() > 128 || args.iter().any(|argument| argument.contains('\0')) { return Err(super::fail("invalid setup arguments")); }
    let arguments: Vec<OsString> = std::iter::once(executable.as_os_str().to_os_string()).chain(args.into_iter().map(OsString::from)).collect();
    launch(&executable, &arguments, &staging)
}

pub(super) fn launch_process(executable: &Path, arguments: &[OsString], staging: &Path, mut handles: [HANDLE; 3]) -> io::Result<(Handle, Handle)> {
    let command = arguments.iter().map(|argument| argument.to_str().map(quote).ok_or_else(|| super::fail("contained worker argument is not Unicode"))).collect::<io::Result<Vec<_>>>()?.join(" ");
    let mut command: Vec<u16> = command.encode_utf16().chain(Some(0)).collect();
    if command.len() > 32767 { return Err(super::fail("contained worker command exceeds Windows limit")); }
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job.is_null() { return Err(error()); }
    let job = Handle(job);
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_PROCESS_TIME | JOB_OBJECT_LIMIT_JOB_TIME;
    limits.BasicLimitInformation.ActiveProcessLimit = PROCESS_LIMIT;
    limits.BasicLimitInformation.PerProcessUserTimeLimit = CPU_TIME_100NS; limits.BasicLimitInformation.PerJobUserTimeLimit = CPU_TIME_100NS;
    limits.ProcessMemoryLimit = MEMORY_BYTES; limits.JobMemoryLimit = MEMORY_BYTES;
    set_job(job.0, JobObjectExtendedLimitInformation, &limits)?;
    let mut cpu = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION::default(); cpu.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
    cpu.Anonymous.CpuRate = cpu_rate(unsafe { GetActiveProcessorCount(0xffff) });
    set_job(job.0, JobObjectCpuRateControlInformation, &cpu)?;
    for handle in handles { if handle.is_null() || handle == INVALID_HANDLE_VALUE || unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0 { return Err(error()); } }
    let mut size = 0;
    unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 2, 0, &mut size); }
    if size == 0 || size > 65536 { return Err(super::fail("invalid process attribute list")); }
    let mut storage = vec![0u64; size.div_ceil(8)]; let attributes = storage.as_mut_ptr().cast();
    if unsafe { InitializeProcThreadAttributeList(attributes, 2, 0, &mut size) } == 0 { return Err(error()); }
    struct Attributes(*mut c_void);
    impl Drop for Attributes { fn drop(&mut self) { unsafe { DeleteProcThreadAttributeList(self.0); } } }
    let _attributes = Attributes(attributes);
    if unsafe { UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize, handles.as_mut_ptr().cast(), std::mem::size_of_val(&handles), std::ptr::null_mut(), std::ptr::null()) } == 0 { return Err(error()); }
    // Atomic job assignment avoids an orphaned suspended process if this
    // launcher is cancelled between CreateProcess and a later assignment.
    let mut jobs = [job.0];
    if unsafe { UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST as usize, jobs.as_mut_ptr().cast(), std::mem::size_of_val(&jobs), std::ptr::null_mut(), std::ptr::null()) } == 0 { return Err(error()); }
    let mut startup = STARTUPINFOEXW::default(); startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32; startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = handles[0]; startup.StartupInfo.hStdOutput = handles[1]; startup.StartupInfo.hStdError = handles[2]; startup.lpAttributeList = attributes;
    let mut process = PROCESS_INFORMATION::default();
    if unsafe { CreateProcessW(wide(executable.as_os_str()).as_ptr(), command.as_mut_ptr(), std::ptr::null(), std::ptr::null(), 1, CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, std::ptr::null(), wide(staging.as_os_str()).as_ptr(), &startup.StartupInfo, &mut process) } == 0 { return Err(error()); }
    let child = Handle(process.hProcess); let thread = Handle(process.hThread);
    let mut assigned = 0;
    if unsafe { IsProcessInJob(child.0, job.0, &mut assigned) } == 0 || assigned == 0 {
        let failure = error(); unsafe { TerminateProcess(child.0, 126); WaitForSingleObject(child.0, 30000); } return Err(failure);
    }
    if unsafe { ResumeThread(thread.0) } == u32::MAX { let failure = error(); reap(job.0)?; return Err(failure); }
    Ok((job, child))
}

fn launch(executable: &Path, arguments: &[OsString], staging: &Path) -> io::Result<u8> {
    let handles = unsafe { [GetStdHandle(STD_INPUT_HANDLE), GetStdHandle(STD_OUTPUT_HANDLE), GetStdHandle(STD_ERROR_HANDLE)] };
    let (job, child) = launch_process(executable, arguments, staging, handles)?;
    let waited = unsafe { WaitForSingleObject(child.0, WALL_TIME_MS) };
    let mut exit = 1;
    if waited == WAIT_TIMEOUT { reap(job.0)?; return Ok(124); }
    if waited != WAIT_OBJECT_0 { let failure = error(); reap(job.0)?; return Err(failure); }
    if unsafe { GetExitCodeProcess(child.0, &mut exit) } == 0 { let failure = error(); reap(job.0)?; return Err(failure); }
    reap(job.0)?;
    Ok(u8::try_from(exit).unwrap_or(1))
}

#[cfg(test)]
mod venv_tests {
    use super::*;
    #[test]
    fn venv_override_requires_complete_bound_group_and_holds_configuration_immutable() {
        let root = std::env::temp_dir().join(format!("ud-venv-pins-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir(&root).unwrap();
        let launcher = root.join("python.exe"); let config = root.join("pyvenv.cfg");
        std::fs::write(&launcher, b"launcher").unwrap(); std::fs::write(&config, b"home = C:\\verified-base\n").unwrap();
        let mut values = BTreeMap::new();
        assert!(pin_venv(&values, None).unwrap().is_none());
        assert!(pin_venv(&values, Some(launcher.as_os_str().to_os_string())).is_err());
        for (key, value) in [("--venv-executable", launcher.as_os_str().to_os_string()), ("--venv-executable-sha256", super::super::hash(b"launcher").into()), ("--venv-config", config.as_os_str().to_os_string()), ("--venv-config-sha256", super::super::hash(b"home = C:\\verified-base\n").into())] { values.insert(key.to_string(), value); }
        assert!(pin_venv(&values, None).is_err());
        assert!(pin_venv(&values, Some(root.join("foreign.exe").into_os_string())).is_err());
        let digest = values.remove("--venv-config-sha256").unwrap();
        assert!(pin_venv(&values, Some(launcher.as_os_str().to_os_string())).is_err());
        values.insert("--venv-config-sha256".into(), "a".repeat(64).into());
        assert!(pin_venv(&values, Some(launcher.as_os_str().to_os_string())).is_err());
        values.insert("--venv-config-sha256".into(), digest);
        let held = pin_venv(&values, Some(launcher.as_os_str().to_os_string())).unwrap().unwrap();
        assert!(std::fs::write(&launcher, b"changed").is_err()); assert!(std::fs::write(&config, b"changed").is_err());
        assert_eq!(std::fs::read(&launcher).unwrap(), b"launcher"); assert_eq!(std::fs::read(&config).unwrap(), b"home = C:\\verified-base\n");
        drop(held); std::fs::remove_dir_all(root).unwrap();
    }
}
