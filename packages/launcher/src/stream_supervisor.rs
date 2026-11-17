//! Framed, hash-bound CLI supervision. Child output never shares control frames.
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::{Duration, Instant};
use serde::Serialize;
#[cfg(unix)]
#[path = "stream_unix.rs"]
mod backend;
#[cfg(windows)]
#[path = "stream_windows.rs"]
mod backend;

const FRAME: usize = 1024 * 1024;
static SIGNALLED: AtomicBool = AtomicBool::new(false);
#[cfg(unix)]
extern "C" fn cancel_signal(_: i32) { SIGNALLED.store(true, Ordering::SeqCst); }
#[derive(Debug)]
pub(super) struct Options { pub executable: PathBuf, pub expected: String, pub arguments: Vec<String>, timeout: Duration, max_input: u64, max_stdout: u64, max_stderr: u64, control: bool }
fn options(args: Vec<OsString>) -> io::Result<Options> {
    let mut values = BTreeMap::new(); let mut input = args.into_iter();
    while let Some(key) = input.next() { let key = key.into_string().map_err(|_| super::fail("invalid stream option"))?; let value = input.next().ok_or_else(|| super::fail("missing stream option"))?.into_string().map_err(|_| super::fail("invalid stream value"))?; if !["--executable", "--executable-sha256", "--arguments-json", "--timeout-ms", "--max-input-bytes", "--max-stdout-bytes", "--max-stderr-bytes", "--control-fd"].contains(&key.as_str()) || values.insert(key, value).is_some() { return Err(super::fail("unknown or repeated stream option")); } }
    if values.len() != 7 && values.len() != 8 || values.get("--control-fd").is_some_and(|value| value != "3") { return Err(super::fail("stream supervision requires every bound")); }
    let get = |key: &str| values.get(key).ok_or_else(|| super::fail("missing stream bound"));
    let number = |key: &str, minimum: u64, maximum: u64| -> io::Result<u64> { let value = get(key)?; if value.is_empty() || value.len() > 20 || !value.bytes().all(|byte| byte.is_ascii_digit()) || value.len() > 1 && value.starts_with('0') { return Err(super::fail("invalid stream numeric bound")); } let parsed = value.parse::<u64>().map_err(|_| super::fail("invalid stream numeric bound"))?; if parsed < minimum || parsed > maximum { return Err(super::fail("stream numeric bound out of range")); } Ok(parsed) };
    let executable = PathBuf::from(get("--executable")?); let expected = get("--executable-sha256")?.clone(); let json = get("--arguments-json")?;
    if !executable.is_absolute() || expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) || json.len() > 256 * 1024 { return Err(super::fail("invalid stream executable identity")); }
    let arguments: Vec<String> = serde_json::from_str(json).map_err(|_| super::fail("invalid stream argument array"))?;
    if arguments.len() > 256 || arguments.iter().any(|value| value.contains('\0')) { return Err(super::fail("invalid stream arguments")); }
    Ok(Options { executable, expected, arguments, timeout: Duration::from_millis(number("--timeout-ms", 1, 600000)?), max_input: number("--max-input-bytes", 0, 20 * 1024 * 1024 * 1024)?, max_stdout: number("--max-stdout-bytes", 1, 64 * 1024 * 1024)?, max_stderr: number("--max-stderr-bytes", 1, 64 * 1024 * 1024)?, control: values.contains_key("--control-fd") })
}
fn reason(state: &AtomicU8, value: u8) { let _ = state.compare_exchange(0, value, Ordering::SeqCst, Ordering::SeqCst); }
fn frame(output: &Mutex<io::Stdout>, kind: u8, bytes: &[u8]) -> io::Result<()> { if bytes.len() > FRAME { return Err(super::fail("stream output frame exceeds bound")); } let mut output = output.lock().map_err(|_| super::fail("stream output lock poisoned"))?; output.write_all(&[kind])?; output.write_all(&(bytes.len() as u32).to_be_bytes())?; output.write_all(bytes)?; output.flush() }
fn watch_control(state: Arc<AtomicU8>) -> io::Result<()> {
    #[cfg(unix)]
    let mut control = {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        let duplicate = unsafe { libc::fcntl(3, libc::F_DUPFD_CLOEXEC, 4) };
        if duplicate < 0 { return Err(io::Error::last_os_error()); }
        let owned = unsafe { OwnedFd::from_raw_fd(duplicate) };
        let mut info: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(owned.as_raw_fd(), &mut info) } != 0 || ![libc::S_IFIFO, libc::S_IFSOCK].contains(&(info.st_mode & libc::S_IFMT)) { return Err(super::fail("STREAM_CONTROL_PIPE_REQUIRED")); }
        if unsafe { libc::fcntl(3, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 { return Err(io::Error::last_os_error()); }
        let mut poll = libc::pollfd { fd: owned.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        let ready = unsafe { libc::poll(&mut poll, 1, 0) };
        if ready < 0 { return Err(io::Error::last_os_error()); }
        if ready != 0 { reason(&state, 1); return Ok(()); }
        std::fs::File::from(owned)
    };
    #[cfg(windows)]
    let mut control = {
        use std::os::windows::io::BorrowedHandle;
        use windows_sys::Win32::Foundation::*;
        use windows_sys::Win32::Storage::FileSystem::{GetFileType, FILE_TYPE_PIPE};
        use windows_sys::Win32::System::Pipes::PeekNamedPipe;
        let handle = unsafe { libc::get_osfhandle(3) } as HANDLE;
        if handle.is_null() || handle == INVALID_HANDLE_VALUE || unsafe { GetFileType(handle) } != FILE_TYPE_PIPE { return Err(super::fail("STREAM_CONTROL_PIPE_REQUIRED")); }
        if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0 { return Err(io::Error::last_os_error()); }
        let owned = unsafe { BorrowedHandle::borrow_raw(handle) }.try_clone_to_owned()?;
        let mut available = 0;
        if unsafe { PeekNamedPipe(handle, std::ptr::null_mut(), 0, std::ptr::null_mut(), &mut available, std::ptr::null_mut()) } == 0 {
            let error = unsafe { GetLastError() };
            if [ERROR_BROKEN_PIPE, ERROR_PIPE_NOT_CONNECTED, ERROR_NO_DATA].contains(&error) { reason(&state, 1); return Ok(()); }
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        if available != 0 { reason(&state, 1); return Ok(()); }
        std::fs::File::from(owned)
    };
    std::thread::spawn(move || { let mut byte = [0u8; 1]; let _ = control.read(&mut byte); reason(&state, 1); }); Ok(())
}
fn transfer(mut child: Box<dyn Write + Send>, state: Arc<AtomicU8>, ended: Arc<AtomicBool>, maximum: u64) {
    let mut run = || -> io::Result<()> { let input = io::stdin(); let mut input = input.lock(); let mut finished = false; let mut total = 0u64; loop { let mut header = [0u8; 5]; if let Err(error) = input.read_exact(&mut header) { reason(&state, if error.kind() == io::ErrorKind::UnexpectedEof { 1 } else { 5 }); return Ok(()); } let length = u32::from_be_bytes(header[1..].try_into().map_err(|_| super::fail("invalid frame length"))?) as usize;
        match (header[0], length) { (1, 0..=FRAME) if !finished => { total = total.checked_add(length as u64).ok_or_else(|| super::fail("stream input exceeds bound"))?; if total > maximum { reason(&state, 4); return Ok(()); } let mut bytes = vec![0u8; length]; input.read_exact(&mut bytes)?; child.write_all(&bytes)?; }, (2, 0) if !finished => { finished = true; child.flush()?; child = Box::new(io::sink()); ended.store(true, Ordering::SeqCst); }, (3, 0) => { reason(&state, 1); return Ok(()); }, _ => { reason(&state, 5); return Ok(()); } }
    } }; if run().is_err() { reason(&state, 5); }
}
fn drain(mut input: Box<dyn Read + Send>, output: Arc<Mutex<io::Stdout>>, state: Arc<AtomicU8>, kind: u8, maximum: u64) -> std::thread::JoinHandle<io::Result<()>> { std::thread::spawn(move || { let mut total = 0u64; let mut bytes = [0u8; 32768]; loop { let count = input.read(&mut bytes)?; if count == 0 { return Ok(()); } total = total.checked_add(count as u64).ok_or_else(|| super::fail("stream output exceeds bound"))?; if total > maximum { reason(&state, 3); continue; } if let Err(error) = frame(&output, kind, &bytes[..count]) { reason(&state, 1); return Err(error); } } }) }
#[derive(Serialize)]
struct ResultFrame { schema_version: u8, exit_code: Option<i64>, #[serde(skip_serializing_if = "Option::is_none")] signal: Option<i32>, timed_out: bool, cancelled: bool, cleanup_verified: bool, executable_sha256: String, #[serde(skip_serializing_if = "Option::is_none")] error: Option<&'static str> }
pub fn run(args: Vec<OsString>) -> io::Result<()> {
    let options = options(args)?; let state = Arc::new(AtomicU8::new(0)); let ended = Arc::new(AtomicBool::new(false)); let output = Arc::new(Mutex::new(io::stdout()));
    #[cfg(unix)]
    for signal in [libc::SIGINT, libc::SIGTERM] { if unsafe { libc::signal(signal, cancel_signal as *const () as usize) } == libc::SIG_ERR { return Err(io::Error::last_os_error()); } }
    if options.control { watch_control(state.clone())?; }
    if state.load(Ordering::SeqCst) != 0 { return frame(&output, 3, &serde_json::to_vec(&ResultFrame { schema_version: 1, exit_code: None, signal: None, timed_out: false, cancelled: true, cleanup_verified: true, executable_sha256: options.expected, error: None }).map_err(|_| super::fail("stream result serialization failed"))?); }
    let mut child = backend::spawn(&options)?; let pipes = child.pipes()?;
    { let state = state.clone(); let ended = ended.clone(); let maximum = options.max_input; std::thread::spawn(move || transfer(pipes.0, state, ended, maximum)); }
    let stdout = drain(pipes.1, output.clone(), state.clone(), 1, options.max_stdout); let stderr = drain(pipes.2, output.clone(), state.clone(), 2, options.max_stderr); let started = Instant::now();
    loop { if SIGNALLED.load(Ordering::SeqCst) { reason(&state, 1); } if started.elapsed() >= options.timeout { reason(&state, 2); } if state.load(Ordering::SeqCst) != 0 || child.exited()? { break; } std::thread::sleep(Duration::from_millis(5)); }
    // The backend still holds the unreaped group leader or the Job handle.
    // No process/group identifier can be reused before this cleanup transition.
    let (exit_code, signal) = child.finish()?; let deadline = Instant::now() + Duration::from_secs(3);
    while !stdout.is_finished() || !stderr.is_finished() { if Instant::now() >= deadline { return Err(io::Error::other("STREAM_STDIO_CLEANUP_UNVERIFIED")); } std::thread::sleep(Duration::from_millis(5)); }
    stdout.join().map_err(|_| super::fail("stream stdout reader failed"))??; stderr.join().map_err(|_| super::fail("stream stderr reader failed"))??;
    let code = state.load(Ordering::SeqCst); let result = ResultFrame { schema_version: 1, exit_code, signal, timed_out: code == 2, cancelled: code == 1, cleanup_verified: true, executable_sha256: options.expected, error: match code { 3 => Some("output_limit"), 4 => Some("input_limit"), 5 => Some("input_protocol"), _ => None } };
    frame(&output, 3, &serde_json::to_vec(&result).map_err(|_| super::fail("stream result serialization failed"))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn arguments() -> Vec<OsString> { ["--executable", if cfg!(windows) { "C:\\trusted\\engine.exe" } else { "/trusted/engine" }, "--executable-sha256", &"a".repeat(64), "--arguments-json", "[\"safe\",\"two words\"]", "--timeout-ms", "600000", "--max-input-bytes", "21474836480", "--max-stdout-bytes", "67108864", "--max-stderr-bytes", "1"].iter().map(OsString::from).collect() }
    #[test]
    fn requires_exact_identity_arguments_and_bounded_numeric_controls() {
        let valid = options(arguments()).unwrap(); assert_eq!(valid.timeout, Duration::from_millis(600000)); assert_eq!(valid.max_input, 21474836480); assert_eq!(valid.max_stdout, 67108864); assert_eq!(valid.max_stderr, 1); assert_eq!(valid.arguments, ["safe", "two words"]); assert!(!valid.control);
        for (key, values) in [("--timeout-ms", vec!["0", "600001", "-1", "+1", "01", "x", "18446744073709551616"]), ("--max-input-bytes", vec!["21474836481", "-1"]), ("--max-stdout-bytes", vec!["0", "67108865"]), ("--max-stderr-bytes", vec!["0", "67108865"]), ("--executable-sha256", vec!["a", "SHA256:wrong"]), ("--executable", vec!["relative"]), ("--arguments-json", vec!["{}", "[1]", "[\"\\u0000\"]"]) ] { for value in values { let mut args = arguments(); let index = args.iter().position(|item| item == key).unwrap(); args[index + 1] = value.into(); assert!(options(args).is_err(), "{key}={value}"); } }
        let mut controlled = arguments(); controlled.extend(["--control-fd".into(), "3".into()]); assert!(options(controlled.clone()).unwrap().control); *controlled.last_mut().unwrap() = "4".into(); assert!(options(controlled).is_err());
        for value in ["0", "1"] { let mut args = arguments(); let index = args.iter().position(|item| item == "--max-input-bytes").unwrap(); args[index + 1] = value.into(); assert_eq!(options(args).unwrap().max_input, value.parse::<u64>().unwrap()); }
        let mut missing = arguments(); missing.pop(); assert!(options(missing).is_err()); let mut repeated = arguments(); repeated.extend(["--timeout-ms".into(), "1".into()]); assert!(options(repeated).is_err());
    }
    #[test]
    fn failure_reason_is_first_outcome_and_child_bytes_cannot_be_terminal_frames() {
        let value = AtomicU8::new(0); reason(&value, 3); reason(&value, 1); assert_eq!(value.load(Ordering::SeqCst), 3);
        let result = ResultFrame { schema_version: 1, exit_code: Some(4294967295), signal: None, timed_out: false, cancelled: false, cleanup_verified: true, executable_sha256: "a".repeat(64), error: None }; let parsed: serde_json::Value = serde_json::to_value(result).unwrap(); assert_eq!(parsed["exit_code"], 4294967295u64); assert!(parsed.get("signal").is_none()); assert!(parsed.get("error").is_none());
    }
}
