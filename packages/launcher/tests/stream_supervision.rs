use std::fs;
use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use sha2::{Digest, Sha256};
fn hash(bytes: &[u8]) -> String { Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect() }
fn send(output: &mut impl Write, kind: u8, bytes: &[u8]) -> std::io::Result<()> { output.write_all(&[kind])?; output.write_all(&(bytes.len() as u32).to_be_bytes())?; output.write_all(bytes)?; output.flush() }
fn guardian_command(mode: &str, timeout: u64, input: u64, stdout: u64, expected: Option<&str>) -> Command {
    let executable = std::env::current_exe().unwrap(); let digest = hash(&fs::read(&executable).unwrap());
    let mut command = Command::new(env!("CARGO_BIN_EXE_ud-agent-guard")); command.arg("stream-supervise").arg("--executable").arg(&executable).args(["--executable-sha256", expected.unwrap_or(&digest), "--arguments-json", "[\"process_fixture\",\"--exact\",\"--nocapture\"]", "--timeout-ms", &timeout.to_string(), "--max-input-bytes", &input.to_string(), "--max-stdout-bytes", &stdout.to_string(), "--max-stderr-bytes", "1048576"]).env("UD_STREAM_CHILD_MODE", mode).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()); command
}
fn guardian(mode: &str, timeout: u64, input: u64, stdout: u64, expected: Option<&str>) -> Child { guardian_command(mode, timeout, input, stdout, expected).spawn().unwrap()
}
fn frames(bytes: &[u8]) -> (Vec<u8>, Vec<u8>, serde_json::Value) {
    let mut cursor = 0; let mut stdout = Vec::new(); let mut stderr = Vec::new(); let mut result = None;
    while cursor < bytes.len() { assert!(cursor + 5 <= bytes.len()); let kind = bytes[cursor]; let length = u32::from_be_bytes(bytes[cursor+1..cursor+5].try_into().unwrap()) as usize; cursor += 5; assert!(length <= 1024 * 1024 && cursor + length <= bytes.len()); let payload = &bytes[cursor..cursor+length]; cursor += length;
        assert!(result.is_none(), "no frame may follow the terminal result"); match kind { 1 => stdout.extend_from_slice(payload), 2 => stderr.extend_from_slice(payload), 3 => { let parsed = serde_json::from_slice::<serde_json::Value>(payload); assert!(parsed.is_ok(), "guardian terminal frame must contain valid JSON: {parsed:?}"); result = Some(parsed.unwrap()); }, _ => panic!("unknown guardian frame") }
    }
    assert!(result.is_some(), "guardian must return its actual cleanup result"); let result = result.unwrap(); assert_eq!(result["schema_version"], 1); assert_eq!(result["cleanup_verified"], true); assert_eq!(result["executable_sha256"], hash(&fs::read(std::env::current_exe().unwrap()).unwrap())); (stdout, stderr, result)
}
fn complete(child: Child, mut control: std::process::ChildStdin) -> (Vec<u8>, Vec<u8>, serde_json::Value) { let transfer = send(&mut control, 2, &[]); let output = child.wait_with_output().unwrap(); drop(control); assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr)); transfer.unwrap(); assert!(output.stderr.is_empty()); frames(&output.stdout) }

#[test]
fn process_fixture() {
    let Ok(mode) = std::env::var("UD_STREAM_CHILD_MODE") else { return; };
    if mode == "silent-hold" { use std::io::Write; let file = std::env::var_os("UD_STREAM_MARKER").unwrap(); let mut output = std::fs::OpenOptions::new().create(true).append(true).open(file).unwrap(); loop { output.write_all(b"tick\n").unwrap(); output.flush().unwrap(); std::thread::sleep(Duration::from_millis(20)); } }
    if mode == "silent-grandchild" { let marker = std::path::PathBuf::from(std::env::var_os("UD_STREAM_MARKER").unwrap()); let child = Command::new(std::env::current_exe().unwrap()).args(["process_fixture", "--exact", "--nocapture"]).env("UD_STREAM_CHILD_MODE", "silent-hold").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap(); let end = Instant::now() + Duration::from_secs(3); while !marker.exists() { assert!(Instant::now() < end); std::thread::sleep(Duration::from_millis(5)); } println!("owned-silent-grandchild:{}", child.id()); std::io::stdout().flush().unwrap(); std::process::exit(0); }
    if mode == "echo" { let mut bytes = Vec::new(); std::io::stdin().read_to_end(&mut bytes).unwrap(); std::io::stdout().write_all(&bytes).unwrap(); std::io::stderr().write_all(b"child stderr\0\xff").unwrap(); std::process::exit(7); }
    if mode == "output" { std::io::stdout().write_all(&[b'x'; 8192]).unwrap(); std::io::stdout().flush().unwrap(); }
    if mode == "grandchild" || mode == "cancel-tree" || mode == "detached-tree" { let mut command = Command::new(std::env::current_exe().unwrap()); command.args(["process_fixture", "--exact", "--nocapture"]).env("UD_STREAM_CHILD_MODE", if mode == "detached-tree" { "detached" } else { "hold" }).stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit()); let child = command.spawn().unwrap(); println!("owned-grandchild:{}", child.id()); std::io::stdout().flush().unwrap(); if mode == "grandchild" { std::process::exit(0); } }
    #[cfg(target_os = "linux")]
    if mode == "detached" { assert!(unsafe { libc::setsid() } > 0); }
    println!("child-started:{}", std::process::id()); std::io::stdout().flush().unwrap(); std::thread::sleep(Duration::from_secs(60)); std::process::exit(0);
}
#[test]
fn preserves_exact_input_output_stderr_and_nonzero_engine_status_without_result_spoofing() {
    let mut child = guardian("echo", 5000, 1048576, 1048576, None); let mut control = child.stdin.take().unwrap(); let payload = b"\0\xff\x03\0\0\0\x02{}raw\r\n"; let transfer = send(&mut control, 1, payload);
    let (stdout, stderr, result) = complete(child, control); transfer.unwrap(); assert!(stdout.ends_with(payload)); assert_eq!(stderr, b"child stderr\0\xff"); assert_eq!(result["exit_code"], 7); assert_eq!(result["timed_out"], false); assert_eq!(result["cancelled"], false); assert!(result.get("signal").is_none()); assert!(result.get("error").is_none());
}
#[test]
fn reaps_grandchildren_holding_output_after_the_group_leader_exits() {
    let started = Instant::now(); let mut child = guardian("grandchild", 5000, 1, 1048576, None); let control = child.stdin.take().unwrap(); let (stdout, _, result) = complete(child, control); assert!(started.elapsed() < Duration::from_secs(4)); assert!(String::from_utf8_lossy(&stdout).contains("owned-grandchild:")); assert_eq!(result["exit_code"], 0); assert_eq!(result["cleanup_verified"], true);
}
#[test]
fn cancellation_and_parent_eof_kill_the_exact_live_tree_and_drain_stdio() {
    for explicit in [true, false] {
        let mut child = guardian("cancel-tree", 5000, 1, 1048576, None);
        let mut control = child.stdin.take().unwrap();
        let initial_transfer = send(&mut control, 2, &[]);
        let mut output = child.stdout.take().unwrap();
        let (ready, receiver) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut all = Vec::new(); let mut bytes = [0u8; 4096]; let mut seen = false;
            loop {
                let count = output.read(&mut bytes)?;
                if count == 0 { return Ok::<_, std::io::Error>(all); }
                all.extend_from_slice(&bytes[..count]);
                if !seen && all.windows(b"child-started:".len()).any(|part| part == b"child-started:") {
                    let _ = ready.send(()); seen = true;
                }
            }
        });
        let readiness = receiver.recv_timeout(Duration::from_secs(3));
        let started = Instant::now();
        // Always revoke the live control lease and reap before asserting readiness.
        // An early valid-fixture rejection must be an explicit status assertion,
        // rather than a channel-disconnection panic which hides the actual result.
        let cancellation = if explicit && readiness.is_ok() {
            control.write_all(&[3, 0, 0, 0, 0]).and_then(|_| control.flush())
        } else { Ok(()) };
        drop(control);
        let waited = child.wait_with_output().unwrap();
        let bytes = reader.join().unwrap().unwrap();
        assert!(waited.status.success(), "valid cancellation fixture was rejected: {}", String::from_utf8_lossy(&waited.stderr));
        assert!(readiness.is_ok(), "guardian did not start the requested child: {readiness:?}");
        initial_transfer.unwrap(); cancellation.unwrap();
        let (_, _, result) = frames(&bytes);
        assert!(started.elapsed() < Duration::from_secs(4));
        assert_eq!(result["cancelled"], true); assert_eq!(result["timed_out"], false);
    }
}

#[test]
fn enforces_timeout_input_output_and_protocol_bounds_as_failures_with_cleanup() {
    let mut child = guardian("hold", 150, 1, 1048576, None); let control = child.stdin.take().unwrap(); let (_, _, result) = complete(child, control); assert_eq!(result["timed_out"], true);
    let mut child = guardian("output", 5000, 1, 128, None); let control = child.stdin.take().unwrap(); let (_, _, result) = complete(child, control); assert_eq!(result["error"], "output_limit");
    let mut child = guardian("hold", 5000, 1, 1048576, None); let mut control = child.stdin.take().unwrap(); let transfer = send(&mut control, 1, b"too much"); let output = child.wait_with_output().unwrap(); drop(control); assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr)); transfer.unwrap(); assert_eq!(frames(&output.stdout).2["error"], "input_limit");
    let mut child = guardian("hold", 5000, 1, 1048576, None); let mut control = child.stdin.take().unwrap(); let transfer = send(&mut control, 2, &[]).and_then(|_| send(&mut control, 2, &[])); let output = child.wait_with_output().unwrap(); drop(control); assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr)); transfer.unwrap(); assert_eq!(frames(&output.stdout).2["error"], "input_protocol");
}
#[test]
fn rejects_wrong_executable_identity_and_invalid_options_without_a_cleanup_claim() {
    let mut child = guardian("echo", 5000, 1, 1048576, Some(&"0".repeat(64))); let control = child.stdin.take().unwrap(); let output = child.wait_with_output().unwrap(); drop(control); assert!(!output.status.success()); assert!(output.stdout.is_empty()); assert!(String::from_utf8_lossy(&output.stderr).contains("IDENTITY_CHANGED"));
    for args in [vec!["stream-supervise"], vec!["stream-supervise", "--unknown", "value"], vec!["stream-supervise", "--executable", "/unused", "--executable", "/unused"]] { let output = Command::new(env!("CARGO_BIN_EXE_ud-agent-guard")).args(args).output().unwrap(); assert!(!output.status.success()); assert!(output.stdout.is_empty()); }
}
#[cfg(target_os = "linux")]
#[test]
fn subreaps_a_descendant_that_starts_its_own_session() { let mut child = guardian("detached-tree", 200, 1, 1048576, None); let control = child.stdin.take().unwrap(); let started = Instant::now(); let (_, _, result) = complete(child, control); assert!(started.elapsed() < Duration::from_secs(4)); assert_eq!(result["timed_out"], true); assert_eq!(result["cleanup_verified"], true); }

#[cfg(unix)]
#[test]
fn independent_control_pipe_cancels_a_blocked_large_input_writer() {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    let (read, write) = UnixStream::pair().unwrap(); let descriptor = read.as_raw_fd();
    let mut command = guardian_command("hold", 5000, 20 * 1024 * 1024, 1048576, None); command.args(["--control-fd", "3"]);
    unsafe { command.pre_exec(move || { if libc::dup2(descriptor, 3) != 3 || libc::fcntl(3, libc::F_SETFD, 0) != 0 { return Err(std::io::Error::last_os_error()); } Ok(()) }); }
    let mut child = command.spawn().unwrap(); drop(read); let mut data = child.stdin.take().unwrap(); let mut stdout = child.stdout.take().unwrap();
    let writer = std::thread::spawn(move || {
        let chunk = vec![b'x'; 1024 * 1024];
        for _ in 0..20 {
            data.write_all(&[1])?;
            data.write_all(&(chunk.len() as u32).to_be_bytes())?;
            data.write_all(&chunk)?;
        }
        Ok::<_, std::io::Error>(())
    });
    let (ready, receiver) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut all = Vec::new(); let mut chunk = [0u8; 4096]; let mut seen = false;
        loop {
            let count = stdout.read(&mut chunk)?;
            if count == 0 { return Ok::<_, std::io::Error>(all); }
            all.extend_from_slice(&chunk[..count]);
            if !seen && all.windows(b"child-started:".len()).any(|value| value == b"child-started:") {
                let _ = ready.send(()); seen = true;
            }
        }
    });
    let readiness = receiver.recv_timeout(Duration::from_secs(3));
    let started = Instant::now(); drop(write);
    let output = child.wait_with_output().unwrap();
    let transfer = writer.join().unwrap(); let bytes = reader.join().unwrap().unwrap();
    assert!(output.status.success(), "valid independent-control fixture was rejected: {}", String::from_utf8_lossy(&output.stderr));
    assert!(readiness.is_ok(), "guardian did not start the requested child: {readiness:?}");
    if let Err(error) = transfer { if error.kind() != std::io::ErrorKind::BrokenPipe { panic!("fixture input transfer failed: {error}"); } }
    assert!(started.elapsed() < Duration::from_secs(4));
    let (_, _, result) = frames(&bytes); assert_eq!(result["cancelled"], true); assert_eq!(result["cleanup_verified"], true);
}

#[cfg(unix)]
#[test]
fn already_closed_control_revokes_before_any_engine_process_is_created() {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    let (read, write) = UnixStream::pair().unwrap(); drop(write); let descriptor = read.as_raw_fd();
    let mut command = guardian_command("grandchild", 5000, 1, 1048576, None); command.args(["--control-fd", "3"]);
    unsafe { command.pre_exec(move || { if libc::dup2(descriptor, 3) != 3 || libc::fcntl(3, libc::F_SETFD, 0) != 0 { return Err(std::io::Error::last_os_error()); } Ok(()) }); }
    let mut child = command.spawn().unwrap(); drop(read); let control = child.stdin.take().unwrap(); let output = child.wait_with_output().unwrap(); drop(control); assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr)); let (stdout, stderr, result) = frames(&output.stdout); assert!(stdout.is_empty()); assert!(stderr.is_empty()); assert_eq!(result["exit_code"], serde_json::Value::Null); assert_eq!(result["cancelled"], true); assert_eq!(result["cleanup_verified"], true);
}

#[test]
fn verifies_silent_descendants_stop_writing_before_reporting_cleanup() {
    let directory = std::env::temp_dir().join(format!("ud-stream-silent-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos())); fs::create_dir(&directory).unwrap(); let marker = directory.join("side-effects");
    let mut command = guardian_command("silent-grandchild", 5000, 1, 1048576, None); command.env("UD_STREAM_MARKER", &marker); let mut child = command.spawn().unwrap(); let control = child.stdin.take().unwrap(); let (stdout, _, result) = complete(child, control); assert!(String::from_utf8_lossy(&stdout).contains("owned-silent-grandchild:")); assert_eq!(result["exit_code"], 0); let before = fs::read(&marker).unwrap(); assert!(!before.is_empty()); std::thread::sleep(Duration::from_millis(150)); assert_eq!(fs::read(&marker).unwrap(), before); fs::remove_dir_all(directory).unwrap();
}
