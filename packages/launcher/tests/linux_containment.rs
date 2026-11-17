#![cfg(target_os = "linux")]
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Digest, Sha256};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self { let root = std::env::temp_dir().canonicalize().unwrap().join(format!("ud-linux-containment-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos())); fs::create_dir(&root).unwrap(); fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap(); Self(root) }
    fn python(&self) -> PathBuf {
        // Original acceptance selects and records its managed interpreter.
        // Hosted PATH can still contain a separate, shared setup-python tree.
        let prerequisite = std::env::var_os("UD_AGENT_PYTHON").unwrap_or_else(|| "python3".into());
        let selected = Command::new(&prerequisite).args(["-I", "-c", "import os,sys;print(os.path.realpath(sys.executable))"]).output().expect("required Python prerequisite");
        assert!(selected.status.success(), "selected Python {:?}: {}", prerequisite, String::from_utf8_lossy(&selected.stderr));
        PathBuf::from(String::from_utf8(selected.stdout).unwrap().trim())
    }
    fn venv(&self, python: &Path) -> PathBuf { let root = self.0.join("venv"); let status = Command::new(python).args(["-I", "-m", "venv", "--without-pip"]).arg(&root).status().unwrap(); assert!(status.success(), "required private venv creation"); let alias = root.join("bin/python"); assert!(fs::symlink_metadata(&alias).unwrap().file_type().is_symlink()); alias }
}
impl Drop for Fixture { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
fn hash(file: &Path) -> String { Sha256::digest(fs::read(file).unwrap()).iter().map(|byte| format!("{byte:02x}")).collect() }
fn setup(root: &Path, executable: &Path, expected: &str, arguments: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ud-agent-guard")).args(["contained-setup", "--executable"]).arg(executable).args(["--executable-sha256", expected, "--arguments-json", arguments, "--staging"]).arg(root).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    // EOF revokes setup: keep its control pipe open through normal completion.
    let control = child.stdin.take(); let output = child.wait_with_output().unwrap(); drop(control); output
}
#[test]
fn setup_executes_the_verified_alias_with_its_private_venv_prefix() {
    let fixture = Fixture::new(); let python = fixture.python(); let alias = fixture.venv(&python); let expected = hash(&python);
    let output = setup(&fixture.0, &alias, &expected, r#"["-I","-c","import sys;print(sys.prefix)"]"#); assert!(output.status.success(), "selected Python {}: {}", python.display(), String::from_utf8_lossy(&output.stderr)); assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), fixture.0.join("venv").to_str().unwrap());
    let output = setup(&fixture.0, &alias, &"0".repeat(64), r#"["-I","-c","raise AssertionError('unverified interpreter executed')"]"#); assert!(!output.status.success()); assert!(String::from_utf8_lossy(&output.stderr).contains("IDENTITY_CHANGED"));
    let replacement = fixture.0.join("replacement"); fs::write(&replacement, b"\x7fELFchanged executable").unwrap(); fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700)).unwrap(); fs::remove_file(&alias).unwrap(); std::os::unix::fs::symlink(&replacement, &alias).unwrap(); assert!(!setup(&fixture.0, &alias, &expected, "[]").status.success());
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o777)).unwrap(); let unsafe_output = setup(&fixture.0, &alias, &hash(&replacement), "[]"); assert!(!unsafe_output.status.success()); assert!(String::from_utf8_lossy(&unsafe_output.stderr).contains("CONTAINED_FILE_UNSAFE"));
}
#[test]
fn worker_preserves_fd3_and_request_framing_and_rejects_bootstrap_aliases() {
    unsafe extern "C" { fn dup2(old: i32, new: i32) -> i32; fn fcntl(fd: i32, operation: i32, ...) -> i32; }
    let fixture = Fixture::new(); let python = fixture.python(); let alias = fixture.venv(&python); let bootstrap = fixture.0.join("bootstrap.py");
    let code = format!("import os,sys\nassert sys.prefix=={:?}\nassert os.read(3,64)==b'snapshot'\nassert sys.stdin.buffer.readline()==b'request\\n'\nprint('native-framing-ok')\n", fixture.0.join("venv").to_str().unwrap()); fs::write(&bootstrap, code).unwrap();
    let invoke = |entry: &Path, expected: &str| {
        let (read, mut write) = UnixStream::pair().unwrap(); let descriptor = read.as_raw_fd(); let mut command = Command::new(env!("CARGO_BIN_EXE_ud-agent-guard"));
        command.args(["contained-run", "--executable"]).arg(&alias).args(["--executable-sha256", &hash(&python), "--bootstrap"]).arg(entry).args(["--bootstrap-sha256", expected, "--worker"]).arg(&fixture.0).arg("--upstream").arg(&fixture.0).arg("--context").arg(&fixture.0).args(["--snapshot-sha256", &"0".repeat(64), "--staging"]).arg(&fixture.0).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        unsafe { command.pre_exec(move || { if dup2(descriptor, 3) != 3 || fcntl(3, 2, 0) != 0 { return Err(std::io::Error::last_os_error()); } Ok(()) }); }
        let mut child = command.spawn().unwrap(); drop(read); let _ = write.write_all(b"snapshot"); let _ = write.shutdown(std::net::Shutdown::Write); let _ = child.stdin.take().unwrap().write_all(b"request\n"); child.wait_with_output().unwrap()
    };
    let result = invoke(&bootstrap, &hash(&bootstrap)); assert!(result.status.success(), "selected Python {}: {}", python.display(), String::from_utf8_lossy(&result.stderr)); assert_eq!(result.stdout, b"native-framing-ok\n");
    let linked = fixture.0.join("linked.py"); std::os::unix::fs::symlink(&bootstrap, &linked).unwrap(); let result = invoke(&linked, &hash(&bootstrap)); assert!(!result.status.success()); assert!(result.stdout.is_empty()); let result = invoke(&bootstrap, &"0".repeat(64)); assert!(!result.status.success()); assert!(String::from_utf8_lossy(&result.stderr).contains("IDENTITY_CHANGED"));
}
