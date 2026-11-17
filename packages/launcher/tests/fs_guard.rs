use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::io::{BufRead, BufReader, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

// Decode the public response only after asserting its successful-response
// contract. A malformed response is an assertion failure in the guard, whereas
// fixture filesystem/process errors below retain their runtime-error meaning.
fn response_json(bytes: &[u8]) -> serde_json::Value {
    let parsed = serde_json::from_slice(bytes);
    assert!(parsed.is_ok(), "guard returned malformed JSON: {parsed:?}");
    parsed.unwrap()
}
fn response_string(value: &serde_json::Value) -> &str {
    assert!(value.is_string(), "guard identity field must be a string: {value}");
    value.as_str().unwrap()
}

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let id = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let parent = std::env::temp_dir().canonicalize().unwrap();
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!("ud-agent-guard-{}-{id}-{serial}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}

fn guard(root: &Path, command: &str, path: &str, max: Option<&str>) -> Output {
    let mut process = Command::new(env!("CARGO_BIN_EXE_ud-agent-guard"));
    process.arg(command).arg("--root").arg(root).arg("--path").arg(path);
    if let Some(limit) = max { process.arg("--max-bytes").arg(limit); }
    process.output().unwrap()
}

fn root_identity(root: &Path) -> (String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_ud-agent-guard"))
        .arg("identity").arg("--root").arg(root).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let value = response_json(&output.stdout);
    (response_string(&value["device"]).into(), response_string(&value["inode"]).into())
}

fn owned(root: &Path, action: &str, name: &str, token: &str, expected: Option<(&str, &str)>) -> Output {
    let (device, inode) = root_identity(root);
    let mut command = Command::new(env!("CARGO_BIN_EXE_ud-agent-guard"));
    command.args([action, "--root"]).arg(root).args(["--root-device", &device, "--root-inode", &inode, "--path", name, "--owner-token", token]);
    if let Some((device, inode)) = expected { command.args(["--entry-device", device, "--entry-inode", inode]); }
    command.output().unwrap()
}

#[test]
fn owned_directory_lifecycle_keeps_foreign_contents_and_binds_cleanup_to_identity() {
    let tmp = Fixture::new(); let token = "a".repeat(64); let foreign = "b".repeat(64);
    for invalid in ["".to_owned(), "a".repeat(63), "a".repeat(65), "A".repeat(64), "g".repeat(64)] { assert!(!owned(&tmp.0, "mkdir-owned", "new", &invalid, None).status.success()); }
    let made = owned(&tmp.0, "mkdir-owned", "new", &token, None); assert!(made.status.success(), "{}", String::from_utf8_lossy(&made.stderr));
    let identity: serde_json::Value = response_json(&made.stdout);
    let device = response_string(&identity["device"]); let inode = response_string(&identity["inode"]);
    assert_eq!(fs::read_to_string(tmp.0.join("new/.ud-agent-directory-owner")).unwrap(), token);
    let replay = owned(&tmp.0, "mkdir-owned", "new", &token, None); assert!(replay.status.success()); assert_eq!(response_json(&replay.stdout), identity);
    assert!(!owned(&tmp.0, "mkdir-owned", "new", &foreign, None).status.success());
    assert!(!owned(&tmp.0, "release-owned", "new", &foreign, Some((device, inode))).status.success());
    assert!(!owned(&tmp.0, "rmdir-owned", "new", &token, Some((device, "0"))).status.success());
    fs::write(tmp.0.join("new/keep"), b"unrecognized").unwrap();
    assert!(!owned(&tmp.0, "rmdir-owned", "new", &token, Some((device, inode))).status.success());
    assert_eq!(fs::read(tmp.0.join("new/keep")).unwrap(), b"unrecognized");
    assert!(owned(&tmp.0, "release-owned", "new", &token, Some((device, inode))).status.success());
    assert!(!tmp.0.join("new/.ud-agent-directory-owner").exists());
    assert!(!owned(&tmp.0, "mkdir-owned", "new", &token, None).status.success());
    assert!(!owned(&tmp.0, "rmdir-owned", "new", &token, None).status.success());
    assert!(owned(&tmp.0, "release-owned", "new", &token, Some((device, inode))).status.success());
    fs::remove_file(tmp.0.join("new/keep")).unwrap();
    assert!(owned(&tmp.0, "rmdir-owned", "new", &token, Some((device, inode))).status.success());
    assert!(!tmp.0.join("new").exists());
    assert!(owned(&tmp.0, "rmdir-owned", "new", &token, Some((device, inode))).status.success());
}

#[cfg(unix)]
#[test]
fn owned_directory_recovers_only_private_token_bound_staging() {
    use std::os::unix::fs::{PermissionsExt, symlink}; use sha2::{Digest, Sha256};
    let tmp = Fixture::new(); let token = "c".repeat(64);
    let suffix = Sha256::digest(token.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let staging = tmp.0.join(format!(".ud-agent-directory-{suffix}"));
    let prepare = |contents: Option<&str>| { fs::create_dir(&staging).unwrap(); fs::set_permissions(&staging, fs::Permissions::from_mode(0o700)).unwrap(); if let Some(value) = contents { fs::write(staging.join(".ud-agent-directory-owner"), value).unwrap(); } };
    prepare(Some(&token[..17]));
    let published = owned(&tmp.0, "mkdir-owned", "destination", &token, None); assert!(published.status.success(), "{}", String::from_utf8_lossy(&published.stderr));
    assert!(!staging.exists()); assert_eq!(fs::read_to_string(tmp.0.join("destination/.ud-agent-directory-owner")).unwrap(), token);
    assert!(owned(&tmp.0, "rmdir-owned", "destination", &token, None).status.success());
    prepare(Some("different transaction"));
    assert!(!owned(&tmp.0, "mkdir-owned", "destination", &token, None).status.success()); assert!(!owned(&tmp.0, "rmdir-owned", "destination", &token, None).status.success());
    assert_eq!(fs::read_to_string(staging.join(".ud-agent-directory-owner")).unwrap(), "different transaction"); fs::remove_dir_all(&staging).unwrap();
    prepare(None); fs::write(staging.join("foreign"), b"keep").unwrap();
    assert!(!owned(&tmp.0, "mkdir-owned", "destination", &token, None).status.success()); assert!(!owned(&tmp.0, "rmdir-owned", "destination", &token, None).status.success()); fs::remove_dir_all(&staging).unwrap();
    prepare(Some("")); assert!(owned(&tmp.0, "rmdir-owned", "destination", &token, None).status.success()); assert!(!staging.exists());
    prepare(None); fs::set_permissions(&staging, fs::Permissions::from_mode(0o755)).unwrap(); assert!(!owned(&tmp.0, "mkdir-owned", "destination", &token, None).status.success()); fs::remove_dir(&staging).unwrap();
    fs::create_dir(tmp.0.join("foreign")).unwrap(); symlink(tmp.0.join("foreign"), &staging).unwrap(); assert!(!owned(&tmp.0, "mkdir-owned", "destination", &token, None).status.success());
    assert!(fs::read_dir(tmp.0.join("foreign")).unwrap().next().is_none());
}

#[test]
fn command_argument_contracts_reject_incompatible_or_partial_authorities_without_writes() {
    let tmp = Fixture::new(); fs::write(tmp.0.join("file"), b"unchanged").unwrap(); fs::create_dir(tmp.0.join("workspace")).unwrap();
    let (device, inode) = root_identity(&tmp.0); let (workspace_device, workspace_inode) = root_identity(&tmp.0.join("workspace"));
    let invoke = |command: &str, options: &[&str]| { Command::new(env!("CARGO_BIN_EXE_ud-agent-guard")).arg(command).arg("--root").arg(&tmp.0).args(options).output().unwrap() };
    let rejected = |command: &str, options: &[&str]| { let result = invoke(command, options); assert!(!result.status.success(), "{command} unexpectedly accepted {options:?}"); assert!(result.stdout.is_empty(), "rejected command wrote protocol output"); assert_eq!(fs::read(tmp.0.join("file")).unwrap(), b"unchanged"); };
    for option in ["--root-device", "--root-inode"] { rejected("identity", &[option, "0"]); }
    for option in ["--path", "--max-bytes", "--before-sha256", "--workspace-device", "--workspace-inode", "--owner-token", "--entry-device", "--entry-inode"] {
        let value = if option == "--max-bytes" { "1" } else { "x" }; rejected("identity", &[option, value]); rejected("capabilities", &[option, value]);
    }
    for options in [vec!["--workspace", "workspace"], vec!["--workspace", "workspace", "--root-device", &device, "--root-inode", &inode], vec!["--workspace", "workspace", "--workspace-device", &workspace_device, "--workspace-inode", &workspace_inode], vec!["--workspace", "workspace", "--root-device", &device, "--root-inode", &inode, "--workspace-device", &workspace_device], vec!["--workspace", "workspace", "--root-device", &device, "--root-inode", &inode, "--workspace-device", &workspace_device, "--workspace-inode", "0"]] { rejected("list", &options); }
    for option in ["--root-device", "--root-inode", "--workspace-device", "--workspace-inode", "--path", "--max-bytes", "--before-sha256"] { let value = if option == "--root-device" { device.as_str() } else if option == "--root-inode" { inode.as_str() } else if option == "--max-bytes" { "1" } else { "x" }; rejected("bind", &["--workspace", "workspace", option, value]); }
    rejected("bind", &[]); rejected("bind", &["--workspace", "../escape"]);
    for command in ["read", "private-read", "list", "replace", "metadata", "create", "restore", "remove", "flush-parent", "state-lock", "mkdir-owned", "release-owned", "rmdir-owned", "state-private-check", "state-private-init"] {
        rejected(command, &[]); rejected(command, &["--path", "file", "--root-device", &device]);
        rejected(command, &["--path", "file", "--root-device", &device, "--root-inode", "0"]);
    }
    for command in ["read", "private-read", "list", "create", "restore", "flush-parent", "state-lock", "mkdir-owned", "release-owned", "rmdir-owned", "state-private-check", "state-private-init"] { rejected(command, &["--path", "file", "--root-device", &device, "--root-inode", &inode, "--before-sha256", "x"]); }
    for command in ["read", "replace", "metadata", "create", "restore", "remove"] { rejected(command, &["--path", "file", "--root-device", &device, "--root-inode", &inode, "--max-bytes", "18446744073709551615"]); }
    for command in ["list", "flush-parent", "state-lock", "state-private-check", "state-private-init"] { rejected(command, &["--path", "file", "--root-device", &device, "--root-inode", &inode, "--max-bytes", "1"]); }
    for command in ["read", "identity", "list", "bind"] { rejected(command, &["--root", "duplicate"]); rejected(command, &["--unknown", "x"]); }
    for limit in ["-1", "NaN", "18446744073709551616"] { rejected("read", &["--path", "file", "--max-bytes", limit]); }
    assert!(invoke("read", &["--path", "file", "--max-bytes", "9"]).status.success());
    assert!(invoke("bind", &["--workspace", "workspace"]).status.success());
    assert!(invoke("list", &["--path", ".", "--workspace", "workspace", "--root-device", &device, "--root-inode", &inode, "--workspace-device", &workspace_device, "--workspace-inode", &workspace_inode]).status.success());
}

#[test]
fn native_transfer_limits_include_exact_boundaries_and_reject_invalid_fingerprints() {
    use sha2::{Digest, Sha256};
    let tmp = Fixture::new(); fs::write(tmp.0.join("file"), b"x").unwrap();
    let (device, inode) = root_identity(&tmp.0);
    let before = Sha256::digest(b"x").iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let call = |operation: &str, name: &str, limit: &str, expected: Option<&str>, bytes: &[u8]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ud-agent-guard"));
        command.args([operation, "--root"]).arg(&tmp.0).args(["--path", name, "--max-bytes", limit, "--root-device", &device, "--root-inode", &inode]);
        if let Some(hash) = expected { command.args(["--before-sha256", hash]); }
        let mut child = command.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap();
        if !bytes.is_empty() { let _ = child.stdin.take().unwrap().write_all(bytes); } else { drop(child.stdin.take()); }
        child.wait_with_output().unwrap()
    };
    for limit in ["1", "268435456"] { let result = call("read", "file", limit, None, b""); assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr)); assert_eq!(result.stdout, b"x"); }
    for operation in ["read", "replace", "create"] {
        let result = call(operation, if operation == "create" { "new" } else { "file" }, "268435457", if operation == "replace" { Some(before.as_str()) } else { None }, b"");
        assert!(!result.status.success()); assert!(result.stdout.is_empty());
    }
    for limit in ["1", "268435456"] { let result = call("replace", "file", limit, Some(&before), b"x"); assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr)); }
    let rejected = call("replace", "file", "1", Some(&before), b"xx"); assert!(!rejected.status.success()); assert_eq!(fs::read(tmp.0.join("file")).unwrap(), b"x");
    for invalid in ["a".repeat(63), "a".repeat(65), "g".repeat(64), before.to_uppercase()] {
        let result = call("replace", "file", "1", Some(&invalid), b"x"); assert!(!result.status.success()); assert!(String::from_utf8_lossy(&result.stderr).contains("before hash must be a lowercase SHA-256")); assert_eq!(fs::read(tmp.0.join("file")).unwrap(), b"x");
    }
    assert!(call("create", "empty", "0", None, b"").status.success()); assert!(call("read", "empty", "0", None, b"").status.success());
    assert!(call("create", "exact", "1", None, b"x").status.success()); assert!(call("create", "maximum", "268435456", None, b"x").status.success());
    assert!(!call("create", "oversized", "1", None, b"xx").status.success()); assert!(!tmp.0.join("oversized").exists());
}

#[cfg(unix)]
#[test]
fn private_directory_check_is_read_only_and_initialization_uses_the_bound_handle() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let tmp = Fixture::new(); let child = tmp.0.join("volume"); fs::create_dir(&child).unwrap(); fs::set_permissions(&child, fs::Permissions::from_mode(0o755)).unwrap();
    let (device, inode) = root_identity(&tmp.0);
    let call = |operation: &str, name: &str| Command::new(env!("CARGO_BIN_EXE_ud-agent-guard")).args([operation, "--root"]).arg(&tmp.0).args(["--path", name, "--root-device", &device, "--root-inode", &inode]).output().unwrap();
    assert!(!call("state-private-check", "volume").status.success());
    assert_eq!(fs::metadata(&child).unwrap().permissions().mode() & 0o777, 0o755);
    let initialized = call("state-private-init", "volume"); assert!(initialized.status.success(), "{}", String::from_utf8_lossy(&initialized.stderr));
    assert_eq!(fs::metadata(&child).unwrap().permissions().mode() & 0o777, 0o700);
    assert!(call("state-private-check", "volume").status.success());
    let unchanged = fs::metadata(&child).unwrap(); std::thread::sleep(std::time::Duration::from_millis(2));
    assert!(call("state-private-init", "volume").status.success());
    use std::os::unix::fs::MetadataExt;
    let reused = fs::metadata(&child).unwrap(); assert_eq!((unchanged.ctime(), unchanged.ctime_nsec()), (reused.ctime(), reused.ctime_nsec()), "warm initialization must not chmod an already private directory");
    symlink(&child, tmp.0.join("substituted")).unwrap(); assert!(!call("state-private-init", "substituted").status.success());
    #[cfg(target_os = "macos")]
    {
        let status = Command::new("/bin/chmod").args(["+a", "everyone allow read,search"]).arg(&child).status().unwrap(); assert!(status.success());
        assert!(!call("state-private-check", "volume").status.success());
        assert!(!call("state-private-init", "volume").status.success());
    }
}

#[test]
fn state_lock_is_exclusive_and_kernel_released_after_process_death() {
    let tmp = Fixture::new(); let (device, inode) = root_identity(&tmp.0);
    #[cfg(windows)]
    {
        let output = Command::new(env!("CARGO_BIN_EXE_ud-agent-guard")).args(["state-private-init", "--root"]).arg(&tmp.0).args(["--root-device", &device, "--root-inode", &inode]).output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    }
    let command = |operation: &str| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ud-agent-guard"));
        command.args([operation, "--root"]).arg(&tmp.0).args(["--path", "owned.native", "--root-device", &device, "--root-inode", &inode]); command
    };
    let missing = command("state-lock-existing").output().unwrap(); assert!(!missing.status.success()); assert!(missing.stdout.is_empty()); assert!(!tmp.0.join("owned.native").exists());
    let mut first = command("state-lock").stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap();
    let mut response = String::new(); BufReader::new(first.stdout.take().unwrap()).read_line(&mut response).unwrap();
    assert_eq!(response_json(response.as_bytes())["locked"], true);
    assert!(!command("state-lock").output().unwrap().status.success()); assert!(!command("state-lock-existing").output().unwrap().status.success());
    first.kill().unwrap(); first.wait().unwrap();
    let mut next = command("state-lock-existing").stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap();
    response.clear(); BufReader::new(next.stdout.take().unwrap()).read_line(&mut response).unwrap();
    assert_eq!(response_json(response.as_bytes())["locked"], true);
    drop(next.stdin.take()); assert!(next.wait().unwrap().success());
    assert!(tmp.0.join("owned.native").exists()); // existence never means ownership
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(tmp.0.join("owned.native"), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!command("state-lock-existing").output().unwrap().status.success());
        fs::set_permissions(tmp.0.join("owned.native"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(tmp.0.join("owned.native"), tmp.0.join("alias.native")).unwrap();
        assert!(!command("state-lock-existing").output().unwrap().status.success());
    }
}

#[test]
fn simultaneous_first_lock_creators_share_one_exclusive_inode() {
    let tmp = Fixture::new(); let (device, inode) = root_identity(&tmp.0);
    #[cfg(windows)] {
        let initialized = Command::new(env!("CARGO_BIN_EXE_ud-agent-guard")).args(["state-private-init", "--root"]).arg(&tmp.0).args(["--root-device", &device, "--root-inode", &inode]).output().unwrap();
        assert!(initialized.status.success(), "{}", String::from_utf8_lossy(&initialized.stderr));
    }
    for index in 0..20 {
        let name = format!("new-{index}.native");
        let spawn = || Command::new(env!("CARGO_BIN_EXE_ud-agent-guard")).args(["state-lock", "--root"]).arg(&tmp.0).args(["--path", &name, "--root-device", &device, "--root-inode", &inode]).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap();
        let mut a = spawn(); let mut b = spawn(); let mut first = String::new(); let mut second = String::new();
        BufReader::new(a.stdout.take().unwrap()).read_line(&mut first).unwrap(); BufReader::new(b.stdout.take().unwrap()).read_line(&mut second).unwrap();
        drop(a.stdin.take()); drop(b.stdin.take()); let result_a = a.wait_with_output().unwrap(); let result_b = b.wait_with_output().unwrap();
        assert_ne!(first.is_empty(), second.is_empty(), "exactly one creator must hold the kernel lock");
        let (winner, loser) = if first.is_empty() { (result_b, result_a) } else { (result_a, result_b) };
        assert!(winner.status.success(), "{}", String::from_utf8_lossy(&winner.stderr)); assert!(!loser.status.success());
        let text = String::from_utf8_lossy(&loser.stderr); assert!(text.contains("WouldBlock"), "contention must not become a filesystem/runner error: {text}");
    }
}

// A rejected request may close its input before the fixture finishes sending it.
// Reap the child first so positive tests attribute that rejection to its status,
// while unrelated transport failures retain their infrastructure-error meaning.
fn check_transfer_after_exit(transferred: std::io::Result<()>, output: &Output) {
    match transferred {
        Ok(()) => {},
        Err(error) if !output.status.success() && error.kind() == std::io::ErrorKind::BrokenPipe => {},
        Err(error) => panic!("fixture input transfer failed: {error}"),
    }
}

fn replace(root: &Path, path: &str, before: &str, data: &[u8]) -> Output {
    let (device, inode) = root_identity(root);
    let mut child = Command::new(env!("CARGO_BIN_EXE_ud-agent-guard"))
        .args(["replace", "--root"]).arg(root)
        .args(["--path", path, "--root-device", &device, "--root-inode", &inode,
            "--before-sha256", before, "--max-bytes", "1024"])
        .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped()).spawn().unwrap();
    let transferred = child.stdin.take().unwrap().write_all(data);
    let output = child.wait_with_output().unwrap();
    check_transfer_after_exit(transferred, &output);
    output
}

#[cfg(any(target_os = "macos", target_os = "linux", windows))]
fn mutate(root: &Path, command: &str, path: &str, before: Option<&str>, bytes: &[u8]) -> Output {
    let (device, inode) = root_identity(root);
    let mut process = Command::new(env!("CARGO_BIN_EXE_ud-agent-guard"));
    process.args([command, "--root"]).arg(root)
        .args(["--path", path, "--root-device", &device, "--root-inode", &inode, "--max-bytes", "1024"]);
    if let Some(expected) = before { process.args(["--before-sha256", expected]); }
    let mut child = process.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap();
    let transferred = child.stdin.take().unwrap().write_all(bytes);
    let output = child.wait_with_output().unwrap();
    check_transfer_after_exit(transferred, &output);
    output
}

#[test]
fn exclusive_creation_handles_short_unicode_names_and_preserves_conflicts() {
    let tmp = Fixture::new();
    for name in ["a", "配置-🦀.json", "a-longer-published-configuration.json"] {
        let created = mutate(&tmp.0, "create", name, None, b"original");
        assert!(created.status.success(), "create {name}: {}", String::from_utf8_lossy(&created.stderr));
        assert_eq!(fs::read(tmp.0.join(name)).unwrap(), b"original");
        let conflict = mutate(&tmp.0, "create", name, None, b"replacement");
        assert!(!conflict.status.success(), "create must not replace {name}");
        assert_eq!(fs::read(tmp.0.join(name)).unwrap(), b"original");
    }
    fs::create_dir(tmp.0.join("directory")).unwrap();
    fs::write(tmp.0.join("directory/foreign"), b"retained").unwrap();
    assert!(!mutate(&tmp.0, "create", "directory", None, b"replacement").status.success());
    assert_eq!(fs::read(tmp.0.join("directory/foreign")).unwrap(), b"retained");
    assert_eq!(fs::read_dir(&tmp.0).unwrap().count(), 4, "failed publications must remove only their temporary files");
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn creates_exclusively_and_restores_checked_deletions_with_original_metadata() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let tmp = Fixture::new();
    let file = tmp.0.join("file");
    fs::write(&file, b"before").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
    let before = fs::metadata(&file).unwrap();
    #[cfg(target_os = "macos")]
    assert!(Command::new("/usr/bin/xattr").args(["-w", "org.ud-agent.test", "retained"]).arg(&file).status().unwrap().success());
    let digest = "6db7d803e74f1ffa7d8f5adc0bf95b3e15bf4c8373fffadf546227cc6c6742cb";
    let metadata = mutate(&tmp.0, "metadata", "file", Some(digest), b"");
    assert!(metadata.status.success(), "{}", String::from_utf8_lossy(&metadata.stderr));
    assert!(!mutate(&tmp.0, "create", "file", None, b"overwrite").status.success());
    assert!(!mutate(&tmp.0, "remove", "file", Some(&"0".repeat(64)), b"").status.success());
    assert_eq!(fs::read(&file).unwrap(), b"before");
    assert!(mutate(&tmp.0, "remove", "file", Some(digest), b"").status.success());
    assert!(!file.exists());
    let mut restore = metadata.stdout; restore.push(b'\n'); restore.extend_from_slice(b"before");
    let result = mutate(&tmp.0, "restore", "file", None, &restore);
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let after = fs::metadata(&file).unwrap();
    assert_eq!((before.uid(), before.gid(), before.mode()), (after.uid(), after.gid(), after.mode()));
    assert_eq!(fs::read(&file).unwrap(), b"before");
    #[cfg(target_os = "macos")]
    assert_eq!(Command::new("/usr/bin/xattr").args(["-p", "org.ud-agent.test"]).arg(&file).output().unwrap().stdout, b"retained\n");
    assert_eq!(fs::read_dir(&tmp.0).unwrap().count(), 1);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn refuses_hardlinked_deletion_and_invalid_restore_metadata() {
    let tmp = Fixture::new();
    fs::write(tmp.0.join("original"), b"before").unwrap();
    fs::hard_link(tmp.0.join("original"), tmp.0.join("alias")).unwrap();
    let digest = "6db7d803e74f1ffa7d8f5adc0bf95b3e15bf4c8373fffadf546227cc6c6742cb";
    assert!(!mutate(&tmp.0, "remove", "original", Some(digest), b"").status.success());
    assert!(!mutate(&tmp.0, "restore", "new", None, b"{}\nnew").status.success());
    assert!(!mutate(&tmp.0, "create", "../outside", None, b"new").status.success());
    assert_eq!(fs::read(tmp.0.join("original")).unwrap(), b"before");
    assert_eq!(fs::read_dir(&tmp.0).unwrap().count(), 2);
}

#[test]
fn reads_exact_bytes_and_lists_a_nested_directory() {
    let tmp = Fixture::new();
    fs::create_dir(tmp.0.join("nested")).unwrap();
    fs::write(tmp.0.join("nested").join("sample.conllu"), b"a\0b\r\n").unwrap();
    let result = guard(&tmp.0, "read", "nested/sample.conllu", Some("5"));
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    assert_eq!(result.stdout, b"a\0b\r\n");
    let listing = guard(&tmp.0, "list", "nested", None);
    let parsed: serde_json::Value = response_json(&listing.stdout);
    assert_eq!(parsed[0]["name"], "sample.conllu");
    assert_eq!(parsed[0]["kind"], "file");
    assert_eq!(parsed[0]["size"], 5);
}

#[test]
fn rejects_escaping_paths_and_oversized_files_without_output() {
    let tmp = Fixture::new();
    fs::write(tmp.0.join("input"), b"1234").unwrap();
    for (name, limit) in [("../input", "10"), ("/etc/passwd", "100"), ("input", "3")] {
        let result = guard(&tmp.0, "read", name, Some(limit));
        assert!(!result.status.success(), "accepted {name}");
        assert!(result.stdout.is_empty());
    }
}

#[test]
fn replacement_checks_precondition_and_preserves_previous_file_on_conflict() {
    let tmp = Fixture::new();
    fs::write(tmp.0.join("file"), b"before").unwrap();
    let digest = "6db7d803e74f1ffa7d8f5adc0bf95b3e15bf4c8373fffadf546227cc6c6742cb";
    let conflict = replace(&tmp.0, "file", &"0".repeat(64), b"after");
    assert!(!conflict.status.success());
    assert_eq!(fs::read(tmp.0.join("file")).unwrap(), b"before");
    let result = replace(&tmp.0, "file", digest, b"after");
    #[cfg(any(target_os = "macos", target_os = "linux", windows))]
    {
        assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
        assert_eq!(fs::read(tmp.0.join("file")).unwrap(), b"after");
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("REPLACEMENT_UNAVAILABLE"));
        assert_eq!(fs::read(tmp.0.join("file")).unwrap(), b"before");
    }
    assert_eq!(fs::read_dir(&tmp.0).unwrap().count(), 1);
}

#[test]
fn identity_binding_rejects_a_replaced_workspace_root() {
    let tmp = Fixture::new();
    let root = tmp.0.join("root");
    fs::create_dir(&root).unwrap();
    let (device, inode) = root_identity(&root);
    fs::rename(&root, tmp.0.join("old")).unwrap();
    fs::create_dir(&root).unwrap();
    fs::write(root.join("file"), b"new root").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_ud-agent-guard"))
        .args(["read", "--root"]).arg(&root)
        .args(["--path", "file", "--max-bytes", "20", "--root-device", &device, "--root-inode", &inode])
        .output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("WORKSPACE_ROOT_CHANGED"));
}

#[cfg(windows)]
#[test]
fn windows_preserves_security_creation_time_and_alternate_streams() {
    use std::os::windows::fs::MetadataExt;
    let tmp = Fixture::new(); let file = tmp.0.join("file");
    fs::write(&file, b"before").unwrap();
    fs::write(format!("{}:annotation", file.display()), b"retained alternate stream").unwrap();
    let original = fs::metadata(&file).unwrap();
    let before = "6db7d803e74f1ffa7d8f5adc0bf95b3e15bf4c8373fffadf546227cc6c6742cb";
    let metadata = mutate(&tmp.0, "metadata", "file", Some(before), b"");
    assert!(metadata.status.success(), "{}", String::from_utf8_lossy(&metadata.stderr));
    let replaced = replace(&tmp.0, "file", before, b"after");
    assert!(replaced.status.success(), "{}", String::from_utf8_lossy(&replaced.stderr));
    assert_eq!(fs::read(&file).unwrap(), b"after");
    assert_eq!(fs::read(format!("{}:annotation", file.display())).unwrap(), b"retained alternate stream");
    let after = "f39592393ef0859cb196a52693d2cea00fb2df784b3c04ae54aa7cadb8e562f8";
    let actual = mutate(&tmp.0, "metadata", "file", Some(after), b"");
    assert!(actual.status.success(), "{}", String::from_utf8_lossy(&actual.stderr));
    let first: serde_json::Value = response_json(&metadata.stdout); let second: serde_json::Value = response_json(&actual.stdout);
    if first.get("preserved_file").is_some() {
        assert_eq!(first["preserved_file"]["file_id"], second["preserved_file"]["file_id"]);
        assert_eq!(first["preserved_file"]["volume"], second["preserved_file"]["volume"]);
        assert_eq!(second["preserved_file"]["before_sha256"], after);
        assert_eq!(fs::metadata(&file).unwrap().creation_time(), original.creation_time());
    } else { assert_eq!(first, second); }
}

#[cfg(windows)]
#[test]
fn windows_ntfs_deletion_rollback_preserves_the_original_object_without_security_privileges() {
    use std::os::windows::fs::MetadataExt;
    let tmp = Fixture::new(); let file = tmp.0.join("file"); fs::write(&file, b"before").unwrap(); fs::write(format!("{}:annotation", file.display()), b"ADS survives").unwrap();
    let original = fs::metadata(&file).unwrap(); let before = "6db7d803e74f1ffa7d8f5adc0bf95b3e15bf4c8373fffadf546227cc6c6742cb";
    let snapshot = mutate(&tmp.0, "metadata", "file", Some(before), b""); assert!(snapshot.status.success(), "{}", String::from_utf8_lossy(&snapshot.stderr));
    let metadata: serde_json::Value = response_json(&snapshot.stdout); assert!(metadata.get("preserved_file").is_some(), "The ordinary-user test requires the transactional NTFS backend.");
    let backup = tmp.0.join(response_string(&metadata["preserved_file"]["backup"])); assert!(!backup.exists());
    let removed = mutate(&tmp.0, "remove-preserved", "file", Some(before), &snapshot.stdout); assert!(removed.status.success(), "{}", String::from_utf8_lossy(&removed.stderr)); assert!(!file.exists()); assert!(backup.exists());
    let mut restore = snapshot.stdout.clone(); restore.push(b'\n'); restore.extend_from_slice(b"before");
    let restored = mutate(&tmp.0, "restore", "file", None, &restore); assert!(restored.status.success(), "{}", String::from_utf8_lossy(&restored.stderr)); assert!(!backup.exists());
    assert_eq!(fs::metadata(&file).unwrap().creation_time(), original.creation_time()); assert_eq!(fs::read(format!("{}:annotation", file.display())).unwrap(), b"ADS survives");
    let actual = mutate(&tmp.0, "metadata", "file", Some(before), b""); assert!(actual.status.success(), "{}", String::from_utf8_lossy(&actual.stderr)); let actual_json: serde_json::Value = response_json(&actual.stdout); assert_eq!(metadata["preserved_file"]["file_id"], actual_json["preserved_file"]["file_id"]);
    assert!(mutate(&tmp.0, "remove-preserved", "file", Some(before), &actual.stdout).status.success());
    let released = mutate(&tmp.0, "release-metadata", "file", None, &actual.stdout); assert!(released.status.success(), "{}", String::from_utf8_lossy(&released.stderr)); assert_eq!(fs::read_dir(&tmp.0).unwrap().count(), 0);
}

#[cfg(windows)]
#[test]
fn windows_rejects_directory_reparse_points() {
    let tmp = Fixture::new(); let outside = Fixture::new();
    fs::write(outside.0.join("secret"), b"not authorized").unwrap();
    std::os::windows::fs::symlink_dir(&outside.0, tmp.0.join("escape")).unwrap();
    let output = guard(&tmp.0, "read", "escape/secret", Some("100"));
    assert!(!output.status.success()); assert!(output.stdout.is_empty());
    assert_eq!(fs::read(outside.0.join("secret")).unwrap(), b"not authorized");
}

#[cfg(unix)]
#[test]
fn rejects_file_and_directory_symlinks() {
    use std::os::unix::fs::symlink;
    let tmp = Fixture::new();
    let outside = Fixture::new();
    fs::write(outside.0.join("secret"), b"not authorized").unwrap();
    symlink(outside.0.join("secret"), tmp.0.join("linked-file")).unwrap();
    symlink(&outside.0, tmp.0.join("linked-dir")).unwrap();
    assert!(!guard(&tmp.0, "read", "linked-file", Some("100")).status.success());
    assert!(!guard(&tmp.0, "read", "linked-dir/secret", Some("100")).status.success());
    let listing = guard(&tmp.0, "list", ".", None);
    assert!(listing.status.success(), "valid directory listing was rejected: {}", String::from_utf8_lossy(&listing.stderr));
    let parsed: serde_json::Value = response_json(&listing.stdout);
    assert!(parsed.is_array(), "directory listing must return an array");
    assert_eq!(parsed.as_array().unwrap().iter().filter(|entry| entry["kind"] == "symlink").count(), 2);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn replacement_preserves_mode_and_ownership() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let tmp = Fixture::new();
    let path = tmp.0.join("file");
    fs::write(&path, b"before").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    let before = fs::metadata(&path).unwrap();
    let digest = "6db7d803e74f1ffa7d8f5adc0bf95b3e15bf4c8373fffadf546227cc6c6742cb";
    let result = replace(&tmp.0, "file", digest, b"after");
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let after = fs::metadata(&path).unwrap();
    assert_eq!((before.uid(), before.gid(), before.mode(), before.nlink()),
               (after.uid(), after.gid(), after.mode(), after.nlink()));
    assert_ne!(before.ino(), after.ino());
    assert_eq!(fs::read(path).unwrap(), b"after");
    assert_eq!(fs::read_dir(&tmp.0).unwrap().count(), 1);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn replacement_flushes_a_nested_parent_directory() {
    let tmp = Fixture::new();
    fs::create_dir(tmp.0.join("nested")).unwrap();
    fs::write(tmp.0.join("nested/file"), b"before").unwrap();
    let digest = "6db7d803e74f1ffa7d8f5adc0bf95b3e15bf4c8373fffadf546227cc6c6742cb";
    let result = replace(&tmp.0, "nested/file", digest, b"after");
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    assert_eq!(fs::read(tmp.0.join("nested/file")).unwrap(), b"after");
    assert_eq!(fs::read_dir(tmp.0.join("nested")).unwrap().count(), 1);
}

#[cfg(target_os = "macos")]
#[test]
fn replacement_preserves_extended_attributes() {
    let tmp = Fixture::new();
    let path = tmp.0.join("file");
    fs::write(&path, b"before").unwrap();
    let status = Command::new("/usr/bin/xattr").args(["-w", "org.ud-agent.test", "retained"]).arg(&path).status().unwrap();
    assert!(status.success());
    let digest = "6db7d803e74f1ffa7d8f5adc0bf95b3e15bf4c8373fffadf546227cc6c6742cb";
    assert!(replace(&tmp.0, "file", digest, b"after").status.success());
    let output = Command::new("/usr/bin/xattr").args(["-p", "org.ud-agent.test"]).arg(&path).output().unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"retained\n");
    assert_eq!(fs::read(path).unwrap(), b"after");
}

#[cfg(target_os = "macos")]
#[test]
fn replacement_preserves_acl() {
    let tmp = Fixture::new();
    let path = tmp.0.join("file");
    fs::write(&path, b"before").unwrap();
    // A real ACL entry independent of account-directory availability: isolated
    // native quality jobs deliberately use an unregistered numeric identity.
    let status = Command::new("/bin/chmod").args(["+a", "everyone allow read"]).arg(&path).status().unwrap();
    assert!(status.success());
    let before = Command::new("/bin/ls").args(["-lde"]).arg(&path).output().unwrap();
    assert!(before.status.success());
    let digest = "6db7d803e74f1ffa7d8f5adc0bf95b3e15bf4c8373fffadf546227cc6c6742cb";
    let result = replace(&tmp.0, "file", digest, b"after");
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let after = Command::new("/bin/ls").args(["-lde"]).arg(&path).output().unwrap();
    assert_eq!(String::from_utf8(before.stdout).unwrap().lines().skip(1).collect::<Vec<_>>(), String::from_utf8(after.stdout).unwrap().lines().skip(1).collect::<Vec<_>>());
    assert_eq!(fs::read(path).unwrap(), b"after");
    assert_eq!(fs::read_dir(&tmp.0).unwrap().count(), 1);
}

#[cfg(target_os = "macos")]
#[test]
fn replacement_preserves_file_flags() {
    use std::os::macos::fs::MetadataExt;
    let tmp = Fixture::new();
    let path = tmp.0.join("file");
    fs::write(&path, b"before").unwrap();
    assert!(Command::new("/usr/bin/chflags").arg("hidden").arg(&path).status().unwrap().success());
    let before = fs::metadata(&path).unwrap().st_flags();
    assert_ne!(before, 0);
    let digest = "6db7d803e74f1ffa7d8f5adc0bf95b3e15bf4c8373fffadf546227cc6c6742cb";
    let result = replace(&tmp.0, "file", digest, b"after");
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    assert_eq!(fs::metadata(&path).unwrap().st_flags(), before);
    assert_eq!(fs::read(&path).unwrap(), b"after");
    assert_eq!(fs::read_dir(&tmp.0).unwrap().count(), 1);
}
