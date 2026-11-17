#[cfg(unix)]
mod unix {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn launches_only_with_absolute_existing_node_and_coordinator() {
        let parent = std::env::temp_dir().canonicalize().unwrap();
        let root = parent.join(format!("ud-agent-launcher-{}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&root).unwrap();
        let child = root.join("node");
        let marker = root.join("started");
        let coordinator = root.join("coordinator.mjs");
        fs::write(&child, "#!/bin/sh\nprintf started > \"$UD_AGENT_TEST_MARKER\"\n").unwrap();
        fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&coordinator, "// test coordinator\n").unwrap();
        let run = |node: &Path, script: &Path| Command::new(env!("CARGO_BIN_EXE_ud-agent"))
            .env("UD_AGENT_NODE", node)
            .env("UD_AGENT_COORDINATOR", script)
            .env("UD_AGENT_TEST_MARKER", &marker)
            .output().unwrap();

        let relative = run(&child, Path::new("coordinator.mjs"));
        assert!(!relative.status.success());
        assert!(!marker.exists(), "rejected coordinator must not start a child");
        let missing = run(&child, &root.join("missing.mjs"));
        assert!(!missing.status.success());
        assert!(!marker.exists());
        let relative_node = run(Path::new("node"), &coordinator);
        assert!(!relative_node.status.success());
        assert!(!marker.exists());
        let missing_node = run(&root.join("missing-node"), &coordinator); assert!(!missing_node.status.success()); assert!(String::from_utf8_lossy(&missing_node.stderr).contains("absolute Node executable is unavailable")); assert!(!marker.exists());
        let directory_node = run(&root, &coordinator); assert!(!directory_node.status.success()); assert!(!marker.exists());
        let directory_script = run(&child, &root); assert!(!directory_script.status.success()); assert!(!marker.exists());
        let valid = run(&child, &coordinator);
        assert!(valid.status.success(), "{}", String::from_utf8_lossy(&valid.stderr));
        assert_eq!(fs::read(&marker).unwrap(), b"started");
        fs::remove_file(&marker).unwrap(); fs::set_permissions(&child, fs::Permissions::from_mode(0o600)).unwrap();
        let denied = run(&child, &coordinator); assert!(!denied.status.success()); assert!(!marker.exists());
        fs::write(&child, "#!/bin/sh\nexit 42\n").unwrap(); fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(run(&child, &coordinator).status.code(), Some(42));
        fs::remove_dir_all(root).unwrap();
    }
}
