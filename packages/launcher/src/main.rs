use std::path::PathBuf;
use std::process::{Command, ExitCode};

#[cfg(windows)]
mod windows_node;

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("ud-agent: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<u8, Box<dyn std::error::Error>> {
    let executable = std::env::current_exe()?;
    let package_root = executable.parent().and_then(|p| p.parent()).ok_or("missing package root")?;
    #[cfg(windows)]
    let (arguments, workspace) = windows_node::launch_arguments(std::env::args_os().skip(1).collect())?;
    #[cfg(not(windows))]
    let (arguments, workspace) = (std::env::args_os().skip(1).collect::<Vec<_>>(), None::<String>);
    let explicit = workspace.is_none();
    let node_override = explicit.then(|| std::env::var_os("UD_AGENT_NODE")).flatten();
    #[cfg(windows)]
    let acquired = if node_override.is_none() {
        let offline = arguments.iter().any(|arg| arg == "--offline") || std::env::var_os("UD_AGENT_OFFLINE").as_deref() == Some(std::ffi::OsStr::new("1"));
        Some(windows_node::acquire(package_root, offline)?)
    } else { None };
    #[cfg(windows)]
    let node = node_override.map(PathBuf::from).unwrap_or_else(|| acquired.as_ref().unwrap().path.clone());
    #[cfg(not(windows))]
    let node = node_override.map(PathBuf::from).unwrap_or_else(|| package_root.join("runtime/node/bin/node"));
    if !node.is_absolute() || !node.is_file() {
        return Err("absolute Node executable is unavailable".into());
    }
    let coordinator = explicit.then(|| std::env::var_os("UD_AGENT_COORDINATOR")).flatten().map(PathBuf::from)
        .unwrap_or_else(|| package_root.join("lib").join("coordinator.mjs"));
    if !coordinator.is_absolute() || !coordinator.is_file() {
        return Err("coordinator bundle is unavailable".into());
    }
    let mut command = Command::new(node);
    command.arg(coordinator).args(arguments);
    if let Some(workspace) = workspace {
        command.env_remove("UD_AGENT_NODE").env_remove("UD_AGENT_COORDINATOR");
        command.env("UD_AGENT_ALLOWED_ROOTS", workspace);
    }
    // Replacing the launcher keeps the host's process identity and signal delivery
    // attached to the coordinator instead of leaving an orphaned child on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        Err(command.exec().into())
    }
    #[cfg(not(unix))]
    {
        let status = command.status()?;
        Ok(status.code().and_then(|code| u8::try_from(code).ok()).unwrap_or(1))
    }
}
