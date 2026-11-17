//! Recoverable publication and cleanup of transaction-owned parent directories.
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, DirBuilder, OpenOptions};
#[cfg(unix)]
use cap_std::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::io::{self, Read, Write};
use std::path::Path;
use super::{Identity, components, fail, hash, identity, open_directory};
const MARKER: &str = ".ud-agent-directory-owner";

fn sync(dir: &Dir) -> io::Result<()> {
    #[cfg(windows)]
    { super::fs_windows::flush_directory(dir.try_clone()?) }
    #[cfg(not(windows))]
    { let mut options = OpenOptions::new(); options.read(true).follow(FollowSymlinks::No); dir.open_with(".", &options)?.sync_all() }
}
fn private(dir: &Dir) -> io::Result<()> {
    #[cfg(windows)]
    { super::fs_windows::private_state(dir, true) }
    #[cfg(unix)]
    {
        unsafe extern "C" { fn getuid() -> u32; }
        let info = dir.dir_metadata()?;
        if info.uid() != unsafe { getuid() } || info.mode() & 0o077 != 0 { return Err(fail("owned transaction directory is not private")); }
        Ok(())
    }
}
fn marker(dir: &Dir) -> io::Result<Option<String>> {
    let mut options = OpenOptions::new(); options.read(true).follow(FollowSymlinks::No);
    match dir.open_with(MARKER, &options) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
        Ok(file) => {
            if !file.metadata()?.is_file() || file.metadata()?.len() > 64 { return Err(fail("invalid owned directory marker")); }
            let mut bytes = Vec::new(); file.take(65).read_to_end(&mut bytes)?;
            Ok(Some(String::from_utf8(bytes).map_err(|_| fail("invalid owned directory marker"))?))
        }
    }
}
fn check_marker(dir: &Dir, token: &str) -> io::Result<bool> {
    match marker(dir)? { Some(found) if found == token => Ok(true), None => Ok(false), _ => Err(fail("owned directory marker belongs to another transaction")) }
}
fn matches(dir: &Dir, expected: Option<(&str, &str)>) -> io::Result<bool> {
    let value = identity(dir)?;
    Ok(expected.is_some_and(|(device, inode)| value.device == device && value.inode == inode))
}
fn rename_exclusive(parent: &Dir, directory: Dir, old: &str, new: &std::ffi::OsStr) -> io::Result<Identity> {
    #[cfg(windows)]
    { return super::fs_windows::rename_directory_exclusive(parent, directory, old, new); }
    #[cfg(unix)]
    {
        use std::ffi::{c_char, c_int, CString}; use std::os::fd::AsRawFd; use std::os::unix::ffi::OsStrExt;
        unsafe extern "C" {
            #[cfg(target_os = "macos")]
            fn renameatx_np(from: c_int, old: *const c_char, to: c_int, new: *const c_char, flags: u32) -> c_int;
            #[cfg(target_os = "linux")]
            fn renameat2(from: c_int, old: *const c_char, to: c_int, new: *const c_char, flags: u32) -> c_int;
        }
        let old = CString::new(old).map_err(|_| fail("invalid owned directory name"))?;
        let new = CString::new(new.as_bytes()).map_err(|_| fail("invalid destination directory name"))?;
        #[cfg(target_os = "macos")]
        let result = unsafe { renameatx_np(parent.as_raw_fd(), old.as_ptr(), parent.as_raw_fd(), new.as_ptr(), 4) };
        #[cfg(target_os = "linux")]
        let result = unsafe { renameat2(parent.as_raw_fd(), old.as_ptr(), parent.as_raw_fd(), new.as_ptr(), 1) };
        if result != 0 { return Err(io::Error::last_os_error()); }
        identity(&directory)
    }
}

pub fn operate(root: Dir, path: &Path, token: &str, expected: Option<(&str, &str)>, action: &str) -> io::Result<Option<Identity>> {
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) { return Err(fail("invalid owned directory token")); }
    let mut parts = components(path, false)?; let leaf = parts.pop().ok_or_else(|| fail("missing owned directory name"))?;
    let parent = open_directory(root, &parts)?; sync(&parent)?;
    let temporary = format!(".ud-agent-directory-{}", hash(token.as_bytes()));
    if action == "mkdir-owned" {
        match parent.open_dir_nofollow(&leaf) {
            Ok(dir) => {
                private(&dir)?;
                if !check_marker(&dir, token)? { return Err(fail("DIRECTORY_CREATE_CONFLICT: existing directory is not transaction-owned")); }
                return Ok(Some(identity(&dir)?));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(error),
        }
        #[cfg(unix)]
        let mut builder = DirBuilder::new();
        #[cfg(windows)]
        let builder = DirBuilder::new();
        #[cfg(unix)]
        builder.mode(0o700);
        match parent.create_dir_with(&temporary, &builder) {
            Ok(()) => (),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
            Err(error) => return Err(error),
        }
        let dir = parent.open_dir_nofollow(&temporary)?; private(&dir)?;
        if dir.entries()?.any(|entry| entry.map_or(true, |entry| entry.file_name() != MARKER)) { return Err(fail("unknown temporary directory contents")); }
        let existing = marker(&dir)?;
        if existing.as_deref() != Some(token) {
            if let Some(prefix) = existing {
                if !token.starts_with(&prefix) { return Err(fail("temporary directory belongs to another transaction")); }
                dir.remove_file(MARKER)?;
            }
            let mut options = OpenOptions::new(); options.write(true).create_new(true).follow(FollowSymlinks::No);
            #[cfg(unix)] options.mode(0o600);
            let mut file = dir.open_with(MARKER, &options)?; file.write_all(token.as_bytes())?; file.sync_all()?;
        }
        sync(&dir)?; let published = rename_exclusive(&parent, dir, &temporary, &leaf)?; sync(&parent)?;
        return Ok(Some(published));
    }
    let dir = match parent.open_dir_nofollow(&leaf) {
        Ok(dir) => dir,
        Err(error) if error.kind() == io::ErrorKind::NotFound && action == "rmdir-owned" => {
            // A failed exclusive publish may have retained its private staging
            // directory. The token and private ownership bind that cleanup.
            match parent.open_dir_nofollow(&temporary) {
                Ok(staged) => {
                    private(&staged)?;
                    let marker = marker(&staged)?;
                    if marker.as_ref().is_some_and(|prefix| !token.starts_with(prefix)) { return Err(fail("temporary directory belongs to another transaction")); }
                    if staged.entries()?.any(|entry| entry.map_or(true, |entry| entry.file_name() != MARKER)) { return Err(fail("owned directory contains unrecognized files")); }
                    if marker.is_some() { staged.remove_file(MARKER)?; }
                    drop(staged); parent.remove_dir(&temporary)?; sync(&parent)?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => (),
                Err(error) => return Err(error),
            }
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    private(&dir)?;
    if expected.is_some() && !matches(&dir, expected)? { return Err(fail("OWNED_DIRECTORY_CHANGED")); }
    let marked = check_marker(&dir, token)?;
    if !marked && !matches(&dir, expected)? { return Err(fail("OWNED_DIRECTORY_UNVERIFIED")); }
    if action == "release-owned" {
        if marked { dir.remove_file(MARKER)?; sync(&dir)?; }
        return Ok(Some(identity(&dir)?));
    }
    if action != "rmdir-owned" { return Err(fail("unknown owned-directory action")); }
    if dir.entries()?.any(|entry| entry.map_or(true, |entry| entry.file_name() != MARKER)) { return Err(fail("owned directory contains unrecognized files")); }
    if marked { dir.remove_file(MARKER)?; sync(&dir)?; }
    drop(dir); parent.remove_dir(&leaf)?; sync(&parent)?;
    Ok(None)
}
