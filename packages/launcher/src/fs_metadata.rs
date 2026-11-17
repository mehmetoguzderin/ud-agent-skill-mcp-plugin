//! Metadata is captured and restored through open handles, never pathnames.
use cap_std::fs::{File, MetadataExt};
use serde::{Deserialize, Serialize};
use std::ffi::{c_char, c_int, c_void, CString};
use std::io;
use std::os::fd::AsRawFd;

const MAX_METADATA: usize = 256 * 1024;
#[cfg(target_os = "macos")]
const ACL_EXTENDED: c_int = 0x100;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    uid: u32,
    gid: u32,
    mode: u32,
    flags: u32,
    xattrs: Vec<(Vec<u8>, Vec<u8>)>,
    acl: Option<Vec<u8>>,
}

unsafe extern "C" {
    fn fchown(fd: c_int, owner: u32, group: u32) -> c_int;
    #[cfg(target_os = "macos")]
    fn flistxattr(fd: c_int, names: *mut c_char, size: usize, options: c_int) -> isize;
    #[cfg(target_os = "linux")]
    fn flistxattr(fd: c_int, names: *mut c_char, size: usize) -> isize;
    #[cfg(target_os = "macos")]
    fn fgetxattr(fd: c_int, name: *const c_char, value: *mut c_void, size: usize, position: u32, options: c_int) -> isize;
    #[cfg(target_os = "linux")]
    fn fgetxattr(fd: c_int, name: *const c_char, value: *mut c_void, size: usize) -> isize;
    #[cfg(target_os = "macos")]
    fn fsetxattr(fd: c_int, name: *const c_char, value: *const c_void, size: usize, position: u32, options: c_int) -> c_int;
    #[cfg(target_os = "linux")]
    fn fsetxattr(fd: c_int, name: *const c_char, value: *const c_void, size: usize, options: c_int) -> c_int;
    #[cfg(target_os = "macos")]
    fn fremovexattr(fd: c_int, name: *const c_char, options: c_int) -> c_int;
    #[cfg(target_os = "linux")]
    fn fremovexattr(fd: c_int, name: *const c_char) -> c_int;
    #[cfg(target_os = "macos")]
    fn acl_get_fd_np(fd: c_int, kind: c_int) -> *mut c_void;
    #[cfg(target_os = "macos")]
    fn acl_set_fd_np(fd: c_int, acl: *mut c_void, kind: c_int) -> c_int;
    #[cfg(target_os = "macos")]
    fn acl_free(acl: *mut c_void) -> c_int;
    #[cfg(target_os = "macos")]
    fn acl_to_text(acl: *mut c_void, length: *mut isize) -> *mut c_char;
    #[cfg(target_os = "macos")]
    fn acl_from_text(text: *const c_char) -> *mut c_void;
    #[cfg(target_os = "macos")]
    fn acl_init(count: c_int) -> *mut c_void;
    #[cfg(target_os = "macos")]
    fn fchflags(fd: c_int, flags: u32) -> c_int;
    #[cfg(target_os = "linux")]
    fn ioctl(fd: c_int, request: usize, ...) -> c_int;
}

fn invalid() -> io::Error { io::Error::new(io::ErrorKind::InvalidInput, "invalid or oversized file metadata") }
fn check_size(size: isize) -> io::Result<usize> {
    if size < 0 { return Err(io::Error::last_os_error()); }
    if (size as usize) > MAX_METADATA { return Err(invalid()); }
    Ok(size as usize)
}

fn names(fd: c_int) -> io::Result<Vec<Vec<u8>>> {
    #[cfg(target_os = "macos")]
    let length = unsafe { flistxattr(fd, std::ptr::null_mut(), 0, 0) };
    #[cfg(target_os = "linux")]
    let length = unsafe { flistxattr(fd, std::ptr::null_mut(), 0) };
    let mut bytes = vec![0; check_size(length)?];
    if bytes.is_empty() { return Ok(Vec::new()); }
    #[cfg(target_os = "macos")]
    let actual = unsafe { flistxattr(fd, bytes.as_mut_ptr().cast(), bytes.len(), 0) };
    #[cfg(target_os = "linux")]
    let actual = unsafe { flistxattr(fd, bytes.as_mut_ptr().cast(), bytes.len()) };
    if check_size(actual)? != bytes.len() || bytes.last() != Some(&0) { return Err(invalid()); }
    bytes.pop();
    let mut result: Vec<Vec<u8>> = bytes.split(|byte| *byte == 0).map(|name| name.to_vec()).collect();
    if result.iter().any(Vec::is_empty) { return Err(invalid()); }
    result.sort();
    if result.windows(2).any(|pair| pair[0] == pair[1]) { return Err(invalid()); }
    Ok(result)
}

fn xattrs(fd: c_int) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut result = Vec::new();
    let mut total = 0usize;
    for name in names(fd)? {
        let c_name = CString::new(name.clone()).map_err(|_| invalid())?;
        #[cfg(target_os = "macos")]
        let size = unsafe { fgetxattr(fd, c_name.as_ptr(), std::ptr::null_mut(), 0, 0, 0) };
        #[cfg(target_os = "linux")]
        let size = unsafe { fgetxattr(fd, c_name.as_ptr(), std::ptr::null_mut(), 0) };
        let mut value = vec![0; check_size(size)?];
        #[cfg(target_os = "macos")]
        let actual = unsafe { fgetxattr(fd, c_name.as_ptr(), value.as_mut_ptr().cast(), value.len(), 0, 0) };
        #[cfg(target_os = "linux")]
        let actual = unsafe { fgetxattr(fd, c_name.as_ptr(), value.as_mut_ptr().cast(), value.len()) };
        if check_size(actual)? != value.len() { return Err(invalid()); }
        total = total.checked_add(name.len() + value.len()).ok_or_else(invalid)?;
        if total > MAX_METADATA { return Err(invalid()); }
        result.push((name, value));
    }
    Ok(result)
}

#[cfg(target_os = "macos")]
struct Acl(*mut c_void);
#[cfg(target_os = "macos")]
impl Drop for Acl { fn drop(&mut self) { unsafe { acl_free(self.0); } } }

#[cfg(target_os = "macos")]
fn acl(fd: c_int) -> io::Result<Option<Vec<u8>>> {
    let raw = unsafe { acl_get_fd_np(fd, ACL_EXTENDED) };
    if raw.is_null() {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(2) { Ok(None) } else { Err(error) };
    }
    let acl = Acl(raw);
    let mut length = 0isize;
    let text = unsafe { acl_to_text(acl.0, &mut length) };
    if text.is_null() { return Err(io::Error::last_os_error()); }
    let owned = Acl(text.cast());
    let size = check_size(length)?;
    let bytes = unsafe { std::slice::from_raw_parts(owned.0.cast::<u8>(), size) }.to_vec();
    Ok(Some(bytes))
}

#[cfg(target_os = "macos")]
pub(super) fn verify_private_directory_acl(fd: c_int) -> io::Result<()> {
    if let Some(bytes) = acl(fd)? {
        let text = std::str::from_utf8(&bytes).map_err(|_| invalid())?;
        if text.lines().any(|line| !line.trim().is_empty() && line.trim() != "!#acl 1") {
            return Err(io::Error::other("PRIVATE_STATE_EXTENDED_ACL_UNVERIFIED"));
        }
    }
    Ok(())
}

fn flags(file: &File) -> io::Result<u32> {
    #[cfg(target_os = "macos")]
    { use std::os::macos::fs::MetadataExt; Ok(file.try_clone()?.into_std().metadata()?.st_flags()) }
    #[cfg(target_os = "linux")]
    {
        let mut value: i32 = 0;
        if unsafe { ioctl(file.as_raw_fd(), 0x80086601, &mut value) } != 0 { return Err(io::Error::last_os_error()); }
        Ok(value as u32)
    }
}

impl Metadata {
    pub fn read(file: &File) -> io::Result<Self> {
        let stat = file.metadata()?;
        if !stat.is_file() { return Err(invalid()); }
        Ok(Self { uid: stat.uid(), gid: stat.gid(), mode: stat.mode(), flags: flags(file)?, xattrs: xattrs(file.as_raw_fd())?,
            #[cfg(target_os = "macos")] acl: acl(file.as_raw_fd())?,
            #[cfg(target_os = "linux")] acl: None,
        })
    }

    pub fn apply(&self, file: &File) -> io::Result<()> {
        // Invalid serialized recovery material must fail before native calls.
        let mut total = self.acl.as_ref().map_or(0, Vec::len);
        let mut previous: Option<&[u8]> = None;
        for (name, value) in &self.xattrs {
            if name.is_empty() || name.contains(&0) || previous.is_some_and(|old| old >= name.as_slice()) { return Err(invalid()); }
            previous = Some(name);
            total = total.checked_add(name.len() + value.len()).ok_or_else(invalid)?;
        }
        if total > MAX_METADATA || self.mode & !0o177777 != 0 || self.mode & 0o170000 != 0o100000 { return Err(invalid()); }
        // Immutable/append flags prohibit editing; applying them to a temporary
        // file would also make failed-replacement cleanup impossible.
        #[cfg(target_os = "macos")]
        if self.flags & (0x2 | 0x4 | 0x20000 | 0x40000) != 0 { return Err(invalid()); }
        #[cfg(target_os = "linux")]
        if self.flags & (0x10 | 0x20) != 0 || self.acl.is_some() { return Err(invalid()); }
        let fd = file.as_raw_fd();
        let current = file.metadata()?;
        if (current.uid() != self.uid || current.gid() != self.gid) && unsafe { fchown(fd, self.uid, self.gid) } != 0 { return Err(io::Error::last_os_error()); }
        // Remove inherited attributes absent from the original inode.
        for name in names(fd)? {
            if self.xattrs.iter().any(|(wanted, _)| *wanted == name) { continue; }
            let name = CString::new(name).map_err(|_| invalid())?;
            #[cfg(target_os = "macos")]
            let result = unsafe { fremovexattr(fd, name.as_ptr(), 0) };
            #[cfg(target_os = "linux")]
            let result = unsafe { fremovexattr(fd, name.as_ptr()) };
            if result != 0 { return Err(io::Error::last_os_error()); }
        }
        file.set_permissions(cap_std::fs::Permissions::from_std({ use std::os::unix::fs::PermissionsExt; std::fs::Permissions::from_mode(self.mode & 0o7777) }))?;
        for (name, value) in &self.xattrs {
            let name = CString::new(name.as_slice()).map_err(|_| invalid())?;
            #[cfg(target_os = "macos")]
            let result = unsafe { fsetxattr(fd, name.as_ptr(), value.as_ptr().cast(), value.len(), 0, 0) };
            #[cfg(target_os = "linux")]
            let result = unsafe { fsetxattr(fd, name.as_ptr(), value.as_ptr().cast(), value.len(), 0) };
            if result != 0 { return Err(io::Error::last_os_error()); }
        }
        #[cfg(target_os = "macos")]
        {
            let text = self.acl.as_ref().map(|bytes| CString::new(bytes.as_slice()).map_err(|_| invalid())).transpose()?;
            let raw = match &text { Some(text) => unsafe { acl_from_text(text.as_ptr()) }, None => unsafe { acl_init(0) } };
            if raw.is_null() { return Err(io::Error::last_os_error()); }
            let acl = Acl(raw);
            if unsafe { acl_set_fd_np(fd, acl.0, ACL_EXTENDED) } != 0 { return Err(io::Error::last_os_error()); }
            if unsafe { fchflags(fd, self.flags) } != 0 { return Err(io::Error::last_os_error()); }
        }
        #[cfg(target_os = "linux")]
        if flags(file)? != self.flags {
            let value = self.flags as i32;
            if unsafe { ioctl(fd, 0x40086602, &value) } != 0 { return Err(io::Error::last_os_error()); }
        }
        if Self::read(file)? != *self { return Err(io::Error::other("file metadata could not be preserved")); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Temporary(std::path::PathBuf);
    impl Temporary {
        fn new() -> Self { let path = std::env::temp_dir().join(format!("ud-native-metadata-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed))); std::fs::create_dir(&path).unwrap(); Self(path) }
        fn file(&self, name: &str) -> File { let file = std::fs::OpenOptions::new().create_new(true).read(true).write(true).open(self.0.join(name)).unwrap(); File::from_std(file) }
    }
    impl Drop for Temporary { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }
    fn set(file: &File, name: &str, bytes: &[u8]) {
        let name = CString::new(name).unwrap();
        #[cfg(target_os = "macos")]
        let result = unsafe { fsetxattr(file.as_raw_fd(), name.as_ptr(), bytes.as_ptr().cast(), bytes.len(), 0, 0) };
        #[cfg(target_os = "linux")]
        let result = unsafe { fsetxattr(file.as_raw_fd(), name.as_ptr(), bytes.as_ptr().cast(), bytes.len(), 0) };
        assert_eq!(result, 0, "{}", io::Error::last_os_error());
    }
    fn name(suffix: &str) -> String { format!("{}ud-agent.{suffix}", if cfg!(target_os = "linux") { "user." } else { "com." }) }
    fn copy(value: &Metadata) -> Metadata { serde_json::from_value(serde_json::to_value(value).unwrap()).unwrap() }

    #[test]
    fn accepts_exact_metadata_size_and_rejects_negative_or_excessive_native_lengths() {
        assert_eq!(check_size(0).unwrap(), 0); assert_eq!(check_size(262144).unwrap(), 262144);
        assert!(check_size(-1).is_err()); assert!(check_size(262145).is_err());
    }

    #[test]
    fn metadata_application_restores_sorted_binary_and_empty_attributes_and_removes_inheritance() {
        let temp = Temporary::new(); let original = temp.file("original"); let target = temp.file("target");
        original.set_permissions(cap_std::fs::Permissions::from_std(std::fs::Permissions::from_mode(0o641))).unwrap();
        set(&original, &name("z"), &[0, 1, 255]); set(&original, &name("a"), &[]);
        let metadata = Metadata::read(&original).unwrap();
        assert_eq!(metadata.xattrs, vec![(name("a").into_bytes(), vec![]), (name("z").into_bytes(), vec![0, 1, 255])]);
        set(&target, &name("foreign"), b"inherited"); set(&target, &name("z"), b"old");
        metadata.apply(&target).unwrap(); assert_eq!(Metadata::read(&target).unwrap(), metadata);
        assert_eq!(std::fs::metadata(temp.0.join("target")).unwrap().permissions().mode() & 0o7777, 0o641);
    }

    #[test]
    fn malformed_recovery_metadata_is_rejected_before_changing_the_target() {
        let temp = Temporary::new(); let file = temp.file("target"); set(&file, &name("retained"), b"data");
        let original = Metadata::read(&file).unwrap();
        let mut values = Vec::new();
        let mut invalid = copy(&original); invalid.xattrs = vec![(vec![], vec![])]; values.push(invalid);
        let mut invalid = copy(&original); invalid.xattrs = vec![(b"bad\0name".to_vec(), vec![])]; values.push(invalid);
        let mut invalid = copy(&original); invalid.xattrs = vec![(b"z".to_vec(), vec![]), (b"a".to_vec(), vec![])]; values.push(invalid);
        let mut invalid = copy(&original); invalid.xattrs = vec![(b"a".to_vec(), vec![]), (b"a".to_vec(), vec![])]; values.push(invalid);
        let mut invalid = copy(&original); invalid.xattrs = vec![(b"a".to_vec(), vec![0; 262144])]; values.push(invalid);
        let mut invalid = copy(&original); invalid.mode = 0o040700; values.push(invalid);
        let mut invalid = copy(&original); invalid.mode |= 0o2000000; values.push(invalid);
        let mut invalid = copy(&original); invalid.flags = if cfg!(target_os = "macos") { 2 } else { 0x10 }; values.push(invalid);
        #[cfg(target_os = "linux")]
        { let mut invalid = copy(&original); invalid.acl = Some(vec![]); values.push(invalid); }
        for invalid in values { assert!(invalid.apply(&file).is_err(), "accepted malformed metadata {invalid:?}"); assert_eq!(Metadata::read(&file).unwrap(), original); }
        let directory = File::from_std(std::fs::File::open(&temp.0).unwrap()); assert!(Metadata::read(&directory).is_err());
    }
}
