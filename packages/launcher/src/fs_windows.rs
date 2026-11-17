//! Windows mutations use handle-relative renames and captured security/streams.
//! Audit-security access is enabled only when already assigned to this token.
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_fs_ext::MetadataExt;
use cap_std::fs::{Dir, File, OpenOptions, OpenOptionsExt};
use serde::{Deserialize, Serialize};
use std::ffi::{c_void, OsStr};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;
use windows_sys::Wdk::Storage::FileSystem::{NtSetInformationFile, FILE_RENAME_INFORMATION, FileRenameInformation};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, RtlNtStatusToDosError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
use super::windows_metadata_policy::{validate_backup, validate_security, MAX_METADATA};

const READ_ACCESS: u32 = 0x80000000 | 0x00020000 | 0x01000000;
const WRITE_ACCESS: u32 = 0x80000000 | 0x40000000 | 0x00010000 | 0x00020000 | 0x00040000 | 0x00080000 | 0x01000000;
const SECURITY_FLAGS: u32 = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION;
const SAFE_ATTRIBUTES: u32 = FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_NORMAL;

fn bad(message: &str) -> io::Error { io::Error::new(io::ErrorKind::InvalidInput, message) }
fn error() -> io::Error { io::Error::last_os_error() }
fn handle(file: &File) -> HANDLE { file.as_raw_handle() }
fn aligned(bytes: &[u8]) -> Vec<u64> {
    let mut output = vec![0u64; bytes.len().div_ceil(8)];
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), output.as_mut_ptr().cast(), bytes.len()); }
    output
}

struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle { fn drop(&mut self) { unsafe { CloseHandle(self.0); } } }

pub fn enable_audit_access() -> io::Result<()> {
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) } == 0 { return Err(error()); }
    let token = OwnedHandle(token);
    let name: Vec<u16> = "SeSecurityPrivilege\0".encode_utf16().collect();
    let mut luid = Default::default();
    if unsafe { LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid) } == 0 { return Err(error()); }
    let mut privileges = TOKEN_PRIVILEGES::default();
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0] = LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED };
    if unsafe { AdjustTokenPrivileges(token.0, 0, &privileges, 0, std::ptr::null_mut(), std::ptr::null_mut()) } == 0 || unsafe { GetLastError() } == 1300 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "WINDOWS_SECURITY_ACCESS_REQUIRED: preserving audit ACLs requires SeSecurityPrivilege in the existing token"));
    }
    Ok(())
}

fn security(file: &File, all: bool) -> io::Result<Vec<u8>> {
    let flags = if all { SECURITY_FLAGS } else { OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION };
    let mut required = 0;
    unsafe { GetKernelObjectSecurity(handle(file), flags, std::ptr::null_mut(), 0, &mut required); }
    if required < 20 || (required as usize) > MAX_METADATA { return Err(bad("Windows security descriptor is unavailable or oversized")); }
    let mut buffer = vec![0u64; (required as usize).div_ceil(8)];
    if unsafe { GetKernelObjectSecurity(handle(file), flags, buffer.as_mut_ptr().cast(), required, &mut required) } == 0 { return Err(error()); }
    let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), required as usize) }.to_vec();
    validate_security(&bytes)?;
    Ok(bytes)
}

struct BackupContext { file: HANDLE, context: *mut c_void, write: bool }
impl BackupContext {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let mut used = 0;
        if unsafe { BackupRead(self.file, bytes.as_mut_ptr(), bytes.len() as u32, &mut used, 0, 0, &mut self.context) } == 0 { return Err(error()); }
        Ok(used as usize)
    }
    fn exact(&mut self, bytes: &mut [u8], allow_eof: bool) -> io::Result<bool> {
        let mut used = 0;
        while used < bytes.len() {
            let count = self.read(&mut bytes[used..])?;
            if count == 0 { return if used == 0 && allow_eof { Ok(false) } else { Err(bad("truncated Windows backup stream")) }; }
            used += count;
        }
        Ok(true)
    }
}
impl Drop for BackupContext {
    fn drop(&mut self) {
        let mut used = 0;
        unsafe {
            if self.write { BackupWrite(self.file, std::ptr::null(), 0, &mut used, 1, 0, &mut self.context); }
            else { BackupRead(self.file, std::ptr::null_mut(), 0, &mut used, 1, 0, &mut self.context); }
        }
    }
}

fn backup(file: &File) -> io::Result<Vec<u8>> {
    let mut context = BackupContext { file: handle(file), context: std::ptr::null_mut(), write: false };
    let mut output = Vec::new();
    let mut default_seen = false;
    loop {
        let mut header = [0u8; 20];
        if !context.exact(&mut header, true)? { break; }
        let id = u32::from_le_bytes(header[0..4].try_into().map_err(|_| bad("invalid stream"))?);
        let size = u64::from_le_bytes(header[8..16].try_into().map_err(|_| bad("invalid stream"))?);
        let names = u32::from_le_bytes(header[16..20].try_into().map_err(|_| bad("invalid stream"))?) as usize;
        if names > 65534 || names % 2 != 0 || size > super::MAX_FILE_SIZE { return Err(bad("Windows stream exceeds its bound")); }
        let mut name = vec![0; names]; context.exact(&mut name, false)?;
        if id == 1 {
            if default_seen || names != 0 { return Err(bad("invalid default Windows stream")); }
            default_seen = true;
            let mut low = 0; let mut high = 0;
            if unsafe { BackupSeek(context.file, size as u32, (size >> 32) as u32, &mut low, &mut high, &mut context.context) } == 0 || (u64::from(high) << 32 | u64::from(low)) != size { return Err(error()); }
            continue;
        }
        if size > MAX_METADATA as u64 || output.len() + 20 + names + (size as usize) > MAX_METADATA { return Err(bad("Windows metadata exceeds its bound")); }
        let mut data = vec![0; size as usize]; context.exact(&mut data, false)?;
        output.extend_from_slice(&header); output.extend_from_slice(&name); output.extend_from_slice(&data);
    }
    validate_backup(&output)?;
    Ok(output)
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedMetadata { security: Vec<u8>, backup: Vec<u8>, attributes: u32, creation_time: i64 }

impl CapturedMetadata {
    fn read(file: &File) -> io::Result<Self> {
        let mut basic = FILE_BASIC_INFO::default();
        if unsafe { GetFileInformationByHandleEx(handle(file), FileBasicInfo, (&mut basic as *mut FILE_BASIC_INFO).cast(), std::mem::size_of::<FILE_BASIC_INFO>() as u32) } == 0 { return Err(error()); }
        if basic.FileAttributes & !SAFE_ATTRIBUTES != 0 { return Err(bad("WINDOWS_FILE_ATTRIBUTES_UNSUPPORTED: readonly, encrypted, compressed, sparse or reparse metadata cannot be omitted")); }
        Ok(Self { security: security(file, true)?, backup: backup(file)?, attributes: basic.FileAttributes, creation_time: basic.CreationTime })
    }
    fn apply(&self, file: &File) -> io::Result<()> {
        validate_security(&self.security)?; validate_backup(&self.backup)?;
        if self.attributes & !SAFE_ATTRIBUTES != 0 || self.creation_time <= 0 { return Err(bad("invalid Windows file attributes")); }
        let security = aligned(&self.security);
        if unsafe { IsValidSecurityDescriptor(security.as_ptr().cast_mut().cast()) } == 0 { return Err(bad("invalid Windows security descriptor")); }
        let control = u16::from_le_bytes(self.security[2..4].try_into().map_err(|_| bad("invalid Windows security descriptor"))?);
        let flags = SECURITY_FLAGS | if control & SE_DACL_PROTECTED != 0 { PROTECTED_DACL_SECURITY_INFORMATION } else { UNPROTECTED_DACL_SECURITY_INFORMATION }
            | if control & SE_SACL_PROTECTED != 0 { PROTECTED_SACL_SECURITY_INFORMATION } else { UNPROTECTED_SACL_SECURITY_INFORMATION };
        if unsafe { SetKernelObjectSecurity(handle(file), flags, security.as_ptr().cast_mut().cast()) } == 0 { return Err(error()); }
        if !self.backup.is_empty() {
            let mut context = BackupContext { file: handle(file), context: std::ptr::null_mut(), write: true };
            let mut position = 0;
            while position < self.backup.len() {
                let mut used = 0;
                if unsafe { BackupWrite(context.file, self.backup[position..].as_ptr(), (self.backup.len() - position) as u32, &mut used, 0, 0, &mut context.context) } == 0 { return Err(error()); }
                if used == 0 { return Err(bad("Windows metadata write made no progress")); }
                position += used as usize;
            }
        }
        let basic = FILE_BASIC_INFO { CreationTime: self.creation_time, FileAttributes: self.attributes, ..Default::default() };
        if unsafe { SetFileInformationByHandle(handle(file), FileBasicInfo, (&basic as *const FILE_BASIC_INFO).cast(), std::mem::size_of::<FILE_BASIC_INFO>() as u32) } == 0 { return Err(error()); }
        if Self::read(file)? != *self { return Err(bad("Windows file metadata could not be preserved")); }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreservedFile {
    version: u32, source: String, backup: String, before_sha256: String,
    #[serde(with = "super::windows_transaction_policy::decimal_u64")]
    volume: u64,
    file_id: [u8; 16],
}
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Metadata { Captured(CapturedMetadata), Preserved { preserved_file: PreservedFile } }

struct Transaction { handle: OwnedHandle, committed: bool }
pub fn metadata_capability(parent: &Dir) -> io::Result<(bool, &'static str)> {
    match Transaction::new(parent) {
        Ok(_) => Ok((true, "transactional-ntfs-same-object")),
        Err(error) if error.kind() == io::ErrorKind::Unsupported => Ok((enable_audit_access().is_ok(), "privileged-security-and-stream-capture")),
        Err(error) => Err(error),
    }
}
impl Transaction {
    fn new(parent: &Dir) -> io::Result<Self> {
        let mut filesystem = [0u16; 32]; let mut flags = 0;
        if unsafe { GetVolumeInformationByHandleW(parent.as_raw_handle(), std::ptr::null_mut(), 0, std::ptr::null_mut(), std::ptr::null_mut(), &mut flags, filesystem.as_mut_ptr(), filesystem.len() as u32) } == 0 { return Err(error()); }
        let end = filesystem.iter().position(|value| *value == 0).unwrap_or(filesystem.len());
        if !super::windows_transaction_policy::supports_ntfs(&String::from_utf16_lossy(&filesystem[..end]), flags) { return Err(io::Error::new(io::ErrorKind::Unsupported, "WINDOWS_TRANSACTIONAL_NTFS_REQUIRED: same-object atomic publication is unavailable on this filesystem")); }
        let raw = unsafe { CreateTransaction(std::ptr::null_mut(), std::ptr::null_mut(), 0, 0, 0, 30_000, std::ptr::null()) };
        if raw == INVALID_HANDLE_VALUE || raw.is_null() { return Err(error()); }
        Ok(Self { handle: OwnedHandle(raw), committed: false })
    }
    fn commit(&mut self) -> io::Result<()> { if unsafe { CommitTransaction(self.handle.0) } == 0 { return Err(error()); } self.committed = true; Ok(()) }
}
impl Drop for Transaction { fn drop(&mut self) { if !self.committed { unsafe { RollbackTransaction(self.handle.0); } } } }
pub(super) fn file_identity(raw: HANDLE) -> io::Result<(u64, [u8; 16])> {
    let mut value = FILE_ID_INFO::default();
    if unsafe { GetFileInformationByHandleEx(raw, FileIdInfo, (&mut value as *mut FILE_ID_INFO).cast(), std::mem::size_of::<FILE_ID_INFO>() as u32) } == 0 { return Err(error()); }
    Ok((value.VolumeSerialNumber, value.FileId.Identifier))
}
fn final_path(parent: &Dir, name: &OsStr) -> io::Result<Vec<u16>> {
    let mut buffer = vec![0u16; 32768];
    let length = unsafe { GetFinalPathNameByHandleW(parent.as_raw_handle(), buffer.as_mut_ptr(), buffer.len() as u32, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) } as usize;
    if length == 0 || length >= buffer.len() { return Err(error()); } buffer.truncate(length);
    if !buffer.ends_with(&[b'\\' as u16]) { buffer.push(b'\\' as u16); } buffer.extend(name.encode_wide()); buffer.push(0); Ok(buffer)
}
fn plain_original(parent: &Dir, name: &OsStr, deletion: bool) -> io::Result<File> {
    let mut options = OpenOptions::new(); options.read(true).access_mode(0x80000000 | 0x20000 | if deletion { 0x10000 | 0x40000000 } else { 0 }).share_mode(1 | 2).follow(FollowSymlinks::No);
    let file = parent.open_with(name, &options)?; let info = file.metadata()?;
    if !info.is_file() || MetadataExt::nlink(&info) != 1 { return Err(bad("destination must be a regular file without hard links")); } Ok(file)
}
fn transacted_file(parent: &Dir, name: &OsStr, transaction: &Transaction, write: bool) -> io::Result<std::fs::File> {
    let raw = unsafe { CreateFileTransactedW(final_path(parent, name)?.as_ptr(), 0x80000000 | if write { 0x40000000 } else { 0 }, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, std::ptr::null(), OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, std::ptr::null_mut(), transaction.handle.0, std::ptr::null(), std::ptr::null()) };
    if raw == INVALID_HANDLE_VALUE { return Err(error()); } Ok(unsafe { std::fs::File::from_raw_handle(raw) })
}
fn replace_same_object(parent: &Dir, name: &OsStr, limit: u64, expected: &str, bytes: &[u8]) -> io::Result<()> {
    let source = plain_original(parent, name, false)?; let identity = file_identity(handle(&source))?;
    let mut transaction = Transaction::new(parent)?; let mut output = transacted_file(parent, name, &transaction, true)?;
    if file_identity(output.as_raw_handle())? != identity { return Err(io::Error::other("STALE_INPUT")); }
    let mut before = Vec::new(); Read::by_ref(&mut output).take(limit.saturating_add(1)).read_to_end(&mut before)?;
    if (before.len() as u64) > limit || super::hash(&before) != expected { return Err(io::Error::other("STALE_INPUT")); }
    let mut basic = FILE_BASIC_INFO::default();
    if unsafe { GetFileInformationByHandleEx(output.as_raw_handle(), FileBasicInfo, (&mut basic as *mut FILE_BASIC_INFO).cast(), std::mem::size_of::<FILE_BASIC_INFO>() as u32) } == 0 { return Err(error()); }
    if basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 { return Err(bad("reparse-point output is forbidden")); }
    output.seek(SeekFrom::Start(0))?; output.write_all(bytes)?; output.set_len(bytes.len() as u64)?;
    let preserved = FILE_BASIC_INFO { CreationTime: basic.CreationTime, FileAttributes: basic.FileAttributes, ..Default::default() };
    if unsafe { SetFileInformationByHandle(output.as_raw_handle(), FileBasicInfo, (&preserved as *const FILE_BASIC_INFO).cast(), std::mem::size_of::<FILE_BASIC_INFO>() as u32) } == 0 { return Err(error()); }
    output.sync_all()?;
    // TxF invalidates transacted handles at commit. Keep the ordinary original
    // handle (which denies delete sharing) for the committed identity check.
    drop(output); transaction.commit()?;
    if file_identity(handle(&source))? != identity || super::hash(&super::read_file(parent.try_clone()?, Path::new(name), limit)?) != super::hash(bytes) { return Err(io::Error::other("WINDOWS_COMMITTED_DATA_UNVERIFIED")); }
    Ok(())
}

fn parent(dir: Dir, path: &Path) -> io::Result<(Dir, std::ffi::OsString)> {
    let mut parts = super::components(path, false)?;
    let name = parts.pop().ok_or_else(|| bad("missing filename"))?;
    Ok((super::open_directory(dir, &parts)?, name))
}
fn original(parent: &Dir, name: &OsStr, deletion: bool) -> io::Result<File> {
    enable_audit_access()?;
    let mut options = OpenOptions::new();
    options.read(true).access_mode(READ_ACCESS | if deletion { 0x10000 | 0x40000000 } else { 0 }).share_mode(1 | 2).follow(FollowSymlinks::No);
    let file = parent.open_with(name, &options)?;
    let info = file.metadata()?;
    if !info.is_file() || MetadataExt::nlink(&info) != 1 { return Err(bad("destination must be a regular file without hard links")); }
    Ok(file)
}
fn temporary(parent: &Dir, security: bool) -> io::Result<(String, File)> {
    for attempt in 0..100 {
        let name = format!(".ud-agent-{}-{attempt}.tmp", std::process::id());
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true).access_mode(if security { WRITE_ACCESS } else { 0x80000000 | 0x40000000 | 0x10000 }).share_mode(1 | 2 | 4).follow(FollowSymlinks::No);
        match parent.open_with(&name, &options) {
            Ok(file) => return Ok((name, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(bad("temporary filename exhaustion"))
}
fn rename(file: &File, parent: &Dir, name: &OsStr, replace: bool) -> io::Result<()> {
    let name: Vec<u16> = name.encode_wide().collect();
    let offset = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName);
    let size = std::mem::size_of::<FILE_RENAME_INFORMATION>() + name.len() * 2;
    let mut buffer = vec![0u64; size.div_ceil(8)];
    let pointer = buffer.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    let mut completion = IO_STATUS_BLOCK::default();
    unsafe {
        (*pointer).Anonymous.ReplaceIfExists = replace;
        (*pointer).RootDirectory = parent.as_raw_handle();
        (*pointer).FileNameLength = (name.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(name.as_ptr(), buffer.as_mut_ptr().cast::<u8>().add(offset).cast(), name.len());
        // The native API consumes the parent handle directly, without the
        // Win32 rename wrapper's path translation. Never fall back to a name
        // resolved outside the held parent capability. These handles are
        // synchronous; every non-success status remains a failed mutation.
        let status = NtSetInformationFile(handle(file), &mut completion, pointer.cast(), size as u32, FileRenameInformation);
        if status != 0 { return Err(io::Error::from_raw_os_error(RtlNtStatusToDosError(status) as i32)); }
    }
    file.sync_all()
}
fn reopen_directory_for_rename(parent: &Dir, old: &str, expected: (u64, [u8; 16])) -> io::Result<File> {
    let mut options = OpenOptions::new(); options.read(true).access_mode(0x80000000 | 0x40000000 | 0x10000).share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE).custom_flags(FILE_FLAG_BACKUP_SEMANTICS).follow(FollowSymlinks::No);
    let directory = parent.open_with(old, &options)?;
    if !directory.metadata()?.is_dir() || file_identity(handle(&directory))? != expected { return Err(io::Error::other("OWNED_DIRECTORY_CHANGED")); }
    Ok(directory)
}
pub fn rename_directory_exclusive(parent: &Dir, directory: Dir, old: &str, new: &OsStr) -> io::Result<super::Identity> {
    let identity = super::identity(&directory)?;
    let expected = file_identity(directory.as_raw_handle())?;
    // cap-std directory handles deny delete sharing. Release that handle
    // before requesting DELETE, then bind the replacement handle to the full
    // original file ID before any mutation. A substituted entry is untouched.
    drop(directory);
    let directory = reopen_directory_for_rename(parent, old, expected)?;
    rename(&directory, parent, new, false)?;
    if file_identity(handle(&directory))? != expected { return Err(io::Error::other("OWNED_DIRECTORY_CHANGED")); }
    Ok(identity)
}

pub fn metadata_file(dir: Dir, path: &Path, limit: u64, expected: &str) -> io::Result<Metadata> {
    let (parent, name) = parent(dir, path)?;
    flush_directory(parent.try_clone()?)?;
    let transaction = match Transaction::new(&parent) { Ok(value) => Some(value), Err(unsupported) if unsupported.kind() == io::ErrorKind::Unsupported => None, Err(error) => return Err(error) };
    if let Some(transaction) = transaction {
        let source = plain_original(&parent, &name, false)?; let (volume, file_id) = file_identity(handle(&source))?;
        let opened = transacted_file(&parent, &name, &transaction, false)?;
        if file_identity(opened.as_raw_handle())? != (volume, file_id) || super::hash(&super::read_file(parent.try_clone()?, Path::new(&name), limit)?) != expected { return Err(io::Error::other("STALE_INPUT")); }
        let source_name = path.to_str().ok_or_else(|| bad("Windows transaction path is not Unicode"))?.replace('\\', "/");
        let nonce = format!("{}:{}:{}:{}", source_name, expected, std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|_| bad("invalid clock"))?.as_nanos());
        let backup_name = format!(".ud-agent-original-{}", super::hash(nonce.as_bytes()));
        let backup_path = path.parent().unwrap_or_else(|| Path::new("")).join(backup_name);
        return Ok(Metadata::Preserved { preserved_file: PreservedFile { version: 1, source: source_name, backup: backup_path.to_str().ok_or_else(|| bad("invalid backup path"))?.replace('\\', "/"), before_sha256: expected.to_owned(), volume, file_id } });
    }
    let file = original(&parent, &name, false)?;
    let metadata = CapturedMetadata::read(&file)?;
    if super::hash(&super::read_file(parent.try_clone()?, Path::new(&name), limit)?) != expected || CapturedMetadata::read(&file)? != metadata { return Err(io::Error::other("STALE_INPUT")); }
    Ok(Metadata::Captured(metadata))
}
pub fn replace_file(dir: Dir, path: &Path, limit: u64, expected: &str, bytes: &[u8]) -> io::Result<()> {
    if limit > super::MAX_FILE_SIZE || (bytes.len() as u64) > limit { return Err(bad("replacement exceeds permitted limit")); }
    let (parent, name) = parent(dir, path)?;
    match Transaction::new(&parent) { Ok(_) => return replace_same_object(&parent, &name, limit, expected, bytes), Err(unsupported) if unsupported.kind() == io::ErrorKind::Unsupported => (), Err(error) => return Err(error) }
    flush_directory(parent.try_clone()?)?;
    let source = original(&parent, &name, false)?;
    let before = source.metadata()?;
    let metadata = CapturedMetadata::read(&source)?;
    if super::hash(&super::read_file(parent.try_clone()?, Path::new(&name), limit)?) != expected { return Err(io::Error::other("STALE_INPUT")); }
    let (temp, mut output) = temporary(&parent, true)?;
    let result = (|| {
        output.write_all(bytes)?; metadata.apply(&output)?; output.sync_all()?;
        let current = parent.symlink_metadata(&name)?;
        if !current.is_file() || MetadataExt::dev(&current) != MetadataExt::dev(&before) || MetadataExt::ino(&current) != MetadataExt::ino(&before) || CapturedMetadata::read(&source)? != metadata
            || super::hash(&super::read_file(parent.try_clone()?, Path::new(&name), limit)?) != expected { return Err(io::Error::other("STALE_INPUT")); }
        drop(source);
        rename(&output, &parent, &name, true)?;
        flush_directory(parent.try_clone()?)
    })();
    drop(output);
    if result.is_err() { let _ = parent.remove_file(temp); }
    result
}
pub fn create_file(dir: Dir, path: &Path, limit: u64, bytes: &[u8], metadata: Option<Metadata>) -> io::Result<()> {
    if limit > super::MAX_FILE_SIZE || (bytes.len() as u64) > limit { return Err(bad("creation exceeds permitted limit")); }
    let metadata = match metadata { Some(Metadata::Preserved { preserved_file }) => return restore_preserved(dir, path, limit, bytes, &preserved_file), Some(Metadata::Captured(value)) => Some(value), None => None };
    if metadata.is_some() { enable_audit_access()?; }
    let (parent, name) = parent(dir, path)?;
    flush_directory(parent.try_clone()?)?;
    let (temp, mut output) = temporary(&parent, metadata.is_some())?;
    let result = (|| { output.write_all(bytes)?; if let Some(metadata) = metadata { metadata.apply(&output)?; } output.sync_all()?; rename(&output, &parent, &name, false)?; flush_directory(parent.try_clone()?) })();
    drop(output);
    if result.is_err() { let _ = parent.remove_file(temp); }
    result
}
fn preserved_paths(dir: &Dir, path: &Path, metadata: &PreservedFile) -> io::Result<(Dir, std::ffi::OsString, std::ffi::OsString)> {
    super::windows_transaction_policy::validate_preserved(&metadata.source, &metadata.backup, &metadata.before_sha256)?;
    if metadata.version != 1 || metadata.before_sha256.len() != 64 || !metadata.before_sha256.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()) || metadata.source != path.to_str().ok_or_else(|| bad("invalid recovery path"))?.replace('\\', "/") { return Err(bad("invalid preserved-file recovery authority")); }
    let (parent, name) = parent(dir.try_clone()?, path)?;
    let backup = Path::new(&metadata.backup); let backup_name = backup.file_name().ok_or_else(|| bad("invalid backup filename"))?;
    let suffix = backup_name.to_str().and_then(|value| value.strip_prefix(".ud-agent-original-")).ok_or_else(|| bad("invalid backup filename"))?;
    if suffix.len() != 64 || !suffix.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()) || backup.parent() != path.parent() { return Err(bad("backup must remain in its original confined parent")); }
    Ok((parent, name, backup_name.to_owned()))
}
fn verify_preserved(file: &std::fs::File, metadata: &PreservedFile, limit: u64) -> io::Result<()> {
    if file_identity(file.as_raw_handle())? != (metadata.volume, metadata.file_id) { return Err(io::Error::other("WINDOWS_RECOVERY_FILE_ID_CHANGED")); }
    let mut cloned = file.try_clone()?; cloned.seek(SeekFrom::Start(0))?; let mut bytes = Vec::new(); Read::by_ref(&mut cloned).take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    if (bytes.len() as u64) > limit || super::hash(&bytes) != metadata.before_sha256 { return Err(io::Error::other("WINDOWS_RECOVERY_BYTES_CHANGED")); } Ok(())
}
pub fn remove_preserved(dir: Dir, path: &Path, limit: u64, expected: &str, metadata: Metadata) -> io::Result<()> {
    let preserved = match metadata { Metadata::Preserved { preserved_file } => preserved_file, Metadata::Captured(_) => return remove_file(dir, path, limit, expected) };
    if expected != preserved.before_sha256 { return Err(bad("preserved deletion fingerprint differs")); }
    let (parent, name, backup) = preserved_paths(&dir, path, &preserved)?;
    let original = plain_original(&parent, &name, true)?; if file_identity(handle(&original))? != (preserved.volume, preserved.file_id) { return Err(io::Error::other("STALE_INPUT")); } drop(original);
    let mut transaction = Transaction::new(&parent)?; let opened = transacted_file(&parent, &name, &transaction, false)?; verify_preserved(&opened, &preserved, limit)?;
    if unsafe { MoveFileTransactedW(final_path(&parent, &name)?.as_ptr(), final_path(&parent, &backup)?.as_ptr(), None, std::ptr::null(), 0, transaction.handle.0) } == 0 { return Err(error()); }
    let moved = transacted_file(&parent, &backup, &transaction, false)?; verify_preserved(&moved, &preserved, limit)?; transaction.commit()
}
fn restore_preserved(dir: Dir, path: &Path, limit: u64, bytes: &[u8], metadata: &PreservedFile) -> io::Result<()> {
    if super::hash(bytes) != metadata.before_sha256 { return Err(bad("recovery bytes differ from original object")); }
    let (parent, name, backup) = preserved_paths(&dir, path, metadata)?;
    let original = plain_original(&parent, &backup, true)?; if file_identity(handle(&original))? != (metadata.volume, metadata.file_id) { return Err(io::Error::other("WINDOWS_RECOVERY_FILE_ID_CHANGED")); } drop(original);
    let mut transaction = Transaction::new(&parent)?; let opened = transacted_file(&parent, &backup, &transaction, false)?; verify_preserved(&opened, metadata, limit)?;
    if unsafe { MoveFileTransactedW(final_path(&parent, &backup)?.as_ptr(), final_path(&parent, &name)?.as_ptr(), None, std::ptr::null(), 0, transaction.handle.0) } == 0 { return Err(error()); }
    let moved = transacted_file(&parent, &name, &transaction, false)?; verify_preserved(&moved, metadata, limit)?; transaction.commit()
}
pub fn release_metadata(dir: Dir, path: &Path, limit: u64, metadata: Metadata) -> io::Result<()> {
    let preserved = match metadata { Metadata::Preserved { preserved_file } => preserved_file, Metadata::Captured(_) => return Ok(()) };
    let (parent, _, backup) = preserved_paths(&dir, path, &preserved)?;
    match parent.symlink_metadata(&backup) { Ok(_) => (), Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()), Err(error) => return Err(error) }
    let original = plain_original(&parent, &backup, true)?; if file_identity(handle(&original))? != (preserved.volume, preserved.file_id) { return Err(io::Error::other("WINDOWS_RECOVERY_FILE_ID_CHANGED")); } drop(original);
    let mut transaction = Transaction::new(&parent)?; let opened = transacted_file(&parent, &backup, &transaction, false)?; verify_preserved(&opened, &preserved, limit)?;
    if unsafe { DeleteFileTransactedW(final_path(&parent, &backup)?.as_ptr(), transaction.handle.0) } == 0 { return Err(error()); } transaction.commit()
}
pub fn remove_file(dir: Dir, path: &Path, limit: u64, expected: &str) -> io::Result<()> {
    let (parent, name) = parent(dir, path)?;
    flush_directory(parent.try_clone()?)?;
    let source = plain_original(&parent, &name, true)?;
    if super::hash(&super::read_file(parent.try_clone()?, Path::new(&name), limit)?) != expected { return Err(io::Error::other("STALE_INPUT")); }
    source.sync_all()?;
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    if unsafe { SetFileInformationByHandle(handle(&source), FileDispositionInfo, (&disposition as *const FILE_DISPOSITION_INFO).cast(), std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32) } == 0 { return Err(error()); }
    drop(source);
    flush_parent(parent, Path::new(&name))
}
pub fn flush_parent(dir: Dir, path: &Path) -> io::Result<()> {
    let (parent, _) = parent(dir, path)?;
    flush_directory(parent)
}
pub fn flush_directory(parent: Dir) -> io::Result<()> {
    let mut options = OpenOptions::new(); options.read(true).access_mode(0x80000000 | 0x40000000).custom_flags(FILE_FLAG_BACKUP_SEMANTICS).follow(FollowSymlinks::No);
    parent.open_with(".", &options)?.sync_all()
}

fn current_sid() -> io::Result<Vec<u8>> {
    let mut raw = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 { return Err(error()); }
    let token = OwnedHandle(raw);
    let mut length = 0;
    unsafe { GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut length); }
    if length == 0 || length > 4096 { return Err(bad("invalid Windows token identity")); }
    let mut storage = vec![0u64; (length as usize).div_ceil(8)];
    if unsafe { GetTokenInformation(token.0, TokenUser, storage.as_mut_ptr().cast(), length, &mut length) } == 0 { return Err(error()); }
    let token_user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
    if unsafe { IsValidSid(token_user.User.Sid) } == 0 { return Err(bad("invalid Windows token SID")); }
    let size = unsafe { GetLengthSid(token_user.User.Sid) } as usize;
    if !(8..=68).contains(&size) { return Err(bad("invalid Windows token SID")); }
    Ok(unsafe { std::slice::from_raw_parts(token_user.User.Sid.cast::<u8>(), size) }.to_vec())
}
fn sid_at(descriptor: &[u8], offset: usize) -> io::Result<&[u8]> {
    let header = descriptor.get(offset..offset + 8).ok_or_else(|| bad("invalid SID"))?;
    descriptor.get(offset..offset + 8 + header[1] as usize * 4).ok_or_else(|| bad("invalid SID"))
}
fn private_security(descriptor: &[u8], caller: &[u8]) -> io::Result<bool> {
    validate_security(descriptor)?;
    let offset = |field| -> usize { u32::from_le_bytes(descriptor[field..field + 4].try_into().unwrap()) as usize };
    let owner = offset(4);
    if owner == 0 || sid_at(descriptor, owner)? != caller { return Err(io::Error::new(io::ErrorKind::PermissionDenied, "Windows state must be owned by the current user")); }
    let dacl = offset(16);
    if dacl == 0 { return Ok(false); }
    let count = u16::from_le_bytes(descriptor[dacl + 4..dacl + 6].try_into().unwrap()) as usize;
    let system = [1u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    let admins = [1u8, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];
    let mut next = dacl + 8;
    let mut caller_full = false;
    for _ in 0..count {
        let size = u16::from_le_bytes(descriptor[next + 2..next + 4].try_into().unwrap()) as usize;
        let kind = descriptor[next];
        let sid = sid_at(descriptor, next + 8)?;
        if kind == 0 {
            if sid != caller && sid != system && sid != admins { return Ok(false); }
            let mask = u32::from_le_bytes(descriptor[next + 4..next + 8].try_into().unwrap());
            if sid == caller && (mask & 0x10000000 != 0 || mask & 0x1f01ff == 0x1f01ff) { caller_full = true; }
        } else if kind != 1 { return Ok(false); }
        next += size;
    }
    Ok(caller_full)
}
pub fn verify_private_file(file: &File) -> io::Result<()> {
    if !private_security(&security(file, false)?, &current_sid()?)? { return Err(io::Error::new(io::ErrorKind::PermissionDenied, "WINDOWS_STATE_ACL_UNVERIFIED: state permits another principal")); }
    Ok(())
}
pub fn verify_private_target(dir: Dir, path: &Path) -> io::Result<()> {
    let (parent, name) = parent(dir, path)?;
    let mut options = OpenOptions::new(); options.read(true).access_mode(0x80000000 | 0x20000).follow(FollowSymlinks::No);
    let file = parent.open_with(name, &options)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || MetadataExt::nlink(&metadata) != 1 { return Err(bad("private state must be a regular file without hard links")); }
    verify_private_file(&file)
}
pub fn private_state(dir: &Dir, initialize: bool) -> io::Result<()> {
    let file = File::from_std(dir.try_clone()?.into_std_file());
    let caller = current_sid()?;
    let descriptor = security(&file, false)?;
    if private_security(&descriptor, &caller)? { return Ok(()); }
    if !initialize { return Err(io::Error::new(io::ErrorKind::PermissionDenied, "WINDOWS_STATE_ACL_UNVERIFIED: state permits another principal")); }
    if dir.entries()?.next().is_some() { return Err(io::Error::new(io::ErrorKind::PermissionDenied, "WINDOWS_STATE_ACL_UNVERIFIED: refusing to change a nonempty state directory")); }
    // Initialize only an empty user-owned directory; existing state is never
    // made private by silently rewriting permissions around unknown contents.
    let system = [1u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    let mut sd = vec![0u8; 20]; sd[0] = 1; sd[2..4].copy_from_slice(&(0x8000u16 | 0x1000 | 4).to_le_bytes());
    sd[4..8].copy_from_slice(&20u32.to_le_bytes()); sd.extend_from_slice(&caller);
    while sd.len() % 4 != 0 { sd.push(0); }
    let offset = sd.len(); sd[16..20].copy_from_slice(&(offset as u32).to_le_bytes());
    let mut acl = vec![2u8, 0, 0, 0, 2, 0, 0, 0];
    for sid in [&caller[..], &system[..]] {
        acl.extend_from_slice(&[0, 3]); acl.extend_from_slice(&((8 + sid.len()) as u16).to_le_bytes()); acl.extend_from_slice(&0x1f01ffu32.to_le_bytes()); acl.extend_from_slice(sid);
    }
    let size = acl.len() as u16; acl[2..4].copy_from_slice(&size.to_le_bytes()); sd.extend_from_slice(&acl); validate_security(&sd)?;
    let storage = aligned(&sd);
    let mut options = OpenOptions::new(); options.read(true).access_mode(0x20000 | 0x40000).follow(FollowSymlinks::No);
    let writable = dir.open_with(".", &options)?;
    if unsafe { SetKernelObjectSecurity(handle(&writable), DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, storage.as_ptr().cast_mut().cast()) } == 0 { return Err(error()); }
    verify_private_file(&writable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cap_fs_ext::DirExt;
    #[test]
    fn directory_reopen_rejects_a_replacement_before_renaming() {
        let root = std::env::temp_dir().join(format!("ud-owned-reopen-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir(&root).unwrap();
        let parent = Dir::open_ambient_dir(&root, cap_std::ambient_authority()).unwrap();
        parent.create_dir("staging").unwrap();
        let admitted = parent.open_dir_nofollow("staging").unwrap();
        let expected = file_identity(admitted.as_raw_handle()).unwrap();
        drop(admitted);
        // Retain the original inode so replacement cannot accidentally reuse it.
        parent.rename("staging", &parent, "retained").unwrap();
        parent.create_dir("staging").unwrap();
        parent.write("staging/foreign", b"unchanged").unwrap();
        let rejected = reopen_directory_for_rename(&parent, "staging", expected).unwrap_err();
        assert!(rejected.to_string().contains("OWNED_DIRECTORY_CHANGED"));
        assert_eq!(parent.read("staging/foreign").unwrap(), b"unchanged");
        assert!(parent.is_dir("retained"));
        let original = reopen_directory_for_rename(&parent, "retained", expected).unwrap();
        rename(&original, &parent, OsStr::new("published"), false).unwrap();
        assert_eq!(file_identity(handle(&original)).unwrap(), expected);
        drop(original); drop(parent);
        std::fs::remove_dir_all(root).unwrap();
    }
}
