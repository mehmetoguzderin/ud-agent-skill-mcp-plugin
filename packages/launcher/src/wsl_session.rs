//! Owned WSL Containers session using the pinned Microsoft SDK C ABI.
//! ABI source: microsoft/WSL 19cd15ea579fe09e29fcef8d9b947a588da3a765.
use std::collections::BTreeMap;
use std::ffi::{c_void, OsString};
use std::io::{self, Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use windows_sys::Win32::Foundation::{CloseHandle, FreeLibrary, HMODULE, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Com::{CoInitializeEx, CoTaskMemFree, CoUninitialize, COINIT_MULTITHREADED};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32};
use windows_sys::Win32::System::Threading::WaitForSingleObject;
use windows_sys::Win32::System::Threading::{CreateEventW, SetEvent, WaitForMultipleObjects};
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt, MetadataExt};
use cap_std::fs::{OpenOptions, OpenOptionsExt};

#[repr(C, align(8))]
// Microsoft.WSL.Containers 3.0.3 include/wslcsdk.h: size 72, alignment 8.
struct Settings([u8; 72]);
type Session = *mut c_void;
type HResult = i32;
type Init = unsafe extern "system" fn(*const u16, *const u16, *mut Settings) -> HResult;
type Set = unsafe extern "system" fn(*mut Settings, u32) -> HResult;
type Create = unsafe extern "system" fn(*mut Settings, *mut Session, *mut *mut u16) -> HResult;
type Action = unsafe extern "system" fn(Session) -> HResult;
type Event = unsafe extern "system" fn(Session, *mut HANDLE) -> HResult;
type Missing = unsafe extern "system" fn(*mut u32) -> HResult;
fn check(result: HResult) -> io::Result<()> { if result < 0 { Err(io::Error::other(format!("WSLC_NATIVE_FAILURE: {result:#010x}"))) } else { Ok(()) } }
struct Library(HMODULE);
impl Drop for Library { fn drop(&mut self) { unsafe { FreeLibrary(self.0); } } }
impl Library {
    unsafe fn function<T: Copy>(&self, name: &'static [u8]) -> io::Result<T> {
        let address = unsafe { GetProcAddress(self.0, name.as_ptr()) }.ok_or_else(|| io::Error::other("WSLC_SDK_UPDATE_REQUIRED"))?;
        if std::mem::size_of::<T>() != std::mem::size_of_val(&address) { return Err(super::fail("invalid WSL SDK function ABI")); }
        Ok(unsafe { std::mem::transmute_copy(&address) })
    }
}
struct Com;
impl Drop for Com { fn drop(&mut self) { unsafe { CoUninitialize(); } } }
struct Owned { session: Session, terminate: Action, release: Action }
impl Drop for Owned { fn drop(&mut self) { unsafe { (self.terminate)(self.session); (self.release)(self.session); } } }
fn wide(value: &std::ffi::OsStr) -> Vec<u16> { value.encode_wide().chain(Some(0)).collect() }

pub fn run(arguments: Vec<OsString>) -> io::Result<()> {
    let mut values = BTreeMap::new(); let mut iter = arguments.into_iter();
    while let Some(key) = iter.next() {
        let key = key.into_string().map_err(|_| super::fail("invalid WSL session option"))?;
        let value = iter.next().ok_or_else(|| super::fail("missing WSL session value"))?;
        if !["--sdk", "--sdk-sha256", "--storage", "--name"].contains(&key.as_str()) || values.insert(key, value).is_some() { return Err(super::fail("unknown or repeated WSL session option")); }
    }
    if values.len() != 4 { return Err(super::fail("incomplete WSL session authority")); }
    let sdk = PathBuf::from(&values["--sdk"]); let storage = PathBuf::from(&values["--storage"]);
    let expected = values["--sdk-sha256"].to_str().ok_or_else(|| super::fail("invalid SDK hash"))?;
    let _pinned = super::windows_job::pinned(&sdk, expected, 256 * 1024 * 1024)?;
    let state = super::absolute_root(&storage)?;
    super::fs_windows::private_state(&state, true)?;
    let name = values["--name"].to_str().ok_or_else(|| super::fail("invalid WSL session name"))?;
    if !name.starts_with("ud-agent-") || name.len() != 45 || !name[9..].bytes().all(|value| value.is_ascii_hexdigit() || value == b'-') { return Err(super::fail("invalid owned WSL session name")); }
    let mut lock_options = OpenOptions::new(); lock_options.read(true).write(true).create(true).share_mode(0).follow(FollowSymlinks::No);
    let _session_lock = state.open_with(format!(".session-{name}.native"), &lock_options)?;
    if !_session_lock.metadata()?.is_file() || MetadataExt::nlink(&_session_lock.metadata()?) != 1 { return Err(super::fail("invalid WSL session ownership lock")); }
    super::fs_windows::verify_private_file(&_session_lock)?;
    check(unsafe { CoInitializeEx(std::ptr::null(), COINIT_MULTITHREADED as u32) })?; let _com = Com;
    let module = unsafe { LoadLibraryExW(wide(sdk.as_os_str()).as_ptr(), std::ptr::null_mut(), LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32) };
    if module.is_null() { return Err(io::Error::last_os_error()); } let library = Library(module);
    let init: Init = unsafe { library.function(b"WslcInitSessionSettings\0")? };
    let cpu: Set = unsafe { library.function(b"WslcSetSessionSettingsCpuCount\0")? };
    let memory: Set = unsafe { library.function(b"WslcSetSessionSettingsMemory\0")? };
    let timeout: Set = unsafe { library.function(b"WslcSetSessionSettingsTimeout\0")? };
    let missing: Missing = unsafe { library.function(b"WslcGetMissingComponents\0")? };
    let create: Create = unsafe { library.function(b"WslcCreateSession\0")? };
    let terminate: Action = unsafe { library.function(b"WslcTerminateSession\0")? };
    let release: Action = unsafe { library.function(b"WslcReleaseSession\0")? };
    let event: Event = unsafe { library.function(b"WslcGetSessionTerminationEvent\0")? };
    let mut absent = 0; check(unsafe { missing(&mut absent) })?;
    if absent != 0 { return Err(io::Error::other(format!("WSLC_ADMIN_PREREQUISITES_REQUIRED: {absent:#x}"))); }
    let mut settings = Settings([0; 72]);
    check(unsafe { init(wide(&values["--name"]).as_ptr(), wide(storage.as_os_str()).as_ptr(), &mut settings) })?;
    check(unsafe { cpu(&mut settings, 2) })?; check(unsafe { memory(&mut settings, 2048) })?; check(unsafe { timeout(&mut settings, 300_000) })?;
    let mut session = std::ptr::null_mut(); let mut error_message = std::ptr::null_mut();
    let created = unsafe { create(&mut settings, &mut session, &mut error_message) };
    if !error_message.is_null() { unsafe { CoTaskMemFree(error_message.cast()); } }
    check(created)?;
    if session.is_null() { return Err(io::Error::other("WSLC_SESSION_HANDLE_INVALID")); }
    let owned = Owned { session, terminate, release }; let mut termination = std::ptr::null_mut();
    check(unsafe { event(session, &mut termination) })?;
    if termination.is_null() { return Err(io::Error::other("WSLC_TERMINATION_EVENT_INVALID")); }
    serde_json::to_writer(io::stdout().lock(), &serde_json::json!({"schema_version":1,"ready":true,"session":name,"cpu_count":2,"memory_mb":2048,"rootless":null}))?;
    io::stdout().lock().write_all(b"\n")?; io::stdout().lock().flush()?;
    struct Signal(HANDLE);
    unsafe impl Send for Signal {} unsafe impl Sync for Signal {}
    impl Drop for Signal { fn drop(&mut self) { unsafe { CloseHandle(self.0); } } }
    let control = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) }; if control.is_null() { return Err(io::Error::last_os_error()); }
    let control = std::sync::Arc::new(Signal(control)); let writer = control.clone();
    let input = std::sync::Arc::new(std::sync::Mutex::new(None)); let received = input.clone();
    std::thread::spawn(move || { let mut byte = [0u8; 1]; let result = io::stdin().lock().read(&mut byte); *received.lock().unwrap() = Some(result); unsafe { SetEvent(writer.0); } });
    let events = [termination, control.0];
    let trigger = unsafe { WaitForMultipleObjects(2, events.as_ptr(), 0, u32::MAX) };
    let (terminated, waited) = if trigger == WAIT_OBJECT_0 { (Ok(()), WAIT_OBJECT_0) } else if trigger == WAIT_OBJECT_0 + 1 { (check(unsafe { terminate(session) }), unsafe { WaitForSingleObject(termination, 30_000) }) } else { return Err(io::Error::last_os_error()); };
    unsafe { CloseHandle(termination); }
    // Drop still retries termination on all error branches before release.
    terminated?; if waited != WAIT_OBJECT_0 { return Err(io::Error::other("WSLC_SESSION_CLEANUP_UNVERIFIED")); }
    if trigger == WAIT_OBJECT_0 + 1 { if input.lock().unwrap().take().ok_or_else(|| super::fail("missing WSL control outcome"))?? != 0 { return Err(super::fail("WSL control pipe accepts only EOF")); } }
    drop(owned); Ok(())
}
