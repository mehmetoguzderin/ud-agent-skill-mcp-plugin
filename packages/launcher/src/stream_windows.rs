use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::windows::io::FromRawHandle;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
use super::Options;
use super::super::windows_job::{Handle, launch_process, pinned, reap};
type Pipes = (Box<dyn Write + Send>, Box<dyn Read + Send>, Box<dyn Read + Send>);
pub(super) struct Process { job: Handle, child: Handle, handles: Option<Pipes>, finished: bool, _pinned: cap_std::fs::File }
fn pipe(child_read: bool) -> io::Result<(File, Handle)> {
    let mut read = std::ptr::null_mut(); let mut write = std::ptr::null_mut(); let security = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: std::ptr::null_mut(), bInheritHandle: 1 };
    if unsafe { CreatePipe(&mut read, &mut write, &security, 65536) } == 0 { return Err(io::Error::last_os_error()); }
    let read = Handle(read); let write = Handle(write); let (parent, child) = if child_read { (write, read) } else { (read, write) };
    if unsafe { SetHandleInformation(parent.0, HANDLE_FLAG_INHERIT, 0) } == 0 { return Err(io::Error::last_os_error()); }
    let file = unsafe { File::from_raw_handle(parent.0) }; std::mem::forget(parent); Ok((file, child))
}
pub(super) fn spawn(options: &Options) -> io::Result<Process> {
    let pinned = pinned(&options.executable, &options.expected, 512 * 1024 * 1024)?;
    let (parent_input, input) = pipe(true)?; let (parent_output, output) = pipe(false)?; let (parent_error, error) = pipe(false)?;
    let arguments = std::iter::once(options.executable.as_os_str().to_os_string()).chain(options.arguments.iter().map(OsString::from)).collect::<Vec<_>>();
    let (job, child) = launch_process(&options.executable, &arguments, &std::env::current_dir()?, [input.0, output.0, error.0])?;
    drop(input); drop(output); drop(error);
    Ok(Process { job, child, handles: Some((Box::new(parent_input), Box::new(parent_output), Box::new(parent_error))), finished: false, _pinned: pinned })
}
impl Process {
    pub(super) fn pipes(&mut self) -> io::Result<Pipes> { self.handles.take().ok_or_else(|| super::super::fail("stream pipes already transferred")) }
    pub(super) fn exited(&mut self) -> io::Result<bool> { match unsafe { WaitForSingleObject(self.child.0, 0) } { WAIT_OBJECT_0 => Ok(true), WAIT_TIMEOUT => Ok(false), _ => Err(io::Error::last_os_error()) } }
    pub(super) fn finish(&mut self) -> io::Result<(Option<i64>, Option<i32>)> { let mut code = 0; if unsafe { GetExitCodeProcess(self.child.0, &mut code) } == 0 { return Err(io::Error::last_os_error()); } reap(self.job.0)?; if code == 259 && unsafe { GetExitCodeProcess(self.child.0, &mut code) } == 0 { return Err(io::Error::last_os_error()); } self.finished = true; Ok((Some(i64::from(code)), None)) }
}
impl Drop for Process { fn drop(&mut self) { if !self.finished { let _ = reap(self.job.0); } } }
