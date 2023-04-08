use std::{
    io,
    os::windows::prelude::{AsRawHandle, RawHandle},
};

/// The raw underlying handle to a process.
pub type RawProcessHandle = RawHandle;

/// A handle to a process.
pub trait ProcessHandle: AsRawHandle + FromRawProcessHandle {
    /// Trys to clone this process handle.
    fn try_clone(&self) -> io::Result<Self>
    where
        Self: Sized,
    {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// Construct objects from raw process handles.
pub trait FromRawProcessHandle: Sized {
    /// Constructs a new handle instance from the given raw process handle.
    ///
    /// # Safety
    /// The caller must ensure that the handle is a valid process handle and has the required [privileges](https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights):
    ///  - `PROCESS_CREATE_THREAD`
    ///  - `PROCESS_QUERY_INFORMATION`
    ///  - `PROCESS_VM_OPERATION`
    ///  - `PROCESS_VM_WRITE`
    ///  - `PROCESS_VM_READ`
    unsafe fn from_raw_process_handle(handle: RawProcessHandle) -> Self;
}
