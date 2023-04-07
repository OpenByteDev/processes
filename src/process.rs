use std::{
    ffi::OsString,
    io,
    mem::{self, MaybeUninit},
    num::NonZeroU32,
    os::windows::prelude::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle},
    path::{Path, PathBuf},
    ptr,
    time::Duration,
};

use winapi::{
    shared::{
        minwindef::{DWORD, FALSE},
        winerror::{ERROR_INSUFFICIENT_BUFFER, WAIT_TIMEOUT},
    },
    um::{
        minwinbase::STILL_ACTIVE,
        processthreadsapi::{
            CreateRemoteThread, GetCurrentProcess, GetExitCodeProcess, GetExitCodeThread,
            GetProcessId, TerminateProcess,
        },
        synchapi::WaitForSingleObject,
        winbase::{QueryFullProcessImageNameW, INFINITE, WAIT_FAILED},
    },
};

use crate::{
    error::ProcessError,
    memory::ProcessMemory,
    raw,
    utils::{get_win_ffi_path, TryFillBufResult},
    BorrowedProcess, ProcessModule,
};

/// A handle to a running process.
pub type ProcessHandle = std::os::windows::raw::HANDLE;

/// A trait representing a running process.
///
/// # Note
/// The underlying handle has the following [privileges](https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights):
///  - `PROCESS_CREATE_THREAD`
///  - `PROCESS_QUERY_INFORMATION`
///  - `PROCESS_VM_OPERATION`
///  - `PROCESS_VM_WRITE`
///  - `PROCESS_VM_READ`
pub trait Process: AsHandle + AsRawHandle {
    /// The underlying handle type.
    type Handle;

    /// Returns a borrowed instance of this process.
    fn borrowed(&self) -> BorrowedProcess<'_>;

    /// Tries to clone this process into a new instance.
    fn try_clone(&self) -> Result<Self, ProcessError>
    where
        Self: Sized;

    /// Returns the underlying process handle.
    #[must_use]
    fn into_handle(self) -> Self::Handle;

    /// Creates a new instance from the given handle.
    ///
    /// # Safety
    /// The caller must ensure that the handle is a valid process handle and has the required priviledges.
    #[must_use]
    unsafe fn from_handle_unchecked(handle: Self::Handle) -> Self;

    /// Returns the raw pseudo handle representing the current process.
    #[must_use]
    fn raw_current_handle() -> ProcessHandle {
        unsafe { GetCurrentProcess() }
    }

    /// Returns the pseudo handle representing the current process.
    #[must_use]
    fn current_handle() -> Self::Handle;

    /// Returns an instance representing the current process.
    #[must_use]
    fn current() -> Self
    where
        Self: Sized,
    {
        unsafe { Self::from_handle_unchecked(Self::current_handle()) }
    }

    /// Returns whether this instance represents the current process.
    #[must_use]
    fn is_current(&self) -> bool {
        self.borrowed() == BorrowedProcess::current()
    }

    /// Returns whether this process is still alive and running.
    ///
    /// # Note
    /// If the operation to determine the status fails, this function assumes that the process has exited.
    #[must_use]
    fn is_alive(&self) -> bool {
        if self.is_current() {
            return true;
        }

        let mut exit_code = MaybeUninit::uninit();
        let result = unsafe { GetExitCodeProcess(self.as_raw_handle(), exit_code.as_mut_ptr()) };
        if result == FALSE {
            // GetExitCodeProcess failed, assume the process is dead.
            return false;
        }

        let exit_code = unsafe { exit_code.assume_init() };
        if exit_code != STILL_ACTIVE {
            return false;
        }

        // The process could actually already have exited but returned the exit code STILL_ACTIVE:
        const WAIT_OBJECT_0: DWORD = 0;
        match unsafe { WaitForSingleObject(self.as_raw_handle(), 0) } {
            WAIT_FAILED | WAIT_OBJECT_0 => false,
            WAIT_TIMEOUT => true,
            _ => unreachable!(),
        }
    }

    /// Returns the id of this process.
    fn pid(&self) -> Result<NonZeroU32, ProcessError> {
        let result = unsafe { GetProcessId(self.as_raw_handle()) };
        NonZeroU32::new(result)
            .ok_or_else(io::Error::last_os_error)
            .map_err(|e| e.into())
    }

    /// Returns whether this process is running under [WOW64](https://docs.microsoft.com/en-us/windows/win32/winprog64/running-32-bit-applications).
    /// This is the case for 32-bit programs running on a 64-bit platform.
    fn runs_under_wow64(&self) -> Result<bool, ProcessError> {
        if cfg!(target_pointer_width = "64") {
            return Ok(false);
        }

        raw::process_architecture_info(self.as_raw_handle()).map(|info| info.is_wow64)
    }

    /// Returns whether this process is a 64-bit process.
    fn is_64_bit(&self) -> Result<bool, ProcessError> {
        self.bitness().map(|bits| bits == 64)
    }

    /// Returns whether this process is a 32-bit process.
    fn is_32_bit(&self) -> Result<bool, ProcessError> {
        self.bitness().map(|bits| bits == 32)
    }

    /// Returns the bitness of this process.
    fn bitness(&self) -> Result<usize, ProcessError> {
        raw::process_architecture_info(self.as_raw_handle()).map(|info| info.process_bitness)
    }

    /// Returns the executable path of this process.
    fn path(&self) -> Result<PathBuf, ProcessError> {
        // const PROCESS_NAME_NATIVE: u32 = 0x00000001;

        get_win_ffi_path(|buf_ptr, buf_size| {
            let mut buf_size = buf_size as u32;
            let result = unsafe {
                QueryFullProcessImageNameW(self.as_raw_handle(), 0, buf_ptr, &mut buf_size)
            };
            if result == 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error().unwrap() == ERROR_INSUFFICIENT_BUFFER as i32 {
                    TryFillBufResult::BufTooSmall {
                        size_hint: Some(buf_size as usize),
                    }
                } else {
                    TryFillBufResult::Error(err.into())
                }
            } else {
                TryFillBufResult::Success {
                    actual_len: buf_size as usize,
                }
            }
        })
    }

    /// Returns the file name of the executable of this process.
    fn base_name(&self) -> Result<String, ProcessError> {
        self.path()
            .map(|path| path.file_name().unwrap().to_string_lossy().to_string())
    }

    /// Returns the file name of the executable of this process as an [OsString].
    fn base_name_os(&self) -> Result<OsString, ProcessError> {
        self.path()
            .map(|path| path.file_name().unwrap().to_os_string())
    }

    /// Terminates this process with exit code 1.
    fn kill(&self) -> Result<(), ProcessError> {
        self.kill_with_exit_code(1)
    }

    /// Terminates this process with the given exit code.
    fn kill_with_exit_code(&self, exit_code: u32) -> Result<(), ProcessError> {
        let result = unsafe { TerminateProcess(self.as_raw_handle(), exit_code) };
        if result == 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }

    /// Starts a new thread in this process with the given entry point and argument, and waits for it to finish, returning the exit code.
    fn run_remote_thread<T>(
        &self,
        remote_fn: extern "system" fn(*mut T) -> u32,
        parameter: *mut T,
    ) -> Result<u32, ProcessError> {
        let thread_handle = self.start_remote_thread(remote_fn, parameter)?;

        let reason = unsafe { WaitForSingleObject(thread_handle.as_raw_handle(), INFINITE) };
        if reason == WAIT_FAILED {
            return Err(io::Error::last_os_error().into());
        }

        let mut exit_code = MaybeUninit::uninit();
        let result =
            unsafe { GetExitCodeThread(thread_handle.as_raw_handle(), exit_code.as_mut_ptr()) };
        if result == 0 {
            return Err(io::Error::last_os_error().into());
        }
        debug_assert_ne!(
            result as u32, STILL_ACTIVE,
            "GetExitCodeThread returned STILL_ACTIVE after WaitForSingleObject"
        );

        Ok(unsafe { exit_code.assume_init() })
    }

    /// Starts a new thread in this process with the given entry point and argument and returns the thread handle.
    fn start_remote_thread<T>(
        &self,
        remote_fn: unsafe extern "system" fn(*mut T) -> u32,
        parameter: *mut T,
    ) -> Result<OwnedHandle, ProcessError> {
        const RUN_IMMEDIATELY: DWORD = 0;

        // create a remote thread that will call LoadLibraryW with payload_path as its argument.
        let thread_handle = unsafe {
            CreateRemoteThread(
                self.as_raw_handle(),
                ptr::null_mut(),
                0,
                Some(mem::transmute(remote_fn)),
                parameter.cast(),
                RUN_IMMEDIATELY,
                ptr::null_mut(),
            )
        };
        if thread_handle.is_null() {
            return Err(io::Error::last_os_error().into());
        }

        Ok(unsafe { OwnedHandle::from_raw_handle(thread_handle) })
    }

    /// Searches the modules in this process for one with the given name.
    /// The comparison of names is case-insensitive.
    /// If the extension is omitted, the default library extension `.dll` is appended.
    ///
    /// # Note
    /// If the process is currently starting up and has not loaded all its modules, the returned list may be incomplete.
    /// See also [`Process::wait_for_module_by_name`].
    fn find_module_by_name(
        &self,
        module_name: impl AsRef<Path>,
    ) -> Result<Option<ProcessModule<Self>>, ProcessError>
    where
        Self: Sized;

    /// Searches the modules in this process for one with the given path.
    /// The comparison of paths is case-insensitive.
    /// If the extension is omitted, the default library extension `.dll` is appended.
    ///
    /// # Note
    /// If the process is currently starting up and has not loaded all its modules, the returned list may be incomplete.
    /// See also [`Process::wait_for_module_by_path`].
    fn find_module_by_path(
        &self,
        module_path: impl AsRef<Path>,
    ) -> Result<Option<ProcessModule<Self>>, ProcessError>
    where
        Self: Sized;

    /// Searches the modules in this process for one with the given name repeatedly until a matching module is found or the given timeout elapses.
    /// The comparison of names is case-insensitive.
    /// If the extension is omitted, the default library extension `.dll` is appended.
    fn wait_for_module_by_name(
        &self,
        module_name: impl AsRef<Path>,
        timeout: Duration,
    ) -> Result<Option<ProcessModule<Self>>, ProcessError>
    where
        Self: Sized;

    /// Searches the modules in this process for one with the given path repeatedly until a matching module is found or the given timeout elapses.
    /// The comparison of paths is case-insensitive.
    /// If the extension is omitted, the default library extension `.dll` is appended.
    fn wait_for_module_by_path(
        &self,
        module_path: impl AsRef<Path>,
        timeout: Duration,
    ) -> Result<Option<ProcessModule<Self>>, ProcessError>
    where
        Self: Sized;

    /// Returns a snapshot of all modules currently loaded in this process.
    ///
    /// # Note
    /// If the process is currently starting up and has not loaded all its modules yet, the returned list may be incomplete.
    fn modules(&self) -> Result<Vec<ProcessModule<Self>>, ProcessError>
    where
        Self: Sized,
    {
        let process = self.borrowed();
        let module_handles = process.module_handles()?;
        module_handles
            .map(|module_handle| {
                Ok(unsafe { ProcessModule::new_unchecked(module_handle?, self.try_clone()?) })
            })
            .collect::<Result<Vec<_>, ProcessError>>()
    }

    /// Returns the main module of this process. This is typically the executable.
    fn main_module(&self) -> Result<ProcessModule<Self>, ProcessError>
    where
        Self: Sized,
    {
        Ok(unsafe { ProcessModule::new_unchecked(ptr::null_mut(), self.try_clone()?) })
    }

    #[cfg_attr(feature = "memory", doc(hidden))]
    #[cfg_attr(feature = "doc-cfg", doc(cfg(feature = "memory")))]
    /// Returns a struct representing the memory region owned by this process.
    fn memory(&'_ self) -> ProcessMemory<'_> {
        ProcessMemory {
            process: self.borrowed(),
        }
    }
}
