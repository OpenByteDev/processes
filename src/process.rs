use std::{
    borrow::Cow,
    ffi::OsString,
    hash::{Hash, Hasher},
    io,
    mem::{self, MaybeUninit},
    num::NonZeroU32,
    os::windows::prelude::{
        AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, IntoRawHandle, OwnedHandle,
    },
    path::{Path, PathBuf},
    ptr::{self, NonNull},
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
    utils::{get_win_ffi_path, retry_faillable_until_some_with_timeout, TryFillBufResult},
    BorrowedProcess, FromRawProcessHandle, ModuleHandle, OwnedProcess, ProcessHandle,
    ProcessModule, ProcessOrPathError, RawProcessHandle,
};

use std::fmt::{self, Debug};

use memoffset::offset_of;
use ntapi::{
    ntldr::LDR_DATA_TABLE_ENTRY,
    ntpsapi::{
        NtQueryInformationProcess, ProcessBasicInformation, PEB_LDR_DATA, PROCESS_BASIC_INFORMATION,
    },
    ntrtl::RtlNtStatusToDosError,
};
use winapi::shared::ntdef::LIST_ENTRY;
use winresult::NtStatus;

/// A struct representing a running process.
#[derive(Clone, Copy)]
pub struct Process<Handle: ProcessHandle> {
    handle: Handle,
}

impl<Handle: ProcessHandle> Debug for Process<Handle> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Process")
            .field("handle", &self.as_raw_handle())
            .field("base_name", &self.base_name())
            .field("alive", &self.is_alive())
            .finish()
    }
}

impl<Handle: ProcessHandle + AsRawHandle> AsRawHandle for Process<Handle> {
    fn as_raw_handle(&self) -> RawProcessHandle {
        self.handle.as_raw_handle()
    }
}

impl<Handle: ProcessHandle> AsHandle for Process<Handle> {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        unsafe { BorrowedHandle::borrow_raw(self.as_raw_handle()) }
    }
}

impl<Handle: ProcessHandle + IntoRawHandle> IntoRawHandle for Process<Handle> {
    fn into_raw_handle(self) -> RawProcessHandle {
        self.handle.into_raw_handle()
    }
}

impl<HandleA: ProcessHandle, HandleB: ProcessHandle> PartialEq<Process<HandleB>>
    for Process<HandleA>
{
    fn eq(&self, other: &Process<HandleB>) -> bool {
        (&self).eq(other)
    }
}

impl<HandleA: ProcessHandle, HandleB: ProcessHandle> PartialEq<Process<HandleB>>
    for &'_ Process<HandleA>
{
    fn eq(&self, other: &Process<HandleB>) -> bool {
        // TODO: (unsafe { CompareObjectHandles(self.handle(), other.handle()) }) != FALSE

        self.as_raw_handle() == other.as_raw_handle()
            || self.pid().map_or(0, |v| v.get()) == other.pid().map_or(0, |v| v.get())
    }
}

impl<Handle: ProcessHandle> Eq for Process<Handle> {}

impl<Handle: ProcessHandle> Hash for Process<Handle> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_raw_handle().hash(state)
    }
}

impl<Handle: ProcessHandle> FromRawHandle for Process<Handle> {
    unsafe fn from_raw_handle(handle: RawProcessHandle) -> Self {
        Self {
            handle: unsafe { Handle::from_raw_process_handle(handle) },
        }
    }
}

impl<Handle: ProcessHandle> Process<Handle> {
    /// Returns the underlying process handle.
    #[must_use]
    pub fn into_handle(self) -> Handle {
        self.handle
    }

    /// Creates a new instance from the given handle.
    ///
    /// # Safety
    /// The caller must ensure that the handle is a valid process handle and has the required [privileges](https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights):
    ///  - `PROCESS_CREATE_THREAD`
    ///  - `PROCESS_QUERY_INFORMATION`
    ///  - `PROCESS_VM_OPERATION`
    ///  - `PROCESS_VM_WRITE`
    ///  - `PROCESS_VM_READ`
    #[must_use]
    pub unsafe fn from_handle(handle: Handle) -> Self {
        Self { handle }
    }

    /// Returns a borrowed instance of this process.
    pub fn borrowed(&self) -> BorrowedProcess<'_> {
        let handle = self.as_handle();
        unsafe { BorrowedProcess::from_handle(handle) }
    }

    /// Trys to clone this process instance.
    pub fn try_clone(&self) -> Result<Self, ProcessError> {
        let handle = self.handle.try_clone()?;
        Ok(unsafe { Self::from_handle(handle) })
    }

    /// Trys to create a new [`OwnedProcess`] instance for this process.
    pub fn try_to_owned(&self) -> Result<OwnedProcess, ProcessError> {
        let owned_handle = self.borrowed().into_handle().try_clone_to_owned()?;
        Ok(unsafe { OwnedProcess::from_handle(owned_handle) })
    }

    /// Returns the raw pseudo handle representing the current process.
    #[must_use]
    pub fn raw_current_handle() -> RawProcessHandle {
        unsafe { GetCurrentProcess() }
    }

    /// Returns the pseudo handle representing the current process.
    #[must_use]
    pub fn current_handle() -> Handle {
        let handle = Self::raw_current_handle();
        unsafe { Handle::from_raw_process_handle(handle) }
    }

    /// Returns an instance representing the current process.
    #[must_use]
    pub fn current() -> Self {
        let handle = Self::current_handle();
        unsafe { Self::from_handle(handle) }
    }

    /// Returns whether this instance represents the current process.
    #[must_use]
    pub fn is_current(&self) -> bool {
        self == BorrowedProcess::current()
    }

    /// Returns whether this process is still alive and running.
    ///
    /// # Note
    /// If the operation to determine the status fails, this function assumes that the process has exited.
    #[must_use]
    pub fn is_alive(&self) -> bool {
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
    pub fn pid(&self) -> Result<NonZeroU32, ProcessError> {
        let result = unsafe { GetProcessId(self.as_raw_handle()) };
        NonZeroU32::new(result)
            .ok_or_else(io::Error::last_os_error)
            .map_err(|e| e.into())
    }

    /// Returns whether this process is running under [WOW64](https://docs.microsoft.com/en-us/windows/win32/winprog64/running-32-bit-applications).
    /// This is the case for 32-bit programs running on a 64-bit platform.
    pub fn runs_under_wow64(&self) -> Result<bool, ProcessError> {
        if cfg!(target_pointer_width = "64") {
            return Ok(false);
        }

        raw::process_architecture_info(self.as_raw_handle()).map(|info| info.is_wow64)
    }

    /// Returns whether this process is a 64-bit process.
    pub fn is_64_bit(&self) -> Result<bool, ProcessError> {
        self.bitness().map(|bits| bits == 64)
    }

    /// Returns whether this process is a 32-bit process.
    pub fn is_32_bit(&self) -> Result<bool, ProcessError> {
        self.bitness().map(|bits| bits == 32)
    }

    /// Returns the bitness of this process.
    pub fn bitness(&self) -> Result<usize, ProcessError> {
        raw::process_architecture_info(self.as_raw_handle()).map(|info| info.process_bitness)
    }

    /// Returns the executable path of this process.
    pub fn path(&self) -> Result<PathBuf, ProcessError> {
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
    pub fn base_name(&self) -> Result<String, ProcessError> {
        self.path()
            .map(|path| path.file_name().unwrap().to_string_lossy().to_string())
    }

    /// Returns the file name of the executable of this process as an [OsString].
    pub fn base_name_os(&self) -> Result<OsString, ProcessError> {
        self.path()
            .map(|path| path.file_name().unwrap().to_os_string())
    }

    /// Terminates this process with exit code 1.
    pub fn kill(&self) -> Result<(), ProcessError> {
        self.kill_with_exit_code(1)
    }

    /// Terminates this process with the given exit code.
    pub fn kill_with_exit_code(&self, exit_code: u32) -> Result<(), ProcessError> {
        let result = unsafe { TerminateProcess(self.as_raw_handle(), exit_code) };
        if result == 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }

    /// Starts a new thread in this process with the given entry point and argument, and waits for it to finish, returning the exit code.
    pub fn run_remote_thread<T>(
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
    pub fn start_remote_thread<T>(
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

        Ok(unsafe { OwnedHandle::from_raw_process_handle(thread_handle) })
    }

    /// Returns a snapshot of all modules currently loaded in this process.
    ///
    /// # Note
    /// If the process is currently starting up and has not loaded all its modules yet, the returned list may be incomplete.
    pub fn modules(&self) -> Result<Vec<ProcessModule<Handle>>, ProcessError> {
        let process = self.borrowed();
        let module_handles = process.module_handles()?;
        module_handles
            .map(|module_handle| {
                Ok(unsafe { ProcessModule::new_unchecked(module_handle?, self.try_clone()?) })
            })
            .collect::<Result<Vec<_>, ProcessError>>()
    }

    /// Returns a snapshot of the handles of the modules currently loaded in this process.
    ///
    /// # Note
    /// If the process is currently starting up and has not yet loaded all its modules, the returned list may be incomplete.
    /// This can be worked around by repeatedly calling this method.
    pub fn module_handles(
        &self,
    ) -> Result<impl Iterator<Item = Result<ModuleHandle, ProcessError>> + '_, ProcessError> {
        struct PebModuleListIterator<'a> {
            memory: ProcessMemory<'a>,
            next: NonNull<LIST_ENTRY>,
            header: NonNull<LIST_ENTRY>,
        }

        impl Iterator for PebModuleListIterator<'_> {
            type Item = Result<ModuleHandle, ProcessError>;

            fn next(&mut self) -> Option<Self::Item> {
                if self.next == self.header {
                    return None;
                }

                let module_ptr = (self.next.as_ptr() as usize
                    - offset_of!(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks))
                    as *mut LDR_DATA_TABLE_ENTRY;
                let module = match unsafe { self.memory.read_struct(module_ptr) } {
                    Ok(m) => m,
                    Err(e) => return Some(Err(e)),
                };
                let entry = module.InLoadOrderLinks;
                self.next = NonNull::new(entry.Flink).unwrap();

                let handle = module.DllBase.cast();
                Some(Ok(handle))
            }
        }

        let memory = self.memory();
        let mut process_info = MaybeUninit::<PROCESS_BASIC_INFORMATION>::uninit();
        let mut bytes_written = MaybeUninit::uninit();

        let result = unsafe {
            NtQueryInformationProcess(
                self.as_raw_handle(),
                ProcessBasicInformation,
                process_info.as_mut_ptr().cast(),
                mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                bytes_written.as_mut_ptr(),
            )
        };

        let result = NtStatus::from(result as u32);
        if result.is_error() {
            let code = unsafe { RtlNtStatusToDosError(result.to_u32() as i32) };
            let error = io::Error::from_raw_os_error(code as i32);
            return Err(error.into());
        }
        let bytes_written = unsafe { bytes_written.assume_init() } as usize;
        assert_eq!(bytes_written, mem::size_of::<PROCESS_BASIC_INFORMATION>());

        let process_info = unsafe { process_info.assume_init() };
        let peb = unsafe { memory.read_struct(process_info.PebBaseAddress) }?;
        if peb.Ldr.is_null() {
            if !self.is_alive() {
                return Err(ProcessError::ProcessInaccessible);
            }

            // this case occurs if called shortly after startup.
            let dummy_ptr = NonNull::new(1 as *mut _).unwrap();
            return Ok(PebModuleListIterator {
                memory,
                next: dummy_ptr,
                header: dummy_ptr,
            });
        }
        let ldr = unsafe { memory.read_struct(peb.Ldr) }?;

        let iter = PebModuleListIterator {
            memory,
            next: NonNull::new(ldr.InLoadOrderModuleList.Flink)
                .unwrap()
                .cast(),
            header: NonNull::new(
                (peb.Ldr as usize + offset_of!(PEB_LDR_DATA, InLoadOrderModuleList))
                    as *mut LIST_ENTRY,
            )
            .unwrap(),
        };

        Ok(iter)
    }

    /// Returns the main module of this process. This is typically the executable.
    pub fn main_module(&self) -> Result<ProcessModule<Handle>, ProcessError>
    where
        Self: Sized,
    {
        Ok(unsafe { ProcessModule::new_unchecked(ptr::null_mut(), self.try_clone()?) })
    }

    /// Searches the modules in this process for one with the given name.
    /// The comparison of names is case-insensitive.
    /// If the extension is omitted, the default library extension `.dll` is appended.
    ///
    /// # Note
    /// If the process is currently starting up and has not loaded all its modules, the returned list may be incomplete.
    /// See also [`Process::wait_for_module_by_name`].
    pub fn find_module_by_name(
        &self,
        module_name: impl AsRef<Path>,
    ) -> Result<Option<ProcessModule<Handle>>, ProcessOrPathError> {
        let target_module_name = module_name.as_ref();

        if self.is_current() {
            return ProcessModule::find_local_by_name(target_module_name);
        }

        // add default file extension if missing
        let target_module_name = if target_module_name.extension().is_none() {
            Cow::Owned(target_module_name.with_extension("dll").into_os_string())
        } else {
            Cow::Borrowed(target_module_name.as_os_str())
        };

        let modules = self.module_handles()?;

        for module_handle in modules {
            let module = unsafe { ProcessModule::new_unchecked(module_handle?, self.try_clone()?) };
            let module_name = module.base_name_os()?;

            if module_name.eq_ignore_ascii_case(&target_module_name) {
                return Ok(Some(module));
            }
        }

        Ok(None)
    }

    /// Searches the modules in this process for one with the given path.
    /// The comparison of paths is case-insensitive.
    /// If the extension is omitted, the default library extension `.dll` is appended.
    ///
    /// # Note
    /// If the process is currently starting up and has not loaded all its modules, the returned list may be incomplete.
    /// See also [`Process::wait_for_module_by_path`].
    pub fn find_module_by_path(
        &self,
        module_path: impl AsRef<Path>,
    ) -> Result<Option<ProcessModule<Handle>>, ProcessOrPathError> {
        let target_module_path = module_path.as_ref();

        if self.is_current() {
            return ProcessModule::find_local_by_path(target_module_path);
        }

        // add default file extension if missing
        let target_module_path = if target_module_path.extension().is_none() {
            Cow::Owned(target_module_path.with_extension("dll").into_os_string())
        } else {
            Cow::Borrowed(target_module_path.as_os_str())
        };

        let target_module_handle = same_file::Handle::from_path(&target_module_path)?;

        let modules = self.module_handles()?;

        for module_handle in modules {
            let module = unsafe { ProcessModule::new_unchecked(module_handle?, self.try_clone()?) };
            let module_path = module.path()?.into_os_string();

            match same_file::Handle::from_path(&module_path) {
                Ok(module_handle) => {
                    if module_handle == target_module_handle {
                        return Ok(Some(module));
                    }
                }
                Err(_) => {
                    if target_module_path.eq_ignore_ascii_case(&module_path) {
                        return Ok(Some(module));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Searches the modules in this process for one with the given name repeatedly until a matching module is found or the given timeout elapses.
    /// The comparison of names is case-insensitive.
    /// If the extension is omitted, the default library extension `.dll` is appended.
    pub fn wait_for_module_by_name(
        &self,
        module_name: impl AsRef<Path>,
        timeout: Duration,
    ) -> Result<Option<ProcessModule<Handle>>, ProcessOrPathError> {
        retry_faillable_until_some_with_timeout(
            || self.find_module_by_name(module_name.as_ref()),
            timeout,
        )
    }

    /// Searches the modules in this process for one with the given path repeatedly until a matching module is found or the given timeout elapses.
    /// The comparison of paths is case-insensitive.
    /// If the extension is omitted, the default library extension `.dll` is appended.
    pub fn wait_for_module_by_path(
        &self,
        module_path: impl AsRef<Path>,
        timeout: Duration,
    ) -> Result<Option<ProcessModule<Handle>>, ProcessOrPathError> {
        retry_faillable_until_some_with_timeout(
            || self.find_module_by_path(module_path.as_ref()),
            timeout,
        )
    }

    #[cfg_attr(feature = "memory", doc(hidden))]
    #[cfg_attr(feature = "doc-cfg", doc(cfg(feature = "memory")))]
    /// Returns a struct representing the memory region owned by this process.
    pub fn memory(&'_ self) -> ProcessMemory<'_> {
        ProcessMemory {
            process: self.borrowed(),
        }
    }
}
