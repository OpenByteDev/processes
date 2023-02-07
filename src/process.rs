use std::{
    ffi::OsString,
    io,
    mem::{self, MaybeUninit},
    num::NonZeroU32,
    os::windows::{
        prelude::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle},
        raw::HANDLE,
    },
    path::{Path, PathBuf},
    ptr,
    time::Duration,
};

use winapi::{
    shared::{
        minwindef::{DWORD, FALSE},
        winerror::ERROR_INSUFFICIENT_BUFFER,
    },
    um::{
        minwinbase::STILL_ACTIVE,
        processthreadsapi::{
            CreateRemoteThread, GetCurrentProcess, GetExitCodeProcess, GetExitCodeThread,
            GetProcessId, TerminateProcess,
        },
        synchapi::WaitForSingleObject,
        winbase::{QueryFullProcessImageNameW, INFINITE, WAIT_FAILED},
        winnt::{
            IMAGE_FILE_MACHINE_ALPHA, IMAGE_FILE_MACHINE_ALPHA64, IMAGE_FILE_MACHINE_AM33,
            IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM, IMAGE_FILE_MACHINE_ARM64,
            IMAGE_FILE_MACHINE_ARMNT, IMAGE_FILE_MACHINE_CEE, IMAGE_FILE_MACHINE_CEF,
            IMAGE_FILE_MACHINE_EBC, IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_IA64,
            IMAGE_FILE_MACHINE_M32R, IMAGE_FILE_MACHINE_MIPS16, IMAGE_FILE_MACHINE_MIPSFPU,
            IMAGE_FILE_MACHINE_MIPSFPU16, IMAGE_FILE_MACHINE_POWERPC, IMAGE_FILE_MACHINE_POWERPCFP,
            IMAGE_FILE_MACHINE_R10000, IMAGE_FILE_MACHINE_R3000, IMAGE_FILE_MACHINE_R4000,
            IMAGE_FILE_MACHINE_SH3, IMAGE_FILE_MACHINE_SH3DSP, IMAGE_FILE_MACHINE_SH3E,
            IMAGE_FILE_MACHINE_SH4, IMAGE_FILE_MACHINE_SH5, IMAGE_FILE_MACHINE_THUMB,
            IMAGE_FILE_MACHINE_TRICORE, IMAGE_FILE_MACHINE_UNKNOWN, IMAGE_FILE_MACHINE_WCEMIPSV2
        },
        wow64apiset::IsWow64Process2,
    },
};

use crate::{
    utils::{get_win_ffi_path, FillPathBufResult},
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
    fn try_clone(&self) -> Result<Self, io::Error>
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
        result != FALSE && unsafe { exit_code.assume_init() } == STILL_ACTIVE
    }

    /// Returns the id of this process.
    fn pid(&self) -> Result<NonZeroU32, io::Error> {
        let result = unsafe { GetProcessId(self.as_raw_handle()) };
        NonZeroU32::new(result).ok_or_else(io::Error::last_os_error)
    }

    /// Returns whether this process is running under [WOW64](https://docs.microsoft.com/en-us/windows/win32/winprog64/running-32-bit-applications).
    /// This is the case for 32-bit programs running on a 64-bit platform.
    fn runs_under_wow64(&self) -> Result<bool, io::Error> {
        if cfg!(target_pointer_width = "64") {
            return Ok(false);
        }

        process_architecture_info(self.as_raw_handle()).map(|info| info.is_wow64)
    }

    /// Returns whether this process is a 64-bit process.
    fn is_64_bit(&self) -> Result<bool, io::Error> {
        self.bitness().map(|bits| bits == 64)
    }

    /// Returns whether this process is a 32-bit process.
    fn is_32_bit(&self) -> Result<bool, io::Error> {
        self.bitness().map(|bits| bits == 32)
    }

    /// Returns the bitness of this process.
    fn bitness(&self) -> Result<usize, io::Error> {
        process_architecture_info(self.as_raw_handle()).map(|info| info.process_bitness)
    }

    /// Returns the executable path of this process.
    fn path(&self) -> Result<PathBuf, io::Error> {
        get_win_ffi_path(|buf_ptr, buf_size| {
            let mut buf_size = buf_size as u32;
            let result = unsafe {
                QueryFullProcessImageNameW(self.as_raw_handle(), 0, buf_ptr, &mut buf_size)
            };
            if result == 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error().unwrap() == ERROR_INSUFFICIENT_BUFFER as i32 {
                    FillPathBufResult::BufTooSmall {
                        size_hint: Some(buf_size as usize),
                    }
                } else {
                    FillPathBufResult::Error(err)
                }
            } else {
                FillPathBufResult::Success {
                    actual_len: buf_size as usize,
                }
            }
        })
    }

    /// Returns the file name of the executable of this process.
    fn base_name(&self) -> Result<String, io::Error> {
        self.path()
            .map(|path| path.file_name().unwrap().to_string_lossy().to_string())
    }

    /// Returns the file name of the executable of this process as an [OsString].
    fn base_name_os(&self) -> Result<OsString, io::Error> {
        self.path()
            .map(|path| path.file_name().unwrap().to_os_string())
    }

    /// Terminates this process with exit code 1.
    fn kill(&self) -> Result<(), io::Error> {
        self.kill_with_exit_code(1)
    }

    /// Terminates this process with the given exit code.
    fn kill_with_exit_code(&self, exit_code: u32) -> Result<(), io::Error> {
        let result = unsafe { TerminateProcess(self.as_raw_handle(), exit_code) };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Starts a new thread in this process with the given entry point and argument, and waits for it to finish, returning the exit code.
    fn run_remote_thread<T>(
        &self,
        remote_fn: extern "system" fn(*mut T) -> u32,
        parameter: *mut T,
    ) -> Result<u32, io::Error> {
        let thread_handle = self.start_remote_thread(remote_fn, parameter)?;

        let reason = unsafe { WaitForSingleObject(thread_handle.as_raw_handle(), INFINITE) };
        if reason == WAIT_FAILED {
            return Err(io::Error::last_os_error());
        }

        let mut exit_code = MaybeUninit::uninit();
        let result =
            unsafe { GetExitCodeThread(thread_handle.as_raw_handle(), exit_code.as_mut_ptr()) };
        if result == 0 {
            return Err(io::Error::last_os_error());
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
    ) -> Result<OwnedHandle, io::Error> {
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
            return Err(io::Error::last_os_error());
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
    ) -> Result<Option<ProcessModule<Self>>, io::Error>
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
    ) -> Result<Option<ProcessModule<Self>>, io::Error>
    where
        Self: Sized;

    /// Searches the modules in this process for one with the given name, repeatedly until a matching module is found or the given timeout elapses.
    /// The comparison of names is case-insensitive.
    /// If the extension is omitted, the default library extension `.dll` is appended.
    fn wait_for_module_by_name(
        &self,
        module_name: impl AsRef<Path>,
        timeout: Duration,
    ) -> Result<Option<ProcessModule<Self>>, io::Error>
    where
        Self: Sized;

    /// Searches the modules in this process for one with the given path, repeatedly until a matching module is found or the given timeout elapses.
    /// The comparison of paths is case-insensitive.
    /// If the extension is omitted, the default library extension `.dll` is appended.
    fn wait_for_module_by_path(
        &self,
        module_path: impl AsRef<Path>,
        timeout: Duration,
    ) -> Result<Option<ProcessModule<Self>>, io::Error>
    where
        Self: Sized;

    /// Returns a snapshot of all modules currently loaded in this process.
    ///
    /// # Note
    /// If the process is currently starting up and has not loaded all its modules yet, the returned list may be incomplete.
    fn modules(&self) -> Result<Vec<ProcessModule<Self>>, io::Error>
    where
        Self: Sized,
    {
        let module_handles = self.borrowed().module_handles()?;
        let mut modules = Vec::with_capacity(module_handles.len());
        for module_handle in module_handles {
            modules.push(unsafe { ProcessModule::new_unchecked(module_handle, self.try_clone()?) });
        }
        Ok(modules)
    }
}

struct ArchitectureInfo {
    process_bitness: usize,
    _machine_bitness: usize,
    is_wow64: bool,
}

#[inline]
fn process_architecture_info(handle: HANDLE) -> Result<ArchitectureInfo, io::Error> {
    fn get_bitness(image_file_machine: u16) -> usize {
        // taken from https://github.com/fkie-cad/headerParser/blob/bc45fb361ed654e656dd2f66819f33e1c919a3dd/src/ArchitectureInfo.h

        const IMAGE_FILE_MACHINE_DEC_ALPHA_AXP: u16 = 0x183;
        const IMAGE_FILE_MACHINE_I860: u16 = 0x014d;
        const IMAGE_FILE_MACHINE_I80586: u16 = 0x014e;
        const IMAGE_FILE_MACHINE_R3000_BE: u16 = 0x0160;
        const IMAGE_FILE_MACHINE_RISCV32: u16 = 0x5032;
        const IMAGE_FILE_MACHINE_RISCV64: u16 = 0x5064;
        const IMAGE_FILE_MACHINE_RISCV128: u16 = 0x5128;

        match image_file_machine {
            IMAGE_FILE_MACHINE_ALPHA => 64,
            IMAGE_FILE_MACHINE_ALPHA64 => 64,
            IMAGE_FILE_MACHINE_AM33 => 32,
            IMAGE_FILE_MACHINE_AMD64 => 64,
            IMAGE_FILE_MACHINE_ARM => 32,
            IMAGE_FILE_MACHINE_ARM64 => 64,
            IMAGE_FILE_MACHINE_ARMNT => 32,
            // IMAGE_FILE_MACHINE_AXP64 => 64,
            IMAGE_FILE_MACHINE_CEE => 0,
            IMAGE_FILE_MACHINE_CEF => 0,
            IMAGE_FILE_MACHINE_DEC_ALPHA_AXP => 64,
            IMAGE_FILE_MACHINE_EBC => 32,
            IMAGE_FILE_MACHINE_I386 => 32,
            IMAGE_FILE_MACHINE_I860 => 32,
            IMAGE_FILE_MACHINE_I80586 => 32,
            IMAGE_FILE_MACHINE_IA64 => 64,
            IMAGE_FILE_MACHINE_M32R => 32,
            IMAGE_FILE_MACHINE_MIPS16 => 16,
            IMAGE_FILE_MACHINE_MIPSFPU => 32,
            IMAGE_FILE_MACHINE_MIPSFPU16 => 16,
            IMAGE_FILE_MACHINE_POWERPC => 32,
            IMAGE_FILE_MACHINE_POWERPCFP => 32,
            IMAGE_FILE_MACHINE_R3000 => 32,
            IMAGE_FILE_MACHINE_R3000_BE => 32,
            IMAGE_FILE_MACHINE_R4000 => 64,
            IMAGE_FILE_MACHINE_R10000 => 64,
            IMAGE_FILE_MACHINE_RISCV32 => 32,
            IMAGE_FILE_MACHINE_RISCV64 => 64,
            IMAGE_FILE_MACHINE_RISCV128 => 128,
            IMAGE_FILE_MACHINE_SH3 => 32,
            IMAGE_FILE_MACHINE_SH3DSP => 32,
            IMAGE_FILE_MACHINE_SH3E => 32,
            IMAGE_FILE_MACHINE_SH4 => 32,
            IMAGE_FILE_MACHINE_SH5 => 64,
            IMAGE_FILE_MACHINE_THUMB => 16,
            IMAGE_FILE_MACHINE_TRICORE => 32,
            IMAGE_FILE_MACHINE_WCEMIPSV2 => 32,
            _ => unimplemented!(
                "unknown machine architecture (IMAGE_FILE_MACHINE_*): {image_file_machine}"
            ),
        }
    }

    let mut process_machine_info = MaybeUninit::uninit();
    let mut native_machine_info = MaybeUninit::uninit();
    let result = unsafe {
        IsWow64Process2(
            handle,
            process_machine_info.as_mut_ptr(),
            native_machine_info.as_mut_ptr(),
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }

    let process_machine_info = unsafe { process_machine_info.assume_init() };
    let native_machine_info = unsafe { native_machine_info.assume_init() };

    let is_wow64 = process_machine_info != IMAGE_FILE_MACHINE_UNKNOWN;
    let native_bitness = get_bitness(native_machine_info);
    let (process_bitness, _machine_bitness) = if is_wow64 {
        let process_bitness = get_bitness(process_machine_info);
        (process_bitness, native_bitness)
    } else {
        (native_bitness, native_bitness)
    };

    Ok(ArchitectureInfo {
        process_bitness,
        _machine_bitness,
        is_wow64,
    })
}
