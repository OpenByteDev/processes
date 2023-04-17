use std::{
    ffi::{CStr, CString, OsStr, OsString},
    fmt::{self, Debug},
    io,
    mem::{self, MaybeUninit},
    os::windows::prelude::{AsRawHandle, BorrowedHandle, OwnedHandle},
    path::{Path, PathBuf},
    ptr::NonNull,
};

use crate::{
    error::{GetLocalProcedureAddressError, ProcessError},
    function::RawFunctionPtr,
    utils::{get_win_ffi_path, get_win_ffi_string, TryFillBufResult},
    Process, ProcessHandle, ProcessOrPathError,
};
use path_absolutize::Absolutize;
use widestring::{U16CStr, U16CString, U16Str};
use winapi::{
    shared::{
        minwindef::{HINSTANCE__, HMODULE, MAX_PATH},
        winerror::{ERROR_INSUFFICIENT_BUFFER, ERROR_MOD_NOT_FOUND},
    },
    um::{
        libloaderapi::{GetModuleFileNameW, GetModuleHandleW, GetProcAddress},
        memoryapi::VirtualQueryEx,
        psapi::{GetModuleBaseNameW, GetModuleFileNameExW},
        winnt::{MEMORY_BASIC_INFORMATION, PAGE_NOACCESS},
    },
};

/// A handle to a process module.
///
/// # Note
/// This is not a [`HANDLE`](https://docs.microsoft.com/en-us/windows/win32/winprog/windows-data-types#HANDLE)
/// but a [`HMODULE`](https://docs.microsoft.com/en-us/windows/win32/winprog/windows-data-types#HMODULE)
/// which is the base address of a loaded module.
pub type ModuleHandle = HMODULE;

/// The pointer target of a [`ModuleHandle`].
pub type ModuleHandleTarget = HINSTANCE__;

/// A struct representing a loaded module of a running process.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ProcessModule<P: ProcessHandle> {
    handle: NonNull<ModuleHandleTarget>,
    process: Process<P>,
}

impl<P: Copy + ProcessHandle> Copy for ProcessModule<P> {}

impl<P: ProcessHandle + Debug> Debug for ProcessModule<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProcessModule")
            .field("handle", &self.handle)
            .field("base_name", &self.base_name())
            .field("process", &self.process)
            .finish()
    }
}

/// Type alias for a [`ProcessModule`] that owns its [`Process`] instance.
pub type OwnedProcessModule = ProcessModule<OwnedHandle>;
/// Type alias for a [`ProcessModule`] that does **NOT** own its [`Process`] instance.
pub type BorrowedProcessModule<'a> = ProcessModule<BorrowedHandle<'a>>;

unsafe impl<P: ProcessHandle + Send> Send for ProcessModule<P> {}
unsafe impl<P: ProcessHandle + Sync> Sync for ProcessModule<P> {}

impl<P: ProcessHandle> ProcessModule<P> {
    /// Contructs a new instance from the given module handle and its corresponding process.
    ///
    /// # Safety
    /// The caller must guarantee that the given handle is valid and that the module is loaded into the given process.
    /// (and stays that way while using the returned instance).
    pub unsafe fn new_unchecked(handle: ModuleHandle, process: Process<P>) -> Self {
        debug_assert!(!handle.is_null());
        let handle = unsafe { NonNull::new_unchecked(handle) };
        Self { handle, process }
    }

    /// Contructs a new instance from the given module handle loaded in the current process.
    ///
    /// # Safety
    /// The caller must guarantee that the given handle is valid and that the module is loaded into the given process.
    /// (and stays that way while using the returned instance).
    pub unsafe fn new_local_unchecked(handle: ModuleHandle) -> Self {
        unsafe { ProcessModule::new_unchecked(handle, Process::current()) }
    }

    /// Returns a borrowed instance of this module.
    pub fn borrowed(&self) -> BorrowedProcessModule<'_> {
        ProcessModule {
            handle: self.handle,
            process: self.process.borrowed(),
        }
    }

    /// Searches for a module with the given name or path in the given process.
    /// If the extension is omitted, the default library extension `.dll` is appended.
    pub fn find(
        module_name_or_path: impl AsRef<Path>,
        process: Process<P>,
    ) -> Result<Option<ProcessModule<P>>, ProcessOrPathError> {
        let module_name_or_path = module_name_or_path.as_ref();
        if module_name_or_path.parent().is_some() {
            Self::find_by_path(module_name_or_path, process)
        } else {
            Self::find_by_name(module_name_or_path, process)
        }
    }

    /// Searches for a module with the given name in the given process.
    /// If the extension is omitted, the default library extension `.dll` is appended.
    pub fn find_by_name(
        module_name: impl AsRef<Path>,
        process: Process<P>,
    ) -> Result<Option<ProcessModule<P>>, ProcessOrPathError> {
        if process.is_current() {
            Self::find_local_by_name(module_name)
        } else {
            Self::_find_remote_by_name(module_name, process)
        }
    }

    /// Searches for a module with the given path in the given process.
    /// If the extension is omitted, the default library extension `.dll` is appended.
    pub fn find_by_path(
        module_path: impl AsRef<Path>,
        process: Process<P>,
    ) -> Result<Option<ProcessModule<P>>, ProcessOrPathError> {
        if process.is_current() {
            Self::find_local_by_path(module_path)
        } else {
            Self::_find_remote_by_path(module_path, process)
        }
    }

    /// Searches for a module with the given name or path in the current process.
    /// If the extension is omitted, the default library extension `.dll` is appended.
    pub fn find_local(
        module_name_or_path: impl AsRef<Path>,
    ) -> Result<Option<ProcessModule<P>>, ProcessOrPathError> {
        Self::find(module_name_or_path, Process::current())
    }

    /// Searches for a module with the given name in the current process.
    /// If the extension is omitted, the default library extension `.dll` is appended.
    pub fn find_local_by_name(
        module_name: impl AsRef<Path>,
    ) -> Result<Option<ProcessModule<P>>, ProcessOrPathError> {
        Self::find_local_by_name_or_abs_path(module_name.as_ref())
    }

    /// Searches for a module with the given path in the current process.
    /// If the extension is omitted, the default library extension `.dll` is appended.
    pub fn find_local_by_path(
        module_path: impl AsRef<Path>,
    ) -> Result<Option<ProcessModule<P>>, ProcessOrPathError> {
        let absolute_path = module_path.as_ref().absolutize()?;
        Self::find_local_by_name_or_abs_path(absolute_path.as_ref())
    }

    #[doc(hidden)]
    pub fn find_local_by_name_or_abs_path(
        module: &Path,
    ) -> Result<Option<ProcessModule<P>>, ProcessOrPathError> {
        let module_str = U16CString::from_os_str(module.as_os_str())?;
        let module = Self::find_local_by_name_or_abs_path_wstr(&module_str)?;
        Ok(module)
    }

    #[doc(hidden)]
    pub fn find_local_by_name_or_abs_path_wstr(
        module: &U16CStr,
    ) -> Result<Option<ProcessModule<P>>, ProcessError> {
        let handle = unsafe { GetModuleHandleW(module.as_ptr()) };
        if handle.is_null() {
            let err = io::Error::last_os_error();
            if err.raw_os_error().unwrap() == ERROR_MOD_NOT_FOUND as i32 {
                return Ok(None);
            }

            return Err(err.into());
        }

        Ok(Some(unsafe { Self::new_local_unchecked(handle) }))
    }

    fn _find_remote_by_name(
        module_name: impl AsRef<Path>,
        process: Process<P>,
    ) -> Result<Option<ProcessModule<P>>, ProcessOrPathError> {
        assert!(!process.is_current());

        process.find_module_by_name(module_name)
    }

    fn _find_remote_by_path(
        module_path: impl AsRef<Path>,
        process: Process<P>,
    ) -> Result<Option<ProcessModule<P>>, ProcessOrPathError> {
        assert!(!process.is_current());

        process.find_module_by_path(module_path)
    }

    /// Returns the underlying handle og the module.
    #[must_use]
    pub fn handle(&self) -> ModuleHandle {
        self.handle.as_ptr()
    }

    /// Returns the process this module is loaded in.
    #[must_use]
    pub fn process(&self) -> &Process<P> {
        &self.process
    }

    /// Returns a value indicating whether the module is loaded in current process.
    #[must_use]
    pub fn is_local(&self) -> bool {
        self.process().is_current()
    }
    /// Returns a value indicating whether the module is loaded in a remote process (not the current one).
    #[must_use]
    pub fn is_remote(&self) -> bool {
        !self.is_local()
    }

    /// Returns the path that the module was loaded from.
    pub fn path(&self) -> Result<PathBuf, ProcessError> {
        if self.is_local() {
            get_win_ffi_path(|buf_ptr, buf_size| {
                let buf_size = buf_size as u32;
                let result = unsafe { GetModuleFileNameW(self.handle(), buf_ptr, buf_size) };
                if result == 0 {
                    let err = io::Error::last_os_error();
                    if err.raw_os_error().unwrap() == ERROR_INSUFFICIENT_BUFFER as i32 {
                        TryFillBufResult::BufTooSmall { size_hint: None }
                    } else {
                        TryFillBufResult::Error(err.into())
                    }
                } else if result >= buf_size {
                    TryFillBufResult::BufTooSmall { size_hint: None }
                } else {
                    TryFillBufResult::Success {
                        actual_len: result as usize,
                    }
                }
            })
        } else {
            get_win_ffi_path(|buf_ptr, buf_size| {
                let buf_size = buf_size as u32;
                let result = unsafe {
                    GetModuleFileNameExW(
                        self.process().as_raw_handle(),
                        self.handle(),
                        buf_ptr,
                        buf_size,
                    )
                };
                if result == 0 {
                    let err = io::Error::last_os_error();
                    if err.raw_os_error().unwrap() == ERROR_INSUFFICIENT_BUFFER as i32 {
                        TryFillBufResult::BufTooSmall { size_hint: None }
                    } else {
                        TryFillBufResult::Error(err.into())
                    }
                } else if result >= buf_size {
                    TryFillBufResult::BufTooSmall { size_hint: None }
                } else {
                    TryFillBufResult::Success {
                        actual_len: result as usize,
                    }
                }
            })
        }
    }

    /// Returns the base name of the file the module was loaded from.
    pub fn base_name(&self) -> Result<String, ProcessError> {
        self._base_name(
            |path| path.to_string_lossy().to_string(),
            |buf| buf.to_string_lossy(),
        )
    }

    /// Returns the base name of the file the module was loaded from as an [OsString].
    pub fn base_name_os(&self) -> Result<OsString, ProcessError> {
        self._base_name(|path| path.to_os_string(), |buf| buf.to_os_string())
    }

    fn _base_name<S>(
        &self,
        map_local: impl FnOnce(&OsStr) -> S,
        map_remote: impl FnOnce(&U16Str) -> S,
    ) -> Result<S, ProcessError> {
        if self.is_local() {
            self.path().map(|path| map_local(path.file_name().unwrap()))
        } else {
            get_win_ffi_string::<MAX_PATH, S, ProcessError>(
                |buf_ptr, buf_size| {
                    let buf_size = buf_size as u32;
                    let result = unsafe {
                        GetModuleBaseNameW(
                            self.process().as_raw_handle(),
                            self.handle(),
                            buf_ptr,
                            buf_size,
                        )
                    };
                    if result == 0 {
                        let err = io::Error::last_os_error();
                        if err.raw_os_error().unwrap() == ERROR_INSUFFICIENT_BUFFER as i32 {
                            TryFillBufResult::BufTooSmall { size_hint: None }
                        } else {
                            TryFillBufResult::Error(err.into())
                        }
                    } else if result >= buf_size {
                        TryFillBufResult::BufTooSmall { size_hint: None }
                    } else {
                        TryFillBufResult::Success {
                            actual_len: result as usize,
                        }
                    }
                },
                |s| map_remote(s),
            )
        }
    }

    /// Returns a pointer to the procedure with the given name from this module.
    ///
    /// # Note
    /// This function is only supported for modules in the current process.
    pub fn get_local_procedure_address(
        &self,
        proc_name: impl AsRef<str>,
    ) -> Result<RawFunctionPtr, GetLocalProcedureAddressError> {
        if self.is_remote() {
            return Err(GetLocalProcedureAddressError::UnsupportedRemoteTarget);
        }

        let proc_name = CString::new(proc_name.as_ref())?;
        Ok(self.get_local_procedure_address_cstr(&proc_name)?)
    }

    /*
    /// Returns a pointer to the procedure with the given name from this module.
    ///
    /// # Note
    /// This function is only supported for modules in the current process.
    ///
    /// # Safety
    /// The target function must abide by the given function signature.
    pub unsafe fn get_local_procedure<F: FunctionPtr>(
        &self,
        proc_name: impl AsRef<str>,
    ) -> Result<F, GetLocalProcedureAddressError> {
        self.get_local_procedure_address(proc_name)
            .map(|addr| unsafe { F::from_ptr(addr) })
    }
    */

    #[doc(hidden)]
    pub fn get_local_procedure_address_cstr(
        &self,
        proc_name: &CStr,
    ) -> Result<RawFunctionPtr, ProcessError> {
        assert!(self.is_local());

        let fn_ptr = unsafe { GetProcAddress(self.handle(), proc_name.as_ptr()) };
        if let Some(fn_ptr) = NonNull::new(fn_ptr) {
            Ok(fn_ptr.as_ptr())
        } else {
            Err(io::Error::last_os_error().into())
        }
    }

    /// Returns whether this module is still loaded in the respective process.
    /// If the operation fails, the module is considered to be unloaded.
    pub fn guess_is_loaded(&self) -> bool {
        self.try_guess_is_loaded().unwrap_or(false)
    }

    /// Returns whether this module is still loaded in the respective process.
    pub fn try_guess_is_loaded(&self) -> Result<bool, ProcessError> {
        if !self.process().is_alive() {
            return Ok(false);
        }

        let mut module_info = MaybeUninit::uninit();
        let raw_module = self.handle.as_ptr().cast();
        let result = unsafe {
            VirtualQueryEx(
                self.process.as_raw_handle(),
                raw_module,
                module_info.as_mut_ptr(),
                mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };

        if result == 0 {
            Err(io::Error::last_os_error().into())
        } else {
            let module_info = unsafe { module_info.assume_init() };
            Ok(module_info.BaseAddress == raw_module && module_info.Protect != PAGE_NOACCESS)
        }
    }
}

impl BorrowedProcessModule<'_> {
    /// Trys to create a new [`OwnedProcessModule`] instance for this process module.
    pub fn try_to_owned(&self) -> Result<OwnedProcessModule, ProcessError> {
        self.process
            .try_to_owned()
            .map(|process| OwnedProcessModule {
                process,
                handle: self.handle,
            })
    }
}

impl TryFrom<BorrowedProcessModule<'_>> for OwnedProcessModule {
    type Error = ProcessError;

    fn try_from(module: BorrowedProcessModule<'_>) -> Result<Self, Self::Error> {
        module.try_to_owned()
    }
}

impl<'a> From<&'a OwnedProcessModule> for BorrowedProcessModule<'a> {
    fn from(module: &'a OwnedProcessModule) -> Self {
        module.borrowed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_local_by_name_present() {
        let result = BorrowedProcessModule::find_local_by_name("kernel32.dll");
        assert!(result.is_ok());
        assert!(result.as_ref().unwrap().is_some());

        let module = result.unwrap().unwrap();
        assert!(module.is_local());
        assert!(!module.handle().is_null());
    }

    #[test]
    fn find_local_by_name_absent() {
        let result = BorrowedProcessModule::find_local_by_name("kernel33.dll");
        assert!(&result.is_ok());
        assert!(result.unwrap().is_none());
    }
}
