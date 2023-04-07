use std::{
    borrow::Cow,
    hash::{Hash, Hasher},
    io,
    mem::{self, MaybeUninit},
    os::windows::{
        prelude::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle},
        raw::HANDLE,
    },
    path::Path,
    ptr::NonNull,
    time::Duration,
};

use memoffset::offset_of;
use ntapi::{
    ntldr::LDR_DATA_TABLE_ENTRY,
    ntpsapi::{
        NtQueryInformationProcess, ProcessBasicInformation, PEB_LDR_DATA, PROCESS_BASIC_INFORMATION,
    },
    ntrtl::RtlNtStatusToDosError,
};
use winapi::{
    shared::{minwindef::FALSE, ntdef::LIST_ENTRY},
    um::{
        handleapi::DuplicateHandle, processthreadsapi::GetCurrentProcess,
        winnt::DUPLICATE_SAME_ACCESS,
    },
};
use winresult::NtStatus;

use crate::{
    error::ProcessError, memory::ProcessMemory, utils::retry_faillable_until_some_with_timeout,
    ModuleHandle, OwnedProcess, Process, ProcessModule,
};

/// A struct representing a running process.
/// This struct does **NOT** own the underlying process handle (see also [`OwnedProcess`] for an owned version).
///
/// # Note
/// The underlying handle has the following [privileges](https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights):
///  - `PROCESS_CREATE_THREAD`
///  - `PROCESS_QUERY_INFORMATION`
///  - `PROCESS_VM_OPERATION`
///  - `PROCESS_VM_WRITE`
///  - `PROCESS_VM_READ`
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct BorrowedProcess<'a>(BorrowedHandle<'a>);

unsafe impl Send for BorrowedProcess<'_> {}
unsafe impl Sync for BorrowedProcess<'_> {}

impl AsRawHandle for BorrowedProcess<'_> {
    fn as_raw_handle(&self) -> HANDLE {
        self.0.as_raw_handle()
    }
}

impl AsHandle for BorrowedProcess<'_> {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        self.0.as_handle()
    }
}

impl<'a, 'b> PartialEq<BorrowedProcess<'a>> for BorrowedProcess<'b> {
    fn eq(&self, other: &BorrowedProcess<'a>) -> bool {
        // TODO: (unsafe { CompareObjectHandles(self.handle(), other.handle()) }) != FALSE

        self.as_raw_handle() == other.as_raw_handle()
            || self.pid().map_or(0, |v| v.get()) == other.pid().map_or(0, |v| v.get())
    }
}

impl PartialEq<OwnedProcess> for BorrowedProcess<'_> {
    fn eq(&self, other: &OwnedProcess) -> bool {
        self == &other.borrowed()
    }
}

impl PartialEq<BorrowedProcess<'_>> for OwnedProcess {
    fn eq(&self, other: &BorrowedProcess<'_>) -> bool {
        &self.borrowed() == other
    }
}

impl Eq for BorrowedProcess<'_> {}

impl Hash for BorrowedProcess<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_raw_handle().hash(state);
    }
}

impl<'a> From<&'a OwnedProcess> for BorrowedProcess<'a> {
    fn from(process: &'a OwnedProcess) -> Self {
        process.borrowed()
    }
}

impl<'a> Process for BorrowedProcess<'a> {
    type Handle = BorrowedHandle<'a>;

    fn borrowed(&self) -> BorrowedProcess<'a> {
        *self
    }

    fn into_handle(self) -> Self::Handle {
        self.0
    }

    fn try_clone(&self) -> Result<Self, ProcessError> {
        Ok(*self)
    }

    unsafe fn from_handle_unchecked(handle: Self::Handle) -> Self {
        Self(handle)
    }

    fn current_handle() -> Self::Handle {
        unsafe { BorrowedHandle::borrow_raw(Self::raw_current_handle()) }
    }

    fn find_module_by_name(
        &self,
        module_name: impl AsRef<Path>,
    ) -> Result<Option<ProcessModule<BorrowedProcess<'a>>>, ProcessError> {
        let target_module_name = module_name.as_ref();

        // add default file extension if missing
        let target_module_name = if target_module_name.extension().is_none() {
            Cow::Owned(target_module_name.with_extension("dll").into_os_string())
        } else {
            Cow::Borrowed(target_module_name.as_os_str())
        };

        let modules = self.module_handles()?;

        for module_handle in modules {
            let module = unsafe { ProcessModule::new_unchecked(module_handle?, *self) };
            let module_name = module.base_name_os()?;

            if module_name.eq_ignore_ascii_case(&target_module_name) {
                return Ok(Some(module));
            }
        }

        Ok(None)
    }

    fn find_module_by_path(
        &self,
        module_path: impl AsRef<Path>,
    ) -> Result<Option<ProcessModule<BorrowedProcess<'a>>>, ProcessError> {
        let target_module_path = module_path.as_ref();

        // add default file extension if missing
        let target_module_path = if target_module_path.extension().is_none() {
            Cow::Owned(target_module_path.with_extension("dll").into_os_string())
        } else {
            Cow::Borrowed(target_module_path.as_os_str())
        };

        let target_module_handle = same_file::Handle::from_path(&target_module_path)?;

        let modules = self.module_handles()?;

        for module_handle in modules {
            let module = unsafe { ProcessModule::new_unchecked(module_handle?, *self) };
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

    fn wait_for_module_by_name(
        &self,
        module_name: impl AsRef<Path>,
        timeout: Duration,
    ) -> Result<Option<ProcessModule<BorrowedProcess<'a>>>, ProcessError> {
        retry_faillable_until_some_with_timeout(
            || self.find_module_by_name(module_name.as_ref()),
            timeout,
        )
    }

    fn wait_for_module_by_path(
        &self,
        module_path: impl AsRef<Path>,
        timeout: Duration,
    ) -> Result<Option<ProcessModule<BorrowedProcess<'a>>>, ProcessError> {
        retry_faillable_until_some_with_timeout(
            || self.find_module_by_path(module_path.as_ref()),
            timeout,
        )
    }
}

impl<'a> BorrowedProcess<'a> {
    /// Tries to create a new [`OwnedProcess`] instance for this process.
    pub fn try_to_owned(&self) -> Result<OwnedProcess, ProcessError> {
        let raw_handle = self.as_raw_handle();
        let process = unsafe { GetCurrentProcess() };
        let mut new_handle = MaybeUninit::uninit();
        let result = unsafe {
            DuplicateHandle(
                process,
                raw_handle,
                process,
                new_handle.as_mut_ptr(),
                0,
                FALSE,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if result == 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(unsafe { OwnedProcess::from_raw_handle(new_handle.assume_init()) })
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
}
