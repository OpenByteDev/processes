use std::{io, os::windows::prelude::BorrowedHandle};

use crate::{FromRawProcessHandle, Process, ProcessHandle, RawProcessHandle};

/// A struct representing a running process.
/// This struct does **NOT** own the underlying process handle (see also [`OwnedProcess`](crate::OwnedProcess) for an owned version).
pub type BorrowedProcess<'a> = Process<BorrowedHandle<'a>>;

impl ProcessHandle for BorrowedHandle<'_> {
    fn try_clone(&self) -> io::Result<Self>
    where
        Self: Sized,
    {
        Ok(*self)
    }
}

impl FromRawProcessHandle for BorrowedHandle<'_> {
    unsafe fn from_raw_process_handle(handle: RawProcessHandle) -> Self {
        unsafe { BorrowedHandle::borrow_raw(handle) }
    }
}

#[allow(warnings)]
unsafe impl Send for BorrowedProcess<'_> {}
#[allow(warnings)]
unsafe impl Sync for BorrowedProcess<'_> {}

impl<'a, Handle: ProcessHandle> From<&'a Process<Handle>> for BorrowedProcess<'a> {
    fn from(process: &'a Process<Handle>) -> Self {
        process.borrowed()
    }
}

/*
impl<'a> BorrowedProcess<'a> {
    pub fn find_module_by_name(
        &self,
        module_name: impl AsRef<Path>,
    ) -> Result<Option<BorrowedProcessModule<'a>>, ProcessError> {
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

    pub fn find_module_by_path(
        &self,
        module_path: impl AsRef<Path>,
    ) -> Result<Option<BorrowedProcessModule<'a>>, ProcessError> {
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

    pub fn wait_for_module_by_name(
        &self,
        module_name: impl AsRef<Path>,
        timeout: Duration,
    ) -> Result<Option<BorrowedProcessModule<'a>>, ProcessError> {
        retry_faillable_until_some_with_timeout(
            || self.find_module_by_name(module_name.as_ref()),
            timeout,
        )
    }

    pub fn wait_for_module_by_path(
        &self,
        module_path: impl AsRef<Path>,
        timeout: Duration,
    ) -> Result<Option<BorrowedProcessModule<'a>>, ProcessError> {
        retry_faillable_until_some_with_timeout(
            || self.find_module_by_path(module_path.as_ref()),
            timeout,
        )
    }
}

*/
