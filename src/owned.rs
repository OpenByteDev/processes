use std::{
    fmt::Debug,
    io,
    os::windows::prelude::{
        AsRawHandle, BorrowedHandle, FromRawHandle, IntoRawHandle, OwnedHandle,
    },
    process::Child,
};

use winapi::{
    shared::minwindef::FALSE,
    um::{
        processthreadsapi::OpenProcess,
        winnt::{
            PROCESS_CREATE_THREAD, PROCESS_DUP_HANDLE, PROCESS_QUERY_INFORMATION,
            PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, PROCESS_VM_READ,
            PROCESS_VM_WRITE, SYNCHRONIZE,
        },
    },
};

use crate::{
    error::ProcessError, raw, BorrowedProcess, FromRawProcessHandle, Process, ProcessHandle,
    RawProcessHandle,
};

/// A struct representing a running process.
/// This struct owns the underlying process handle (see also [`BorrowedProcess`] for a borrowed version).
pub type OwnedProcess = Process<OwnedHandle>;

impl ProcessHandle for OwnedHandle {
    fn try_clone(&self) -> io::Result<Self>
    where
        Self: Sized,
    {
        self.try_clone()
    }
}

impl FromRawProcessHandle for OwnedHandle {
    unsafe fn from_raw_process_handle(handle: RawProcessHandle) -> Self {
        unsafe { FromRawHandle::from_raw_handle(handle) }
    }
}

#[allow(warnings)]
unsafe impl Send for OwnedProcess {}
#[allow(warnings)]
unsafe impl Sync for OwnedProcess {}

impl From<Child> for OwnedProcess {
    fn from(child: Child) -> Self {
        Self::from_child(child)
    }
}

impl TryFrom<BorrowedProcess<'_>> for OwnedProcess {
    type Error = ProcessError;

    fn try_from(process: BorrowedProcess<'_>) -> Result<Self, Self::Error> {
        process.try_to_owned()
    }
}

impl OwnedProcess {
    /// Creates a new instance from the given pid.
    pub fn from_pid(pid: u32) -> Result<OwnedProcess, ProcessError> {
        unsafe {
            Self::from_pid_with_access(
                pid,
                PROCESS_CREATE_THREAD
                    | PROCESS_DUP_HANDLE
                    | PROCESS_QUERY_INFORMATION
                    | PROCESS_TERMINATE
                    | PROCESS_VM_READ
                    | PROCESS_VM_WRITE
                    | SYNCHRONIZE
                    | PROCESS_QUERY_LIMITED_INFORMATION,
            )
        }
    }

    /// Creates a new instance from the given pid and the given privileges.
    ///
    /// # Safety
    /// `access` must be a valid set of process-specific access rights.
    pub unsafe fn from_pid_with_access(
        pid: u32,
        access: u32,
    ) -> Result<OwnedProcess, ProcessError> {
        let handle = unsafe { OpenProcess(access, FALSE, pid) };

        if handle.is_null() {
            return Err(io::Error::last_os_error().into());
        }

        Ok(unsafe { OwnedProcess::from_raw_handle(handle) })
    }

    /// Returns a list of all currently running processes.
    pub fn all() -> Result<impl Iterator<Item = OwnedProcess>, ProcessError> {
        let iter = raw::iter_process_ids()?
            .map(OwnedProcess::from_pid)
            .filter_map(|r| r.ok());
        Ok(iter)
    }

    /// Finds all processes whose name contains the given string.
    pub fn find_all_by_name(
        name: impl AsRef<str>,
    ) -> Result<impl Iterator<Item = OwnedProcess>, ProcessError> {
        let target_name = name.as_ref().to_ascii_lowercase();
        // TODO: optimize
        let iter = Self::all()?.filter(move |process| {
            let name = match process.base_name() {
                Ok(name) => name,
                Err(_) => return false,
            };
            name.to_ascii_lowercase().contains(&target_name)
        });
        Ok(iter)
    }

    /// Finds the first process whose name contains the given string.
    pub fn find_first_by_name(name: impl AsRef<str>) -> Result<Option<OwnedProcess>, ProcessError> {
        Ok(Self::find_all_by_name(name)?.next())
    }

    /// Creates a new instance from the given child process.
    #[must_use]
    pub fn from_child(child: Child) -> OwnedProcess {
        unsafe { OwnedProcess::from_raw_handle(child.into_raw_handle()) }
    }

    /// Returns a borrowed instance of this process that lives for `'static`.
    ///
    /// # Safety
    /// - This method is unsafe as the returned instance can outlive the owned instance,
    /// thus the caller must guarantee that the owned instance outlives the returned instance.
    #[must_use]
    #[doc(hidden)]
    pub unsafe fn borrow_static(&self) -> BorrowedProcess<'static> {
        unsafe { BorrowedProcess::from_handle(BorrowedHandle::borrow_raw(self.as_raw_handle())) }
    }

    /// Leaks the underlying handle and return it as a non-owning [`BorrowedProcess`] instance.
    #[allow(clippy::must_use_candidate)]
    pub fn leak(self) -> BorrowedProcess<'static> {
        unsafe { self.borrow_static() }
    }

    /// Returns a [`ProcessKillGuard`] wrapping this process that will automatically kill this process when dropped.
    #[must_use]
    pub const fn kill_on_drop(self) -> ProcessKillGuard {
        ProcessKillGuard(self)
    }
}

#[derive(Debug, shrinkwraprs::Shrinkwrap)]
#[shrinkwrap(mutable)]
/// A guard wrapping a [`OwnedProcess`] that will be automatically killed on drop.
pub struct ProcessKillGuard(pub OwnedProcess);

impl Drop for ProcessKillGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}
