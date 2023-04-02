use std::io;

use thiserror::Error;
use winapi::shared::winerror::ERROR_PARTIAL_COPY;

#[derive(Debug, Error)]
/// Error enum representing an error of an operation on a process.
pub enum ProcessError {
    /// Variant representing an inaccessible target process.
    /// This can occur if it crashed or was terminated.
    #[error("inaccessible target process")]
    ProcessInaccessible,
    /// Variant representing an illegal interior nul value in the module path.
    #[error("path contains illegal interior nul")]
    IllegalPath(#[from] widestring::error::ContainsNul<u16>),
    /// Variant representing an windows api error.
    #[error("io error: {}", _0)]
    Io(io::Error),
    // #[error("native error: {:#04x}", _0.code())]
    // Native(winresult::NtStatus),
}

impl From<io::Error> for ProcessError {
    fn from(err: io::Error) -> Self {
        if err.raw_os_error() == Some(ERROR_PARTIAL_COPY as _)
            || err.kind() == io::ErrorKind::PermissionDenied
        {
            Self::ProcessInaccessible
        } else {
            Self::Io(err)
        }
    }
}

#[derive(Debug, Error)]
/// Error enum representing either a windows api error or a nul error from an invalid interior nul.
pub enum IoOrNulError {
    /// Variant representing an illegal interior nul value.
    #[error("interior nul found")]
    Nul(#[from] widestring::error::ContainsNul<u16>),
    /// Variant representing an windows api error.
    #[error("io error: {}", _0)]
    Io(#[from] io::Error),
}

/// Error enum for errors during a call to [`ProcessModule::get_local_procedure_address`].
///
/// [`ProcessModule::get_local_procedure_address`]: crate::ProcessModule::get_local_procedure_address
#[derive(Debug, Error)]
pub enum GetLocalProcedureAddressError {
    /// Variant representing an inaccessible target process.
    /// This can occur if it crashed or was terminated.
    #[error("inaccessible target process")]
    ProcessInaccessible,
    /// Variant representing an illegal interior nul value in the module path.
    #[error("path contains illegal interior nul")]
    IllegalPath,
    /// Variant representing an windows api error.
    #[error("io error: {}", _0)]
    Io(io::Error),
    /// Variant representing an unsupported target process.
    #[error("unsupported remote target process")]
    UnsupportedRemoteTarget,
}

impl From<io::Error> for GetLocalProcedureAddressError {
    fn from(err: io::Error) -> Self {
        if err.raw_os_error() == Some(ERROR_PARTIAL_COPY as _)
            || err.kind() == io::ErrorKind::PermissionDenied
        {
            Self::ProcessInaccessible
        } else {
            Self::Io(err)
        }
    }
}

impl From<ProcessError> for GetLocalProcedureAddressError {
    fn from(err: ProcessError) -> Self {
        match err {
            ProcessError::ProcessInaccessible => Self::ProcessInaccessible,
            ProcessError::IllegalPath(_) => Self::IllegalPath,
            ProcessError::Io(e) => Self::Io(e),
        }
    }
}

impl From<widestring::error::ContainsNul<u16>> for GetLocalProcedureAddressError {
    fn from(_err: widestring::error::ContainsNul<u16>) -> Self {
        Self::IllegalPath
    }
}

impl From<std::ffi::FromBytesWithNulError> for GetLocalProcedureAddressError {
    fn from(_err: std::ffi::FromBytesWithNulError) -> Self {
        Self::IllegalPath
    }
}

impl From<std::ffi::NulError> for GetLocalProcedureAddressError {
    fn from(_err: std::ffi::NulError) -> Self {
        Self::IllegalPath
    }
}
