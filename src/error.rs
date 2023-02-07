use std::io;

use thiserror::Error;

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
    /// Variant representing an illegal interior nul value.
    #[error("interior nul found")]
    Nul(#[from] std::ffi::NulError),
    /// Variant representing an windows api error.
    #[error("io error: {}", _0)]
    Io(#[from] io::Error),
    /// Variant representing an unsupported target process.
    #[error("unsupported remote target process")]
    UnsupportedRemoteTarget,
}
