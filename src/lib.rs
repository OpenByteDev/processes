#![cfg(windows)]
#![feature(maybe_uninit_uninit_array, maybe_uninit_slice, linked_list_cursors)]
#![warn(
    unsafe_op_in_unsafe_fn,
    missing_docs,
    missing_debug_implementations,
    missing_copy_implementations,
    rust_2018_idioms,
    clippy::todo,
    clippy::manual_assert,
    clippy::must_use_candidate,
    clippy::inconsistent_struct_constructor,
    clippy::wrong_self_convention,
    clippy::new_without_default,
    rustdoc::broken_intra_doc_links,
    rustdoc::private_intra_doc_links
)]
#![allow(
    clippy::module_inception,
    clippy::module_name_repetitions,
    clippy::missing_errors_doc,
    clippy::borrow_as_ptr
)]
#![cfg_attr(feature = "doc-cfg", doc = include_str!("../crate-doc.md"))]
#![cfg_attr(not(feature = "doc-cfg"), allow(missing_docs))]
#![cfg_attr(feature = "doc-cfg", feature(doc_cfg))]

mod process;
pub use process::*;

mod owned;
pub use owned::*;

mod borrowed;
pub use borrowed::*;

mod module;
pub use module::*;

/// Module containing utilities for dealing with memory of another process.
pub mod memory;

/// Module containing error types for this crate.
pub mod error;

/// Module containing function pointer related types.
pub mod function;

mod utils;

/// Returns an abstraction for the current process.
#[must_use]
pub fn current() -> BorrowedProcess<'static> {
    BorrowedProcess::current()
}

/// Returns a list of all currently running processes.
#[must_use]
pub fn all() -> Vec<OwnedProcess> {
    OwnedProcess::all()
}

/// Finds all processes whose name contains the given string.
pub fn find_all_by_name(name: impl AsRef<str>) -> Vec<OwnedProcess> {
    OwnedProcess::find_all_by_name(name)
}

/// Finds the first process whose name contains the given string.
pub fn find_first_by_name(name: impl AsRef<str>) -> Option<OwnedProcess> {
    OwnedProcess::find_first_by_name(name)
}
