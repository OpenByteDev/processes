mod buffer;
pub use buffer::*;

#[cfg(feature = "remote-alloc")]
#[cfg_attr(feature = "doc-cfg", doc(cfg(feature = "remote-alloc")))]
#[allow(missing_docs)]
pub mod alloc;
