use winapi::shared::minwindef::{__some_function, FARPROC};

/// Type alias for a raw untyped function pointer.
pub type RawFunctionPtr = FARPROC;
/// Type alias for the pointee of a raw function pointer.
pub type RawFunctionPtrTarget = __some_function;
