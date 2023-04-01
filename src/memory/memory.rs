use std::{io, mem};

use crate::BorrowedProcess;

use super::{ProcessMemoryBuffer, ProcessMemorySlice};

/// A struct representing the memory region of a process.
#[cfg_attr(feature = "doc-cfg", doc(cfg(feature = "process-memory")))]
#[derive(Debug, Clone, Copy)]
pub struct ProcessMemory<'a> {
    pub process: BorrowedProcess<'a>,
}

impl ProcessMemory<'_> {
    /// Returns a slice of the memory region starting at the given pointer with the given length in this processes memory space.
    pub fn slice(&'_ self, ptr: *mut u8, len: usize) -> ProcessMemorySlice<'_> {
        unsafe { ProcessMemorySlice::from_raw_parts(ptr.cast(), len, self.process) }
    }

    /// Reads a value of type `T` from the given pointer from the memory space of this process.
    ///
    /// # Safety
    /// The caller must ensure that the designated region of memory contains a valid instance of type T.
    pub unsafe fn read_struct<T: Copy>(&self, ptr: *mut T) -> Result<T, io::Error> {
        let memory = self.slice(ptr.cast(), mem::size_of::<T>());
        unsafe { memory.read_struct() }
    }

    /// Copies a sequence of values of type `T` from the given pointer from the memory space of this process into the given buffer.
    ///
    /// # Safety
    /// The caller must ensure that the designated region of memory contains valid instances of type `T`.
    pub unsafe fn read_buf<T: Copy>(&self, ptr: *mut T, buf: &mut [T]) -> Result<(), io::Error> {
        let memory = self.slice(ptr.cast(), buf.len() * mem::size_of::<T>());
        unsafe { memory.read_buf(buf) }
    }

    /// Copies a sequence of values of type `T` from the given pointer from the memory space of this process into the a new [`Vec<T>`].
    ///
    /// # Safety
    /// The caller must ensure that the designated region of memory contains valid instances of type `T`.
    pub unsafe fn read_vec<T: Copy>(&self, ptr: *mut T, len: usize) -> Result<Vec<T>, io::Error> {
        let memory = self.slice(ptr.cast(), len * mem::size_of::<T>());
        unsafe { memory.read_vec(len) }
    }

    /// Copies a sequence of values of type `T` from the given pointer from the memory space of this process into the a new [`Vec<T>`].
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn read_bytes(&self, ptr: *mut u8, len: usize) -> Result<Vec<u8>, io::Error> {
        unsafe { self.read_vec(ptr, len) }
    }

    /// Copies the contents of the given local buffer to the given pointer.
    pub fn write_bytes(&self, ptr: *mut u8, buf: &[u8]) -> Result<(), io::Error> {
        self.write_buf(ptr, buf)
    }

    /// Copies the contents of the given local buffer to the given pointer.
    pub fn write_buf<T: Copy>(&self, ptr: *mut T, buf: &[T]) -> Result<(), io::Error> {
        self.slice(ptr.cast(), buf.len() * mem::size_of::<T>())
            .write_buf(buf)
    }

    /// Writes a value of type `T` to the given pointer.
    pub fn write_struct<T: ?Sized + Copy>(&self, ptr: *mut T, s: &T) -> Result<(), io::Error> {
        self.slice(ptr.cast(), mem::size_of::<T>()).write_struct(s)
    }

    /// Allocates a new buffer of the given length in this memory region. Both data and code can be stored in the buffer.
    pub fn allocate(&self, len: usize) -> Result<ProcessMemoryBuffer<'_>, io::Error> {
        ProcessMemoryBuffer::allocate(self.process, len)
    }
}
