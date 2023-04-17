use std::{
    io,
    marker::PhantomData,
    mem::{self, ManuallyDrop, MaybeUninit},
    ops::{Deref, DerefMut, RangeBounds},
    os::windows::prelude::AsRawHandle,
    ptr, slice,
};

use winapi::{
    shared::minwindef::DWORD,
    um::{
        memoryapi::{ReadProcessMemory, VirtualAllocEx, VirtualFreeEx, WriteProcessMemory},
        processthreadsapi::FlushInstructionCache,
        sysinfoapi::GetSystemInfo,
        winnt::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE},
    },
};

use crate::{error::ProcessError, utils, BorrowedProcess};

/// Returns the memory page size of the operating system.
#[must_use]
pub fn os_page_size() -> usize {
    // TODO: use OnceCell
    let mut system_info = MaybeUninit::uninit();
    unsafe { GetSystemInfo(system_info.as_mut_ptr()) };
    unsafe { system_info.assume_init() }.dwPageSize as usize
}

/// A owned buffer in the memory space of some process.
#[derive(Debug)]
pub struct ProcessMemoryBuffer<'a>(ProcessMemorySlice<'a>);

impl<'a> Deref for ProcessMemoryBuffer<'a> {
    type Target = ProcessMemorySlice<'a>;

    fn deref(&self) -> &ProcessMemorySlice<'a> {
        &self.0
    }
}
impl<'a> DerefMut for ProcessMemoryBuffer<'a> {
    fn deref_mut(&mut self) -> &mut ProcessMemorySlice<'a> {
        &mut self.0
    }
}
impl<'a> AsRef<ProcessMemorySlice<'a>> for ProcessMemoryBuffer<'a> {
    fn as_ref(&self) -> &ProcessMemorySlice<'a> {
        self.deref()
    }
}
impl<'a> AsMut<ProcessMemorySlice<'a>> for ProcessMemoryBuffer<'a> {
    fn as_mut(&mut self) -> &mut ProcessMemorySlice<'a> {
        self.deref_mut()
    }
}

impl<'a> ProcessMemoryBuffer<'a> {
    /// Allocates a new buffer of the given length in the given process. Both data and code can be stored in the buffer.
    pub fn allocate(process: BorrowedProcess<'a>, len: usize) -> Result<Self, ProcessError> {
        Self::allocate_code(process, len)
    }
    /// Allocates a new buffer with the size of a memory page in the given process.
    pub fn allocate_page(process: BorrowedProcess<'a>) -> Result<Self, ProcessError> {
        Self::allocate_code(process, os_page_size())
    }
    /// Allocates a new data buffer of the given length in the given process.
    pub fn allocate_data(process: BorrowedProcess<'a>, len: usize) -> Result<Self, ProcessError> {
        Self::allocate_with_options(process, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    }
    /// Allocates a new data buffer with the size of a memory page in the given process.
    pub fn allocate_data_page(process: BorrowedProcess<'a>) -> Result<Self, ProcessError> {
        Self::allocate_data(process, os_page_size())
    }
    /// Allocates a new code buffer of the given length in the given process.
    pub fn allocate_code(process: BorrowedProcess<'a>, len: usize) -> Result<Self, ProcessError> {
        Self::allocate_with_options(
            process,
            len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    }
    /// Allocates a new code buffer with the size of a memory page in the given process.
    pub fn allocate_code_page(process: BorrowedProcess<'a>) -> Result<Self, ProcessError> {
        Self::allocate_code(process, os_page_size())
    }
    fn allocate_with_options(
        process: BorrowedProcess<'a>,
        len: usize,
        allocation_type: DWORD,
        protection: DWORD,
    ) -> Result<Self, ProcessError> {
        let ptr = unsafe {
            VirtualAllocEx(
                process.as_raw_handle(),
                ptr::null_mut(),
                len,
                allocation_type,
                protection,
            )
        };

        return if ptr.is_null() {
            Err(io::Error::last_os_error().into())
        } else {
            Ok(unsafe { Self::from_raw_parts(ptr.cast(), len, process) })
        };
    }

    /// Allocates a new buffer with enough space to store a value of type `T` in the given process.
    pub fn allocate_for<T>(process: BorrowedProcess<'a>) -> Result<Self, ProcessError> {
        Self::allocate_data(process, mem::size_of::<T>())
    }

    /// Allocates a new buffer with enough space to store the given value in the given process and copies it.
    pub fn allocate_and_write<T: ?Sized + Copy>(
        process: BorrowedProcess<'a>,
        s: &T,
    ) -> Result<Self, ProcessError> {
        let buf = Self::allocate_data(process, mem::size_of_val(s))?;
        buf.write_struct(s)?;
        Ok(buf)
    }

    /// Constructs a new buffer from the given raw parts.
    ///
    /// # Safety
    /// The caller must ensure that the designated region of memory
    /// - is valid
    /// - was allocated using [`VirtualAllocEx`]
    /// - can be deallocated using [`VirtualFreeEx`]
    /// - can be read using [`ReadProcessMemory`]
    /// - can be written to using [`WriteProcessMemory`]
    /// - will not be deallocated by other code
    pub const unsafe fn from_raw_parts(
        ptr: *mut u8,
        len: usize,
        process: BorrowedProcess<'a>,
    ) -> Self {
        Self(unsafe { ProcessMemorySlice::from_raw_parts(ptr, len, process) })
    }

    /// Destructs this buffer into its raw parts.
    /// This function leaks the underlying allocation.
    #[must_use]
    pub fn into_raw_parts(self) -> (*mut u8, usize, BorrowedProcess<'a>) {
        let parts = (self.ptr, self.len, self.process);
        self.leak();
        parts
    }

    /// Leaks this buffer and returns a [`ProcessMemorySlice`] spanning it.
    #[allow(clippy::must_use_candidate)]
    pub fn leak(self) -> ProcessMemorySlice<'a> {
        let this = ManuallyDrop::new(self);
        this.0
    }

    /// Constructs a new slice spanning the whole buffer.
    #[must_use]
    pub fn as_slice(&self) -> ProcessMemorySlice<'a> {
        self.0
    }

    /// Frees the buffer.
    ///
    /// # Note
    /// The underlying allocation of this buffer is automatically freed on [`Drop`], but this function allows
    /// for more explicity and allows handling any error that occur.
    pub fn free(mut self) -> Result<(), (Self, io::Error)> {
        if let Err(ProcessError::Io(e)) = unsafe { self._free() } {
            Err((self, e))
        } else {
            Ok(())
        }
    }

    unsafe fn _free(&mut self) -> Result<(), ProcessError> {
        let result = unsafe {
            VirtualFreeEx(
                self.process.as_raw_handle(),
                self.as_ptr().cast(),
                0,
                MEM_RELEASE,
            )
        };

        if result != 0 || !self.process().is_alive() {
            Ok(())
        } else {
            Err(io::Error::last_os_error().into())
        }
    }
}

impl Drop for ProcessMemoryBuffer<'_> {
    fn drop(&mut self) {
        let result = unsafe { self._free() };
        debug_assert!(
            result.is_ok(),
            "Failed to free process memory buffer: {result:?}"
        );
    }
}

/// A unowned slice of a buffer in the memory space of a process.
#[derive(Debug, Clone, Copy)]
pub struct ProcessMemorySlice<'a> {
    process: BorrowedProcess<'a>,
    ptr: *mut u8,
    len: usize,
    data: PhantomData<&'a [u8]>,
}

impl<'a> ProcessMemorySlice<'a> {
    /// Constructs a new slice from the given raw parts.
    ///
    /// # Safety
    /// The caller must ensure that the designated region of memory
    /// - is valid
    /// - can be read using [`ReadProcessMemory`]
    /// - can be written to using [`WriteProcessMemory`]
    /// - will live as long as the slice is used
    pub const unsafe fn from_raw_parts(
        ptr: *mut u8,
        len: usize,
        process: BorrowedProcess<'a>,
    ) -> Self {
        Self {
            ptr,
            len,
            process,
            data: PhantomData,
        }
    }

    /// Returns whether this slice is in the memory space of the current process.
    #[must_use]
    pub fn is_local(&self) -> bool {
        self.process().is_current()
    }

    /// Returns whether this slice is in the memory space of another process.
    #[must_use]
    pub fn is_remote(&self) -> bool {
        !self.is_local()
    }

    /// Returns the process that owns the memory of this slice.
    #[must_use]
    pub const fn process(&self) -> BorrowedProcess<'a> {
        self.process
    }

    /// Returns the length of the slice.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the slice is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Copies the contents of this slice to the given local buffer.
    ///
    /// # Panics
    /// This function will panic if this slice is smaller than the given buffer.
    pub fn read(&self, buf: &mut [u8]) -> Result<(), ProcessError> {
        assert!(buf.len() <= self.len, "read out of bounds");

        if self.is_local() {
            unsafe {
                ptr::copy(self.ptr, buf.as_mut_ptr(), buf.len());
            }
            return Ok(());
        }

        let mut bytes_read = 0;
        let result = unsafe {
            ReadProcessMemory(
                self.process.as_raw_handle(),
                self.ptr.cast(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut bytes_read,
            )
        };
        if result == 0 {
            Err(io::Error::last_os_error().into())
        } else {
            assert_eq!(bytes_read, buf.len());
            Ok(())
        }
    }

    /// Copies the contents of this slice to the given local buffer.
    ///
    /// # Safety
    /// The caller must ensure that the designated region of memory contains valid instances of type `T`.
    ///
    /// # Panics
    /// This function will panic if this slice is smaller than the given buffer.
    pub unsafe fn read_buf<T: Copy>(&self, buf: &mut [T]) -> Result<(), ProcessError> {
        let byte_buf = unsafe {
            slice::from_raw_parts_mut(buf.as_mut_ptr().cast(), mem::size_of_val(buf))
        };
        self.read(byte_buf)
    }

    /// Copies `len` instances of type `T` at the start of this slice into a newly allocated local [`Vec<T>`].
    ///
    /// # Safety
    /// The caller must ensure that the designated region of memory contains valid instances of type `T`.
    ///
    /// # Panics
    /// This function will panic if this slice is smaller than the given buffer.
    pub unsafe fn read_vec<T: Copy>(&self, len: usize) -> Result<Vec<T>, ProcessError> {
        let mut buf = Vec::with_capacity(len);
        unsafe { self.read_buf(buf.spare_capacity_mut())? };
        unsafe { buf.set_len(len) };
        Ok(buf)
    }

    /// Reads a value of type `T` from the start this slice and copies it into local memory space.
    ///
    /// # Panics
    /// This function will panic if the size of the value exceeds this slice's length.
    ///
    /// # Safety
    /// The caller must ensure that the designated region of memory contains a valid instance of type `T`.
    pub unsafe fn read_struct<T: Copy>(&self) -> Result<T, ProcessError> {
        let mut uninit_value = MaybeUninit::<T>::uninit();
        // TODO: use uninit_value.as_bytes instead
        let buf = unsafe {
            slice::from_raw_parts_mut(uninit_value.as_mut_ptr().cast(), mem::size_of::<T>())
        };
        self.read(buf)?;
        Ok(unsafe { uninit_value.assume_init() })
    }

    /// Copies the contents of the given local buffer to this slice.
    ///
    /// # Panics
    /// This function will panic if the size of the local buffer exceeds this slice's length.
    pub fn write(&self, buf: &[u8]) -> Result<(), ProcessError> {
        assert!(buf.len() <= self.len, "write out of bounds");

        if self.is_local() {
            unsafe {
                ptr::copy(buf.as_ptr(), self.ptr, buf.len());
            }
            return Ok(());
        }

        let mut bytes_written = 0;
        let result = unsafe {
            WriteProcessMemory(
                self.process.as_raw_handle(),
                self.ptr.cast(),
                buf.as_ptr().cast(),
                buf.len(),
                &mut bytes_written,
            )
        };
        if result == 0 {
            Err(io::Error::last_os_error().into())
        } else {
            assert_eq!(bytes_written, buf.len());
            Ok(())
        }
    }

    /// Copies the contents of the given local buffer to the memory region of this slice.
    ///
    /// # Panics
    /// This function will panic if the size of the local buffer exceeds this slice's length.
    pub fn write_buf<T: Copy>(&self, buf: &[T]) -> Result<(), ProcessError> {
        let byte_buf =
            unsafe { slice::from_raw_parts(buf.as_ptr().cast(), mem::size_of_val(buf)) };
        self.write(byte_buf)
    }

    /// Writes a value of type `T` to the start of this slice.
    ///
    /// # Panics
    /// This function will panic if the value's size exceeds this buffer's length.
    pub fn write_struct<T: ?Sized + Copy>(&self, s: &T) -> Result<(), ProcessError> {
        let buf = unsafe { slice::from_raw_parts(s as *const T as *const u8, mem::size_of_val(s)) };
        self.write(buf)
    }

    /// Returns a pointer to the start of this slice.
    ///
    /// # Note
    /// The returned pointer is only valid in the target process.
    #[must_use]
    pub const fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }

    /// Returns a new slice spanning a subregion of this slice.
    #[must_use]
    pub fn slice(&self, bounds: impl RangeBounds<usize>) -> Self {
        let range = utils::range_from_bounds(self.ptr as usize, self.len, &bounds);
        Self {
            process: self.process,
            ptr: range.start as *mut _,
            len: range.len(),
            data: PhantomData,
        }
    }

    /// Constructs a new local slice spanning the memory of this slice.
    /// This function will return [None] for remote memory slices.
    #[must_use]
    pub fn as_local_slice(&self) -> Option<&[u8]> {
        if self.is_local() {
            Some(unsafe { slice::from_raw_parts(self.ptr, self.len) })
        } else {
            None
        }
    }

    /// Constructs a new mutable slice spanning the memory of this slice.
    /// This function will return [None] for remote memory slices.
    #[must_use]
    pub fn as_local_slice_mut(&mut self) -> Option<&mut [u8]> {
        if self.is_local() {
            Some(unsafe { slice::from_raw_parts_mut(self.ptr, self.len) })
        } else {
            None
        }
    }

    /// Flushes the CPU instruction cache for the whole slice.
    /// This may be necesary if the memory is used to store dynamically generated code. For details see [`FlushInstructionCache`].
    ///
    /// [`FlushInstructionCache`]: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-flushinstructioncache
    pub fn flush_instruction_cache(&self) -> Result<(), ProcessError> {
        let result = unsafe {
            FlushInstructionCache(self.process.as_raw_handle(), self.as_ptr().cast(), self.len)
        };
        if result == 0 {
            Err(io::Error::last_os_error().into())
        } else {
            Ok(())
        }
    }
}
