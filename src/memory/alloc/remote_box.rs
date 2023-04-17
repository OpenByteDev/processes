use std::{cell::RefCell, marker::PhantomData, mem, ptr::NonNull, rc::Rc, slice};

use crate::{
    memory::{
        alloc::{Allocation, DynamicMultiBufferAllocator, RawAllocator},
        ProcessMemorySlice,
    },
    BorrowedProcess, OwnedProcess, ProcessError,
};

#[derive(Debug, Clone)]
pub struct RemoteBoxAllocator(pub(crate) Rc<RemoteBoxAllocatorInner>);

#[derive(Debug)]
pub(crate) struct RemoteBoxAllocatorInner {
    pub(crate) process: OwnedProcess,
    pub(crate) allocator: RefCell<DynamicMultiBufferAllocator<'static>>,
}

impl RemoteBoxAllocator {
    #[must_use]
    pub fn new(process: OwnedProcess) -> Self {
        Self(Rc::new(RemoteBoxAllocatorInner {
            allocator: RefCell::new(DynamicMultiBufferAllocator::new(unsafe {
                process.borrow_static()
            })),
            process,
        }))
    }

    #[must_use]
    pub fn process(&self) -> BorrowedProcess<'_> {
        self.0.process.borrowed()
    }

    pub fn alloc_raw(&self, size: usize) -> Result<RemoteAllocation, ProcessError> {
        // TODO: optimize empty allocations
        let allocation = self.0.allocator.borrow_mut().alloc(size)?;
        Ok(RemoteAllocation::new(self.clone(), allocation))
    }
    pub fn alloc_uninit<T: Copy>(&self) -> Result<RemoteBox<T>, ProcessError> {
        let allocation = self.alloc_raw(mem::size_of::<T>())?;
        Ok(unsafe { RemoteBox::new(allocation) })
    }
    pub fn alloc_uninit_for<T: Copy>(&self, value: &T) -> Result<RemoteBox<T>, ProcessError> {
        let allocation = self.alloc_raw(mem::size_of_val(value))?;
        Ok(unsafe { RemoteBox::new(allocation) })
    }
    pub fn alloc_and_copy<T: Copy>(&self, value: &T) -> Result<RemoteBox<T>, ProcessError> {
        let b = self.alloc_uninit_for(value)?;
        b.write(value)?;
        Ok(b)
    }
    pub fn alloc_buf<T: Copy>(&self, len: usize) -> Result<RemoteAllocation, ProcessError> {
        let allocation = self.alloc_raw(len * mem::size_of::<T>())?;
        Ok(allocation)
    }
    pub fn alloc_and_copy_buf<T: Copy>(&self, buf: &[T]) -> Result<RemoteAllocation, ProcessError> {
        let bytes = unsafe {
            slice::from_raw_parts(buf.as_ptr() as *const u8, mem::size_of_val(buf))
        };
        let allocation = self.alloc_raw(bytes.len())?;
        allocation.write_bytes(bytes)?;
        Ok(allocation)
    }

    fn free(&self, allocation: &Allocation) {
        self.0.allocator.borrow_mut().free(allocation);
    }
}

#[derive(Debug)]
pub struct RemoteAllocation {
    allocation: Allocation,
    allocator: RemoteBoxAllocator,
}

impl RemoteAllocation {
    #[must_use]
    const fn new(allocator: RemoteBoxAllocator, allocation: Allocation) -> Self {
        Self {
            allocation,
            allocator,
        }
    }

    #[must_use]
    pub fn process(&self) -> BorrowedProcess<'_> {
        self.allocator.process()
    }

    #[must_use]
    pub fn memory(&self) -> ProcessMemorySlice<'_> {
        unsafe {
            ProcessMemorySlice::from_raw_parts(
                self.allocation.as_raw_ptr(),
                self.allocation.len,
                self.process(),
            )
        }
    }

    pub fn write_bytes(&self, value: &[u8]) -> Result<(), ProcessError> {
        self.memory().write(value)
    }

    pub fn read_bytes(&self, buf: &mut [u8]) -> Result<(), ProcessError> {
        self.memory().read(buf)
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.allocation.len
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[must_use]
    pub const fn as_ptr(&self) -> NonNull<u8> {
        self.allocation.as_ptr()
    }

    #[must_use]
    pub const fn as_raw_ptr(&self) -> *mut u8 {
        self.allocation.as_raw_ptr()
    }
}

impl Drop for RemoteAllocation {
    fn drop(&mut self) {
        self.allocator.free(&self.allocation);
    }
}

#[derive(Debug)]
pub struct RemoteBox<T: ?Sized> {
    allocation: RemoteAllocation,
    phantom: PhantomData<T>,
}

impl<T: ?Sized> RemoteBox<T> {
    #[must_use]
    pub(crate) unsafe fn new(allocation: RemoteAllocation) -> Self {
        Self {
            allocation,
            phantom: PhantomData,
        }
    }

    #[must_use]
    pub fn process(&self) -> BorrowedProcess<'_> {
        self.allocation.process()
    }

    #[must_use]
    pub fn memory(&self) -> ProcessMemorySlice<'_> {
        self.allocation.memory()
    }

    #[must_use]
    pub const fn as_raw_ptr(&self) -> *mut u8 {
        self.allocation.as_raw_ptr()
    }
}

impl<T: ?Sized + Copy> RemoteBox<T> {
    pub fn write(&self, value: &T) -> Result<(), ProcessError> {
        self.allocation.memory().write_struct(value)
    }
}

impl<T: Sized + Copy> RemoteBox<T> {
    pub fn read(&self) -> Result<T, ProcessError> {
        unsafe { self.allocation.memory().read_struct() }
    }

    #[must_use]
    pub const fn as_ptr(&self) -> NonNull<T> {
        self.allocation.as_ptr().cast()
    }
}
