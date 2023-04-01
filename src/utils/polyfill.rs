use std::mem::MaybeUninit;

#[must_use]
#[inline(always)]
pub(crate) fn maybe_uninit_uninit_array<T, const LEN: usize>() -> [MaybeUninit<T>; LEN] {
    #[cfg(feature = "nightly")]
    return MaybeUninit::<T>::uninit_array::<LEN>();
    #[cfg(not(feature = "nightly"))]
    #[allow(clippy::uninit_assumed_init)]
    unsafe {
        MaybeUninit::<[MaybeUninit<T>; LEN]>::uninit().assume_init()
    }
}

#[must_use]
#[inline(always)]
pub(crate) const unsafe fn maybe_uninit_slice_assume_init_ref<T>(slice: &[MaybeUninit<T>]) -> &[T] {
    #[cfg(feature = "nightly")]
    unsafe {
        MaybeUninit::slice_assume_init_ref(slice)
    }
    #[cfg(not(feature = "nightly"))]
    unsafe {
        &*(slice as *const [MaybeUninit<T>] as *const [T])
    }
}

#[must_use]
#[inline(always)]
pub(crate) unsafe fn maybe_uninit_slice_assume_init_mut<T>(
    slice: &mut [MaybeUninit<T>],
) -> &mut [T] {
    #[cfg(feature = "nightly")]
    unsafe {
        MaybeUninit::slice_assume_init_mut(slice)
    }
    #[cfg(not(feature = "nightly"))]
    unsafe {
        &mut *(slice as *mut [MaybeUninit<T>] as *mut [T])
    }
}
