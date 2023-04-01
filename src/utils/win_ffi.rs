use std::{cmp, io, mem::MaybeUninit, path::PathBuf};

use widestring::U16Str;
use winapi::shared::minwindef::MAX_PATH;

use super::{maybe_uninit_slice_assume_init_mut, ArrayBuf};

pub enum TryFillBufResult {
    BufTooSmall { size_hint: Option<usize> },
    Success { actual_len: usize },
    Error(io::Error),
}

pub fn get_win_ffi_path(
    f: impl FnMut(*mut u16, usize) -> TryFillBufResult,
) -> Result<PathBuf, io::Error> {
    get_win_ffi_string::<MAX_PATH, PathBuf>(f, |s| s.to_os_string().into())
}

pub fn get_win_ffi_string<const BUF_SIZE: usize, S>(
    mut try_fill: impl FnMut(*mut u16, usize) -> TryFillBufResult,
    copy: impl FnOnce(&mut U16Str) -> S,
) -> Result<S, io::Error> {
    let mut buf = ArrayBuf::<u16, BUF_SIZE>::new_uninit();
    match try_fill(buf.as_mut_ptr(), buf.capacity()) {
        TryFillBufResult::BufTooSmall { mut size_hint } => {
            let mut vec_buf = Vec::new();
            let mut buf_len = buf.capacity();
            loop {
                buf_len = cmp::max(buf_len.saturating_mul(2), size_hint.unwrap_or(0));
                vec_buf.resize(buf_len, MaybeUninit::uninit());
                match try_fill(vec_buf[0].as_mut_ptr(), vec_buf.len()) {
                    TryFillBufResult::Success { actual_len } => {
                        let slice = unsafe {
                            maybe_uninit_slice_assume_init_mut(&mut vec_buf[..actual_len])
                        };
                        let wide_str = widestring::U16Str::from_slice_mut(slice);
                        let copied = copy(wide_str);
                        return Ok(copied);
                    }
                    TryFillBufResult::Error(e) => return Err(e),
                    TryFillBufResult::BufTooSmall {
                        size_hint: new_size_hint,
                    } => size_hint = new_size_hint,
                }
            }
        }
        TryFillBufResult::Success { actual_len } => {
            unsafe { buf.set_len(actual_len) };
            let wide_str = widestring::U16Str::from_slice_mut(buf.as_mut_slice());
            let copied = copy(wide_str);
            Ok(copied)
        }
        TryFillBufResult::Error(e) => Err(e),
    }
}
