use std::{io, mem::MaybeUninit, os::windows::raw::HANDLE};

use ntapi::ntexapi::{
    NtQuerySystemInformation, SystemProcessInformation, SYSTEM_PROCESS_INFORMATION,
};
use winapi::{
    shared::ntstatus::STATUS_INFO_LENGTH_MISMATCH,
    um::{
        winnt::{
            IMAGE_FILE_MACHINE_ALPHA, IMAGE_FILE_MACHINE_ALPHA64, IMAGE_FILE_MACHINE_AM33,
            IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM, IMAGE_FILE_MACHINE_ARM64,
            IMAGE_FILE_MACHINE_ARMNT, IMAGE_FILE_MACHINE_CEE, IMAGE_FILE_MACHINE_CEF,
            IMAGE_FILE_MACHINE_EBC, IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_IA64,
            IMAGE_FILE_MACHINE_M32R, IMAGE_FILE_MACHINE_MIPS16, IMAGE_FILE_MACHINE_MIPSFPU,
            IMAGE_FILE_MACHINE_MIPSFPU16, IMAGE_FILE_MACHINE_POWERPC, IMAGE_FILE_MACHINE_POWERPCFP,
            IMAGE_FILE_MACHINE_R10000, IMAGE_FILE_MACHINE_R3000, IMAGE_FILE_MACHINE_R4000,
            IMAGE_FILE_MACHINE_SH3, IMAGE_FILE_MACHINE_SH3DSP, IMAGE_FILE_MACHINE_SH3E,
            IMAGE_FILE_MACHINE_SH4, IMAGE_FILE_MACHINE_SH5, IMAGE_FILE_MACHINE_THUMB,
            IMAGE_FILE_MACHINE_TRICORE, IMAGE_FILE_MACHINE_UNKNOWN, IMAGE_FILE_MACHINE_WCEMIPSV2,
        },
        wow64apiset::IsWow64Process2,
    },
};

use crate::error::ProcessError;

/// Returns a list of all currently running processes.
pub fn iter_process_ids() -> Result<impl Iterator<Item = u32>, ProcessError> {
    const IDLE_PROCESS_ID: u32 = 0;
    const SYSTEM_PROCESS_ID: u32 = 4;

    let iter = iter_process_info()?
        .map(|info| info.UniqueProcessId as u32)
        .filter(|pid| *pid != IDLE_PROCESS_ID && *pid != SYSTEM_PROCESS_ID);
    Ok(iter)
}

pub fn iter_process_info() -> Result<impl Iterator<Item = SYSTEM_PROCESS_INFORMATION>, ProcessError>
{
    struct SystemProcessInfoIterator {
        buf: Vec<u8>,
        next_offset: Option<usize>,
    }

    impl Iterator for SystemProcessInfoIterator {
        type Item = SYSTEM_PROCESS_INFORMATION;

        fn next(&mut self) -> Option<Self::Item> {
            let next_offset = self.next_offset?;
            let next_process_info = unsafe { self.buf.as_ptr().add(next_offset) };

            let process_info: &SYSTEM_PROCESS_INFORMATION = unsafe { &*next_process_info.cast() };
            let offset_to_next = process_info.NextEntryOffset as usize;
            if offset_to_next == 0 {
                self.next_offset = None;
                return None;
            }
            *self.next_offset.as_mut().unwrap() += offset_to_next;

            Some(*process_info)
        }
    }

    let mut buf_len = 512 * 1024;
    let mut buf: Vec<u8> = Vec::new();

    loop {
        buf.reserve(buf_len - buf.capacity());

        let mut buf_size_needed = MaybeUninit::uninit();
        let result = unsafe {
            NtQuerySystemInformation(
                SystemProcessInformation,
                buf.as_mut_ptr().cast(),
                buf.capacity() as _,
                buf_size_needed.as_mut_ptr(),
            )
        };

        let buf_size_needed = unsafe { buf_size_needed.assume_init() } as usize;
        if buf.capacity() < buf_size_needed || result == STATUS_INFO_LENGTH_MISMATCH {
            buf_len *= 2;
            continue;
        }
        unsafe { buf.set_len(buf_size_needed) };
        break;
    }

    Ok(SystemProcessInfoIterator {
        buf,
        next_offset: Some(0),
    })
}

pub struct ArchitectureInfo {
    pub process_bitness: usize,
    pub _machine_bitness: usize,
    pub is_wow64: bool,
}

pub fn process_architecture_info(handle: HANDLE) -> Result<ArchitectureInfo, ProcessError> {
    fn get_bitness(image_file_machine: u16) -> usize {
        // taken from https://github.com/fkie-cad/headerParser/blob/bc45fb361ed654e656dd2f66819f33e1c919a3dd/src/ArchitectureInfo.h

        const IMAGE_FILE_MACHINE_DEC_ALPHA_AXP: u16 = 0x183;
        const IMAGE_FILE_MACHINE_I860: u16 = 0x014d;
        const IMAGE_FILE_MACHINE_I80586: u16 = 0x014e;
        const IMAGE_FILE_MACHINE_R3000_BE: u16 = 0x0160;
        const IMAGE_FILE_MACHINE_RISCV32: u16 = 0x5032;
        const IMAGE_FILE_MACHINE_RISCV64: u16 = 0x5064;
        const IMAGE_FILE_MACHINE_RISCV128: u16 = 0x5128;

        match image_file_machine {
            IMAGE_FILE_MACHINE_ALPHA => 64,
            IMAGE_FILE_MACHINE_ALPHA64 => 64,
            IMAGE_FILE_MACHINE_AM33 => 32,
            IMAGE_FILE_MACHINE_AMD64 => 64,
            IMAGE_FILE_MACHINE_ARM => 32,
            IMAGE_FILE_MACHINE_ARM64 => 64,
            IMAGE_FILE_MACHINE_ARMNT => 32,
            // IMAGE_FILE_MACHINE_AXP64 => 64,
            IMAGE_FILE_MACHINE_CEE => 0,
            IMAGE_FILE_MACHINE_CEF => 0,
            IMAGE_FILE_MACHINE_DEC_ALPHA_AXP => 64,
            IMAGE_FILE_MACHINE_EBC => 32,
            IMAGE_FILE_MACHINE_I386 => 32,
            IMAGE_FILE_MACHINE_I860 => 32,
            IMAGE_FILE_MACHINE_I80586 => 32,
            IMAGE_FILE_MACHINE_IA64 => 64,
            IMAGE_FILE_MACHINE_M32R => 32,
            IMAGE_FILE_MACHINE_MIPS16 => 16,
            IMAGE_FILE_MACHINE_MIPSFPU => 32,
            IMAGE_FILE_MACHINE_MIPSFPU16 => 16,
            IMAGE_FILE_MACHINE_POWERPC => 32,
            IMAGE_FILE_MACHINE_POWERPCFP => 32,
            IMAGE_FILE_MACHINE_R3000 => 32,
            IMAGE_FILE_MACHINE_R3000_BE => 32,
            IMAGE_FILE_MACHINE_R4000 => 64,
            IMAGE_FILE_MACHINE_R10000 => 64,
            IMAGE_FILE_MACHINE_RISCV32 => 32,
            IMAGE_FILE_MACHINE_RISCV64 => 64,
            IMAGE_FILE_MACHINE_RISCV128 => 128,
            IMAGE_FILE_MACHINE_SH3 => 32,
            IMAGE_FILE_MACHINE_SH3DSP => 32,
            IMAGE_FILE_MACHINE_SH3E => 32,
            IMAGE_FILE_MACHINE_SH4 => 32,
            IMAGE_FILE_MACHINE_SH5 => 64,
            IMAGE_FILE_MACHINE_THUMB => 16,
            IMAGE_FILE_MACHINE_TRICORE => 32,
            IMAGE_FILE_MACHINE_WCEMIPSV2 => 32,
            _ => unimplemented!(
                "unknown machine architecture (IMAGE_FILE_MACHINE_*): {image_file_machine}"
            ),
        }
    }

    let mut process_machine_info = MaybeUninit::uninit();
    let mut native_machine_info = MaybeUninit::uninit();
    let result = unsafe {
        IsWow64Process2(
            handle,
            process_machine_info.as_mut_ptr(),
            native_machine_info.as_mut_ptr(),
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error().into());
    }

    let process_machine_info = unsafe { process_machine_info.assume_init() };
    let native_machine_info = unsafe { native_machine_info.assume_init() };

    let is_wow64 = process_machine_info != IMAGE_FILE_MACHINE_UNKNOWN;
    let native_bitness = get_bitness(native_machine_info);
    let (process_bitness, _machine_bitness) = if is_wow64 {
        let process_bitness = get_bitness(process_machine_info);
        (process_bitness, native_bitness)
    } else {
        (native_bitness, native_bitness)
    };

    Ok(ArchitectureInfo {
        process_bitness,
        _machine_bitness,
        is_wow64,
    })
}
