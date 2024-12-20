use axerrno::LinuxError;
use axhal::paging::MappingFlags;
use axtask::{current, TaskExtRef};
use memory_addr::{VirtAddr, VirtAddrRange};
use arceos_posix_api as api;
use alloc::vec;
use axhal::mem::MemoryAddr;
use api::imp::fs::File;
use axstd::io::SeekFrom;
use memory_addr::addr_range;

use crate::syscall_body;

bitflags::bitflags! {
    /// permissions for sys_mmap
    ///
    /// See <https://github.com/bminor/glibc/blob/master/bits/mman.h>
    #[derive(Debug)]
    struct MmapProt: i32 {
        /// Page can be read.
        const PROT_READ = 1 << 0;
        /// Page can be written.
        const PROT_WRITE = 1 << 1;
        /// Page can be executed.
        const PROT_EXEC = 1 << 2;
    }
}

impl From<MmapProt> for MappingFlags {
    fn from(value: MmapProt) -> Self {
        let mut flags = MappingFlags::USER;
        if value.contains(MmapProt::PROT_READ) {
            flags |= MappingFlags::READ;
        }
        if value.contains(MmapProt::PROT_WRITE) {
            flags |= MappingFlags::WRITE;
        }
        if value.contains(MmapProt::PROT_EXEC) {
            flags |= MappingFlags::EXECUTE;
        }
        flags
    }
}

bitflags::bitflags! {
    /// flags for sys_mmap
    ///
    /// See <https://github.com/bminor/glibc/blob/master/bits/mman.h>
    #[derive(Debug)]
    struct MmapFlags: i32 {
        /// Share changes
        const MAP_SHARED = 1 << 0;
        /// Changes private; copy pages on write.
        const MAP_PRIVATE = 1 << 1;
        /// Map address must be exactly as requested, no matter whether it is available.
        const MAP_FIXED = 1 << 4;
        /// Don't use a file.
        const MAP_ANONYMOUS = 1 << 5;
        /// Don't check for reservations.
        const MAP_NORESERVE = 1 << 14;
        /// Allocation is for a stack.
        const MAP_STACK = 0x20000;
    }
}

pub(crate) fn sys_brk(brk: usize) -> isize {
    syscall_body!(sys_brk, {
        Ok(brk as isize)
    })
}

pub(crate) fn sys_mmap(
    addr: *mut usize,
    length: usize,
    prot: i32,
    flags: i32,
    _fd: i32,
    _offset: isize,
) -> usize {
    syscall_body!(sys_mmap, {
        // let curr = current();
        // let curr_ext = curr.task_ext();
        // let mut aspace = curr_ext.aspace.lock();
        // let permission_flags = MmapProt::from_bits_truncate(prot);
        // // TODO: check illegal flags for mmap
        // // An example is the flags contained none of MAP_PRIVATE, MAP_SHARED, or MAP_SHARED_VALIDATE.
        // let map_flags = MmapFlags::from_bits_truncate(flags);

        // let start_addr = if map_flags.contains(MmapFlags::MAP_FIXED) {
        //     VirtAddr::from(addr as usize)
        // } else {
        //     aspace
        //         .find_free_area(
        //             VirtAddr::from(addr as usize),
        //             length,
        //             VirtAddrRange::new(aspace.base(), aspace.end()),
        //         )
        //         .or(aspace.find_free_area(
        //             aspace.base(),
        //             length,
        //             VirtAddrRange::new(aspace.base(), aspace.end()),
        //         ))
        //         .ok_or(LinuxError::ENOMEM)?
        // };

        // aspace.map_alloc(start_addr, length, permission_flags.into(), false)?;

        // Ok(start_addr.as_usize())
        let file = File::from_fd(_fd)?;
        let mut file = file.inner.lock();
        let addr_u = addr as usize;
        let mut vaddr = VirtAddr::from(addr as usize).align_down_4k();
        let mut vaddr_end = VirtAddr::from((addr as usize + length) as usize)
            .align_up_4k();

        let curr = axtask::current();
        let mut uspace = curr.task_ext().aspace.lock();

        let limit_range = addr_range!(uspace.base()..uspace.end());

        if addr_u == 0 {
            vaddr = uspace.find_free_area(VirtAddr::from(0x3000000 as usize), length, limit_range).unwrap();
            vaddr_end = (vaddr + length).align_up_4k();
        }

        let mut data = vec![0u8; length as usize];
        file.seek(SeekFrom::Start(_offset.try_into().unwrap()))?;

        let n = file.read(&mut data)?;

        uspace.map_alloc(vaddr, (vaddr_end - vaddr) as usize, MappingFlags::READ|MappingFlags::WRITE|MappingFlags::EXECUTE|MappingFlags::USER, true)?;
        uspace.write(vaddr, &data)?;

        Ok(vaddr.as_usize())
    })
}

pub(crate) fn sys_munmap(addr: usize, length: usize) -> isize {
    syscall_body!(sys_munmap, {
        let curr = current();
        let mut aspace = curr.task_ext().aspace.lock();
        let length_4k = VirtAddr::from(length as usize).align_up_4k();
        aspace.unmap(VirtAddr::from(addr), length_4k.into())?;
        Ok(0)
    })
}
