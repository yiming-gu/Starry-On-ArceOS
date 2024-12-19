//! Loader for loading apps.
//!
//! It will read and parse ELF files.
//!
//! Now these apps are loaded into memory as a part of the kernel image.
use alloc::{collections::btree_map::BTreeMap, vec::Vec};
use core::arch::global_asm;

use axhal::paging::MappingFlags;
use memory_addr::{MemoryAddr, VirtAddr};
use alloc::boxed::Box;

global_asm!(include_str!(concat!(env!("OUT_DIR"), "/link_app.S")));

// extern "C" {
//     fn _app_count();
// }

// /// Get the number of apps.
// pub(crate) fn get_app_count() -> usize {
//     unsafe { (_app_count as *const u64).read() as usize }
// }

// /// Get the name of an app by a given app ID.
// pub(crate) fn get_app_name(app_id: usize) -> &'static str {
//     unsafe {
//         let app_0_start_ptr = (_app_count as *const u64).add(1);
//         assert!(app_id < get_app_count());
//         let app_name = app_0_start_ptr.add(app_id * 2).read() as *const u8;
//         let mut len = 0;
//         while app_name.add(len).read() != b'\0' {
//             len += 1;
//         }
//         let slice = core::slice::from_raw_parts(app_name, len);
//         core::str::from_utf8(slice).unwrap()
//     }
// }

// /// Get the data of an app by a given app ID.
// pub(crate) fn get_app_data(app_id: usize) -> &'static [u8] {
//     unsafe {
//         let app_0_start_ptr = (_app_count as *const u64).add(1);
//         assert!(app_id < get_app_count());
//         let app_start = app_0_start_ptr.add(app_id * 2 + 1).read() as usize;
//         let app_end = app_0_start_ptr.add(app_id * 2 + 2).read() as usize;
//         let app_size = app_end - app_start;
//         core::slice::from_raw_parts(app_start as *const u8, app_size)
//     }
// }

// /// Get the data of an app by the given app name.
// pub(crate) fn get_app_data_by_name(name: &str) -> Option<&'static [u8]> {
//     let app_count = get_app_count();
//     (0..app_count)
//         .find(|&i| get_app_name(i) == name)
//         .map(get_app_data)
// }

// /// List all apps.
// pub(crate) fn list_apps() {
//     info!("/**** APPS ****");
//     let app_count = get_app_count();
//     for i in 0..app_count {
//         info!("{}", get_app_name(i));
//     }
//     info!("**************/");
// }

/// The segment of the elf file, which is used to map the elf file to the memory space
pub struct ELFSegment {
    /// The start virtual address of the segment
    pub start_vaddr: VirtAddr,
    /// The size of the segment
    pub size: usize,
    /// The flags of the segment which is used to set the page table entry
    pub flags: MappingFlags,
    /// The data of the segment
    pub data: &'static [u8],
    /// The offset of the segment relative to the start of the page
    pub offset: usize,
}

/// The information of a given ELF file
pub struct ELFInfo {
    /// The entry point of the ELF file
    pub entry: VirtAddr,
    /// The segments of the ELF file
    pub segments: Vec<ELFSegment>,
    /// The auxiliary vectors of the ELF file
    pub auxv: BTreeMap<u8, usize>,
}

/// Load the ELF files by the given app name and return
/// the segments of the ELF file
///
/// # Arguments
/// * `name` - The name of the app
/// * `base_addr` - The minimal address of user space
///
/// # Returns
/// Entry and information about segments of the given ELF file
pub(crate) fn load_elf(name: &str, base_addr: VirtAddr) -> ELFInfo {
    use xmas_elf::program::{Flags, SegmentData};
    use xmas_elf::{header, ElfFile};

    // let elf = ElfFile::new(
    //     get_app_data_by_name(name).unwrap_or_else(|| panic!("failed to get app: {}", name)),
    // )
    // .expect("invalid ELF file");
    let elf_data: &'static [u8] = Box::leak(axfs::api::read(name).expect("failed to read").into_boxed_slice());
    let elf = ElfFile::new(&elf_data).expect("Error parsing app ELF file.");
    let elf_header = elf.header;

    assert_eq!(elf_header.pt1.magic, *b"\x7fELF", "invalid elf!");

    let expect_arch = if cfg!(target_arch = "x86_64") {
        header::Machine::X86_64
    } else if cfg!(target_arch = "aarch64") {
        header::Machine::AArch64
    } else if cfg!(target_arch = "riscv64") {
        header::Machine::RISC_V
    } else {
        panic!("Unsupported architecture!");
    };
    assert_eq!(
        elf.header.pt2.machine().as_machine(),
        expect_arch,
        "invalid ELF arch"
    );

    fn into_mapflag(f: Flags) -> MappingFlags {
        let mut ret = MappingFlags::USER;
        if f.is_read() {
            ret |= MappingFlags::READ;
        }
        if f.is_write() {
            ret |= MappingFlags::WRITE;
        }
        if f.is_execute() {
            ret |= MappingFlags::EXECUTE;
        }
        ret
    }

    let mut segments = Vec::new();

    let elf_offset = kernel_elf_parser::get_elf_base_addr(&elf, base_addr.as_usize()).unwrap();
    assert!(
        memory_addr::is_aligned_4k(elf_offset),
        "ELF base address must be aligned to 4k"
    );

    elf.program_iter()
        .filter(|ph| ph.get_type() == Ok(xmas_elf::program::Type::Load))
        .for_each(|ph| {
            // align the segment to 4k
            let st_vaddr = VirtAddr::from(ph.virtual_addr() as usize) + elf_offset;
            let st_vaddr_align: VirtAddr = st_vaddr.align_down_4k();
            let ed_vaddr_align = VirtAddr::from((ph.virtual_addr() + ph.mem_size()) as usize)
                .align_up_4k()
                + elf_offset;
            let data = match ph.get_data(&elf).unwrap() {
                SegmentData::Undefined(data) => data,
                _ => panic!("failed to get ELF segment data"),
            };
            segments.push(ELFSegment {
                start_vaddr: st_vaddr_align,
                size: ed_vaddr_align.as_usize() - st_vaddr_align.as_usize(),
                flags: into_mapflag(ph.flags()),
                data,
                offset: st_vaddr.align_offset_4k(),
            });
        });
    ELFInfo {
        entry: VirtAddr::from(elf.header.pt2.entry_point() as usize + elf_offset),
        segments,
        auxv: kernel_elf_parser::get_auxv_vector(&elf, elf_offset),
    }
}

// pub(crate) fn load_user_app(fname: &str, uspace: &mut AddrSpace) -> io::Result<usize> {
//     let mut file = File::open(fname)?;
//     let (phdrs, entry, _, _) = load_elf_phdrs(&mut file)?;

//     for phdr in &phdrs {
//         info!(
//             "phdr: offset: {:#X}=>{:#X} size: {:#X}=>{:#X}",
//             phdr.p_offset, phdr.p_vaddr, phdr.p_filesz, phdr.p_memsz
//         );

//         let vaddr = VirtAddr::from(phdr.p_vaddr as usize).align_down_4k();
//         let vaddr_end = VirtAddr::from((phdr.p_vaddr+phdr.p_memsz) as usize)
//             .align_up_4k();

//         info!("{:#x} - {:#x}", vaddr, vaddr_end);
//         uspace.map_alloc(vaddr, vaddr_end-vaddr, MappingFlags::READ|MappingFlags::WRITE|MappingFlags::EXECUTE|MappingFlags::USER, true)?;

//         let mut data = vec![0u8; phdr.p_memsz as usize];
//         file.seek(SeekFrom::Start(phdr.p_offset))?;

//         let filesz = phdr.p_filesz as usize;
//         let mut index = 0;
//         while index < filesz {
//             let n = file.read(&mut data[index..filesz])?;
//             index += n;
//         }
//         assert_eq!(index, filesz);
//         uspace.write(VirtAddr::from(phdr.p_vaddr as usize), &data)?;
//     }

//     Ok(entry)
// }

// fn load_elf_phdrs(file: &mut File) -> io::Result<(Vec<ProgramHeader>, usize, usize, usize)> {
//     let mut buf: [u8; ELF_HEAD_BUF_SIZE] = [0; ELF_HEAD_BUF_SIZE];
//     file.read(&mut buf)?;

//     let ehdr = ElfBytes::<AnyEndian>::parse_elf_header(&buf[..]).unwrap();
//     info!("e_entry: {:#X}", ehdr.e_entry);

//     let phnum = ehdr.e_phnum as usize;
//     // Validate phentsize before trying to read the table so that we can error early for corrupted files
//     let entsize = ProgramHeader::validate_entsize(ehdr.class, ehdr.e_phentsize as usize).unwrap();
//     let size = entsize.checked_mul(phnum).unwrap();
//     assert!(size > 0 && size <= PAGE_SIZE_4K);
//     let phoff = ehdr.e_phoff;
//     let mut buf = alloc::vec![0u8; size];
//     let _ = file.seek(SeekFrom::Start(phoff));
//     file.read(&mut buf)?;
//     let phdrs = SegmentTable::new(ehdr.endianness, ehdr.class, &buf[..]);

//     let phdrs: Vec<ProgramHeader> = phdrs
//         .iter()
//         .filter(|phdr| phdr.p_type == PT_LOAD || phdr.p_type == PT_INTERP)
//         .collect();
//     Ok((phdrs, ehdr.e_entry as usize, ehdr.e_phoff as usize, ehdr.e_phnum as usize))
// }
