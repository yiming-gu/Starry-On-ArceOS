use core::ffi::{c_void, c_char, c_int};

use arceos_posix_api as api;
use axerrno::LinuxError;
use api::utils::char_ptr_to_str;
use api::imp::fs::flags_to_options;
use api::imp::fs::File;
use api::imp::dir::Dir;
use alloc::format;
use crate::syscall_body;

const AT_FDCWD: i32 = -100;

pub(crate) fn sys_read(fd: i32, buf: *mut c_void, count: usize) -> isize {
    api::sys_read(fd, buf, count)
}

pub(crate) fn sys_write(fd: i32, buf: *const c_void, count: usize) -> isize {
    api::sys_write(fd, buf, count)
}

pub(crate) fn sys_writev(fd: i32, iov: *const api::ctypes::iovec, iocnt: i32) -> isize {
    unsafe { api::sys_writev(fd, iov, iocnt) }
}

pub(crate) fn sys_close(fd: i32) -> isize {
    api::sys_close(fd) as isize
}

pub(crate) fn sys_openat(dfd: c_int, fname: *const c_char, flags: c_int, mode: api::ctypes::mode_t) -> isize {
    // assert_eq!(dfd, AT_FDCWD);
    // api::sys_open(fname, flags, mode) as isize
    let filename = char_ptr_to_str(fname);
    debug!("sys_open <= {:?} {:#o} {:#o}", filename, flags, mode);
    syscall_body!(sys_open, {
        let mut options = flags_to_options(flags, mode);
        if options.directory {
            options.read(true);
            let dir = axfs::fops::Directory::open_dir(filename?, &options)?;
            Dir::new(filename?).add_to_fd_table()
        }
        else {
            if dfd == AT_FDCWD {
                let file = axfs::fops::File::open(filename?, &options)?;
                File::new(filename?, file).add_to_fd_table()
            }
            else {
                let dir = api::imp::fd_ops::get_file_like(dfd)?;
                let dir_path = dir.path();
                let filepath = format!("{}/{}", dir_path, filename?);
                let file = axfs::fops::File::open(&filepath, &options)?;
                File::new(filename?, file).add_to_fd_table()
            }
        }
    })
}

pub(crate) fn sys_dup(fd: i32) -> isize {
    api::sys_dup(fd) as isize
}

pub(crate) fn sys_dup2(oldfd: i32, newfd: c_int) -> isize {
    api::sys_dup2(oldfd, newfd) as isize
}

pub(crate) fn sys_fstat(fd: i32, buf: *mut api::ctypes::stat) -> isize {
    unsafe { api::sys_fstat(fd, buf) as isize }
}

pub(crate) fn sys_getcwd(buf: *mut c_char, size: usize) -> isize {
    api::sys_getcwd(buf, size) as isize
}

pub(crate) fn sys_chdir(path: *const c_char) -> isize {
    syscall_body!(sys_chdir, {
        let path = api::utils::char_ptr_to_str(path)?;
        if let Err(e) = axfs::api::set_current_dir(path) {
            Err(LinuxError::from(e))
        } else {
            Ok(0)
        }
    })
}

pub (crate) fn sys_mkdirat(dfd: i32, path: *const c_char, mode: api::ctypes::mode_t) -> isize {
    assert_eq!(dfd, AT_FDCWD);
    syscall_body!(sys_mkdirat, {
        let path = api::utils::char_ptr_to_str(path)?;
        if let Err(e) = axfs::api::create_dir(path) {
            Err(LinuxError::from(e))
        } else {
            Ok(0)
        }
    })
}
