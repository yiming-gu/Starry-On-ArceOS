use core::ffi::{c_void, c_char, c_int};

use arceos_posix_api as api;
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
    api::sys_open(fname, flags, mode) as isize
}

pub(crate) fn sys_dup(fd: c_int) -> isize {
    api::sys_dup(fd) as isize
}

pub(crate) fn sys_dup2(oldfd: c_int, newfd: c_int) -> isize {
    api::sys_dup2(oldfd, newfd) as isize
}

pub(crate) fn sys_fstat(fd: c_int, buf: *mut api::ctypes::stat) -> isize {
    unsafe { api::sys_fstat(fd, buf) as isize }
}

pub(crate) fn sys_getcwd(buf: *mut c_char, size: usize) -> isize {
    api::sys_getcwd(buf, size) as isize
}

pub(crate) fn sys_chdir(path: *const c_char) -> isize {
    let path = api::utils::char_ptr_to_str(path);
    syscall_body!(sys_chdir, {
        axfs::api::set_current_dir(path?);
        Ok(0)
    })
}

pub (crate) fn sys_mkdirat(dfd: c_int, path: *const c_char, mode: api::ctypes::mode_t) -> isize {
    assert_eq!(dfd, AT_FDCWD);
    let path = api::utils::char_ptr_to_str(path);
    syscall_body!(sys_mkdirat, {
        axfs::api::create_dir(path?);
        Ok(0)
    })
}
