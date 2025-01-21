use arceos_posix_api as api;
use crate::syscall_body;
use axerrno::LinuxError;

pub(crate) fn sys_sched_yield() -> i32 {
    api::sys_sched_yield()
}

pub(crate) fn sys_nanosleep(
    req: *const api::ctypes::timespec,
    rem: *mut api::ctypes::timespec,
) -> i32 {
    unsafe { api::sys_nanosleep(req, rem) }
}

/// Get clock time since epoch
pub unsafe fn sys_gettimeofday(tv: *mut api::ctypes::timeval, _tz: u32) -> isize {
    syscall_body!(sys_gettimeofday, {
        if tv.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let now: api::ctypes::timeval = axhal::time::wall_time().into();
        unsafe { *tv = now };
        debug!("sys_gettimeofday: {}.{:09}s", now.tv_sec, now.tv_usec);
        Ok(0)
    })
}
