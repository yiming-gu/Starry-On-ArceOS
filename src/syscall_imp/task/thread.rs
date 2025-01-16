use arceos_posix_api::{self as api};
use axerrno::LinuxError;
use axtask::{current, TaskExtRef};
use num_enum::TryFromPrimitive;
use axmm::AddrSpace;
use alloc::sync::Arc;
use axsync::Mutex;
use crate::task;
use axhal::arch::UspaceContext;
use axhal::arch::TrapFrame;
use core::sync::atomic::Ordering;

use crate::syscall_body;
use bitflags::*;

/// ARCH_PRCTL codes
///
/// It is only avaliable on x86_64, and is not convenient
/// to generate automatically via c_to_rust binding.
#[derive(Debug, Eq, PartialEq, TryFromPrimitive)]
#[repr(i32)]
enum ArchPrctlCode {
    /// Set the GS segment base
    SetGs = 0x1001,
    /// Set the FS segment base
    SetFs = 0x1002,
    /// Get the FS segment base
    GetFs = 0x1003,
    /// Get the GS segment base
    GetGs = 0x1004,
    /// The setting of the flag manipulated by ARCH_SET_CPUID
    GetCpuid = 0x1011,
    /// Enable (addr != 0) or disable (addr == 0) the cpuid instruction for the calling thread.
    SetCpuid = 0x1012,
}

bitflags! {
    /// 用于 sys_clone 的选项
    #[derive(Debug, Clone, Copy)]
    pub struct CloneFlags: u32 {
        /// .
        const CLONE_NEWTIME = 1 << 7;
        /// 共享地址空间
        const CLONE_VM = 1 << 8;
        /// 共享文件系统新信息
        const CLONE_FS = 1 << 9;
        /// 共享文件描述符(fd)表
        const CLONE_FILES = 1 << 10;
        /// 共享信号处理函数
        const CLONE_SIGHAND = 1 << 11;
        /// 创建指向子任务的fd，用于 sys_pidfd_open
        const CLONE_PIDFD = 1 << 12;
        /// 用于 sys_ptrace
        const CLONE_PTRACE = 1 << 13;
        /// 指定父任务创建后立即阻塞，直到子任务退出才继续
        const CLONE_VFORK = 1 << 14;
        /// 指定子任务的 ppid 为当前任务的 ppid，相当于创建“兄弟”而不是“子女”
        const CLONE_PARENT = 1 << 15;
        /// 作为一个“线程”被创建。具体来说，它同 CLONE_PARENT 一样设置 ppid，且不可被 wait
        const CLONE_THREAD = 1 << 16;
        /// 子任务使用新的命名空间。目前还未用到
        const CLONE_NEWNS = 1 << 17;
        /// 子任务共享同一组信号量。用于 sys_semop
        const CLONE_SYSVSEM = 1 << 18;
        /// 要求设置 tls
        const CLONE_SETTLS = 1 << 19;
        /// 要求在父任务的一个地址写入子任务的 tid
        const CLONE_PARENT_SETTID = 1 << 20;
        /// 要求将子任务的一个地址清零。这个地址会被记录下来，当子任务退出时会触发此处的 futex
        const CLONE_CHILD_CLEARTID = 1 << 21;
        /// 历史遗留的 flag，现在按 linux 要求应忽略
        const CLONE_DETACHED = 1 << 22;
        /// 与 sys_ptrace 相关，目前未用到
        const CLONE_UNTRACED = 1 << 23;
        /// 要求在子任务的一个地址写入子任务的 tid
        const CLONE_CHILD_SETTID = 1 << 24;
        /// New pid namespace.
        const CLONE_NEWPID = 1 << 29;
    }
}

// pub const MAX_SIG_NUM: usize = 64;
// numeric_enum_macro::numeric_enum! {
// #[repr(u8)]
// #[allow(missing_docs)]
// #[derive(Eq, PartialEq, Debug, Copy, Clone)]
// /// 信号编号。
// ///
// /// 从 32 开始的部分为 SIGRT，其中 RT 表示 real time。
// /// 但目前实现时没有通过 ipi 等手段即时处理，而是像其他信号一样等到 trap 再处理
// pub enum SignalNo {
//     ERR = 0,
//     SIGHUP = 1,
//     SIGINT = 2,
//     SIGQUIT = 3,
//     SIGILL = 4,
//     SIGTRAP = 5,
//     SIGABRT = 6,
//     SIGBUS = 7,
//     SIGFPE = 8,
//     SIGKILL = 9,
//     SIGUSR1 = 10,
//     SIGSEGV = 11,
//     SIGUSR2 = 12,
//     SIGPIPE = 13,
//     SIGALRM = 14,
//     SIGTERM = 15,
//     SIGSTKFLT = 16,
//     SIGCHLD = 17,
//     SIGCONT = 18,
//     SIGSTOP = 19,
//     SIGTSTP = 20,
//     SIGTTIN = 21,
//     SIGTTOU = 22,
//     SIGURG = 23,
//     SIGXCPU = 24,
//     SIGXFSZ = 25,
//     SIGVTALRM = 26,
//     SIGPROF = 27,
//     SIGWINCH = 28,
//     SIGIO = 29,
//     SIGPWR = 30,
//     SIGSYS = 31,
//     SIGRTMIN = 32,
//     SIGRT1 = 33,
//     SIGRT2 = 34,
//     SIGRT3 = 35,
//     SIGRT4 = 36,
//     SIGRT5 = 37,
//     SIGRT6 = 38,
//     SIGRT7 = 39,
//     SIGRT8 = 40,
//     SIGRT9 = 41,
//     SIGRT10 = 42,
//     SIGRT11 = 43,
//     SIGRT12 = 44,
//     SIGRT13 = 45,
//     SIGRT14 = 46,
//     SIGRT15 = 47,
//     SIGRT16 = 48,
//     SIGRT17 = 49,
//     SIGRT18 = 50,
//     SIGRT19 = 51,
//     SIGRT20 = 52,
//     SIGRT21 = 53,
//     SIGRT22 = 54,
//     SIGRT23 = 55,
//     SIGRT24 = 56,
//     SIGRT25 = 57,
//     SIGRT26 = 58,
//     SIGRT27 = 59,
//     SIGRT28 = 60,
//     SIGRT29 = 61,
//     SIGRT30 = 62,
//     SIGRT31 = 63,
// }}

// impl From<usize> for SignalNo {
//     fn from(num: usize) -> Self {
//         Self::try_from(num as u8).unwrap_or(Self::ERR)
//     }
// }

pub(crate) fn sys_getpid() -> i32 {
    api::sys_getpid()
}

pub(crate) fn sys_getppid() -> isize {
    syscall_body!(sys_getppid, {
        let curr = current();
        if let Some(parent) = &curr.task_ext().parent {
            Ok(parent.load(Ordering::Acquire) as isize)
        } else {
            Ok(2)
        }
    })
}

pub(crate) fn sys_exit(status: i32) -> ! {
    let curr = current();
    let clear_child_tid = curr.task_ext().clear_child_tid() as *mut i32;
    if !clear_child_tid.is_null() {
        // TODO: check whether the address is valid
        unsafe {
            // TODO: Encapsulate all operations that access user-mode memory into a unified function
            *(clear_child_tid) = 0;
        }
        // TODO: wake up threads, which are blocked by futex, and waiting for the address pointed by clear_child_tid
    }
    axtask::exit(status);
}

pub(crate) fn sys_exit_group(status: i32) -> ! {
    warn!("Temporarily replace sys_exit_group with sys_exit");
    axtask::exit(status);
}

/// To set the clear_child_tid field in the task extended data.
///
/// The set_tid_address() always succeeds
pub(crate) fn sys_set_tid_address(tid_ptd: *const i32) -> isize {
    syscall_body!(sys_set_tid_address, {
        let curr = current();
        curr.task_ext().set_clear_child_tid(tid_ptd as _);
        Ok(curr.id().as_u64() as isize)
    })
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn sys_arch_prctl(code: i32, addr: u64) -> isize {
    use axerrno::LinuxError;
    syscall_body!(sys_arch_prctl, {
        match ArchPrctlCode::try_from(code) {
            // TODO: check the legality of the address
            Ok(ArchPrctlCode::SetFs) => {
                unsafe {
                    axhal::arch::write_thread_pointer(addr as usize);
                }
                Ok(0)
            }
            Ok(ArchPrctlCode::GetFs) => {
                unsafe {
                    *(addr as *mut u64) = axhal::arch::read_thread_pointer() as u64;
                }
                Ok(0)
            }
            Ok(ArchPrctlCode::SetGs) => {
                unsafe {
                    x86::msr::wrmsr(x86::msr::IA32_KERNEL_GSBASE, addr);
                }
                Ok(0)
            }
            Ok(ArchPrctlCode::GetGs) => {
                unsafe {
                    *(addr as *mut u64) = x86::msr::rdmsr(x86::msr::IA32_KERNEL_GSBASE);
                }
                Ok(0)
            }
            _ => Err(LinuxError::ENOSYS),
        }
    })
}

pub(crate) fn sys_clone(
    flags: usize,
    user_stack: usize,
    ptid: usize,
    tls: usize,
    ctid: usize,
) -> isize {
    syscall_body!(sys_clone, {
        let stack = if user_stack == 0 {
            None
        } else {
            Some(user_stack)
        };
        let curr_task = current();

        let clone_flags = CloneFlags::from_bits((flags & !0x3f) as u32).unwrap();

        if clone_flags.contains(CloneFlags::CLONE_SIGHAND)
            && !clone_flags.contains(CloneFlags::CLONE_VM) {
            // Error when CLONE_SIGHAND was specified in the flags mask, but CLONE_VM was not.
            return Err(LinuxError::EINVAL);
        }

        let uspace = AddrSpace::from_existed_user(&curr_task.task_ext().aspace.lock())?;

        let kstack_top: usize = curr_task.kernel_stack_top().unwrap().into();
        let trap_frame_size = core::mem::size_of::<TrapFrame>();
        let trap_frame_ptr = (kstack_top - trap_frame_size) as *mut TrapFrame;
        let tf = &mut unsafe { *trap_frame_ptr };
        if let Some(stack) = stack {
            tf.regs.sp = stack;
            tf.sepc = unsafe {*(user_stack as *mut usize)};
        }

        let mut uctx = UspaceContext::from(tf);
        uctx.set_retval(0);

        let child_task = task::spawn_user_task(
            Arc::new(Mutex::new(uspace)),
            uctx,
            Some(curr_task.id().as_u64()),
        );

        curr_task.task_ext().children.lock().push(child_task.clone());

        Ok(child_task.id().as_u64() as isize)
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitStatus {
    /// 子任务正常退出
    Exited,
    /// 子任务正在运行
    Running,
    /// 找不到对应的子任务
    NotExist,
}

pub unsafe fn wait_pid(pid: i32, exit_code_ptr: *mut i32) -> Result<u64, WaitStatus> {
    let curr_process = current();
    let mut exit_task_id: usize = 0;
    let mut answer_id: u64 = 0;
    let mut answer_status = WaitStatus::NotExist;
    for (index, child) in curr_process.task_ext().children.lock().iter().enumerate() {
        if pid <= 0 {
            if pid == 0 {
                warn!("Don't support for process group.");
            }
            answer_status = WaitStatus::Running;
            if let Some(exit_code) = child.get_code_if_exit() {
                answer_status = WaitStatus::Exited;
                info!("wait pid _{}_ with code _{}_", child.id().as_u64(), exit_code);
                exit_task_id = index;
                if !exit_code_ptr.is_null() {
                    unsafe {
                        *exit_code_ptr = exit_code << 8;
                    }
                }
                answer_id = child.id().as_u64();
                break;
            }
        } else if child.id().as_u64() == pid as u64 {
            if let Some(exit_code) = child.get_code_if_exit() {
                answer_status = WaitStatus::Exited;
                info!("wait pid _{}_ with code _{:?}_", child.id().as_u64(), exit_code);
                exit_task_id = index;
                if !exit_code_ptr.is_null() {
                    unsafe {
                        *exit_code_ptr = exit_code << 8;
                    }
                }
                answer_id = child.id().as_u64();
            } else {
                answer_status = WaitStatus::Running;
            }
            break;
        }
    }
    // 若进程成功结束，需要将其从父进程的children中删除
    if answer_status == WaitStatus::Exited {
        curr_process.task_ext().children.lock().remove(exit_task_id);
        return Ok(answer_id);
    }
    Err(answer_status)
}

pub(crate) fn sys_wait4(pid: i32, exit_code_ptr: *mut i32, option: u32) -> isize {
    syscall_body!(sys_wait4, {
        loop {
            let answer = unsafe { wait_pid(pid, exit_code_ptr) };
            match answer {
                Ok(pid) => {
                    return Ok(pid as isize);
                }
                Err(status) => {
                    match status {
                        WaitStatus::NotExist => {
                            return Err(LinuxError::ECHILD);
                        }
                        WaitStatus::Running => {
                            axtask::yield_now();
                        }
                        _ => {
                            panic!("Shouldn't reach here!");
                        }
                    }
                }
            };
        }
        // for (index, child) in children.iter().enumerate() {
        //     if pid <= 0 {
        //         info!("Don't support for process group.");
        //         if pid == 0 {
        //             warn!("Don't support for process group.");
        //         }
        //         if let Some(ret) = child.join() {
        //             if !exit_code_ptr.is_null() {
        //                 unsafe { *exit_code_ptr = ret << 8; }
        //             }
        //             child_id = child.id().as_u64();
        //             children.remove(index);
        //             break;
        //         }
        //     } else if child.id().as_u64() == pid as u64 {
        //         if let Some(ret) = child.join() {
        //             if !exit_code_ptr.is_null() {
        //                 unsafe { *exit_code_ptr = ret << 8; }
        //             }
        //             child_id = child.id().as_u64();
        //             children.remove(index);
        //             break;
        //         }
        //     }
        // }
        // Ok(child_id)
    })
}

// pub(crate) fn sys_execve(
//     path: *const u8,
//     argv: *const usize,
//     envp: *const usize,
// ) -> isize {
//     syscall_body!(sys_execve, {
//         let filename = api::utils::char_ptr_to_str(filename);
//         let argv = api::utils::char_ptr_to_str_array(argv);
//         let envp = api::utils::char_ptr_to_str_array(envp);
//         let curr_task = current();
//     })
// }
