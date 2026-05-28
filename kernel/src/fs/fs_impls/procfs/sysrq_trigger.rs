// SPDX-License-Identifier: MPL-2.0

//! This module offers `/proc/sysrq-trigger` file support, which allows
//! privileged users to trigger SysRq operations by writing to this file.
//!
//! Reference: <https://docs.kernel.org/admin-guide/sysrq.html>

use aster_util::printer::VmPrinter;
use ostd::{
    log::{LevelFilter, set_max_level},
    power::{ExitCode, poweroff, restart},
};

use crate::{
    fs::{
        file::mkmod,
        procfs::template::{ProcFile, ProcFileOps},
        vfs::{inode::Inode, path::MountNamespace},
    },
    prelude::*,
    process::{
        pid_table,
        posix_thread::AsPosixThread,
        signal::{
            constants::{SIGKILL, SIGTERM},
            sig_num::SigNum,
            signals::kernel::KernelSignal,
        },
    },
    vm,
};

/// Represents the inode at `/proc/sysrq-trigger`.
pub struct SysrqTriggerFileOps;

impl SysrqTriggerFileOps {
    pub fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        // Reference:
        // <https://elixir.bootlin.com/linux/v6.16.5/source/drivers/tty/sysrq.c#L1135>
        // <https://elixir.bootlin.com/linux/v6.16.5/source/fs/proc/generic.c#L549-L550>
        ProcFile::new(Self, parent, mkmod!(u+rw))
    }

    fn print_help(printer: &mut VmPrinter) -> Result<()> {
        writeln!(printer, "SysRq : HELP : sysrq-trigger")?;
        writeln!(printer, "  b       Reboot")?;
        writeln!(printer, "  c       Crash (trigger a kernel panic)")?;
        writeln!(
            printer,
            "  e       Send SIGTERM to all processes except init"
        )?;
        writeln!(printer, "  h       Display this help message")?;
        writeln!(
            printer,
            "  i       Send SIGKILL to all processes except init"
        )?;
        writeln!(printer, "  m       Show memory info")?;
        writeln!(printer, "  o       Poweroff")?;
        writeln!(printer, "  p       Show registers")?;
        writeln!(
            printer,
            "  r       Unraw (turn off keyboard raw mode, no-op)"
        )?;
        writeln!(printer, "  s       Sync all mounted filesystems")?;
        writeln!(printer, "  t       Show task states")?;
        writeln!(printer, "  u       Remount all filesystems read-only")?;
        writeln!(
            printer,
            "  0-9     Set console log level (0=emerg, 7=debug)"
        )?;
        Ok(())
    }
}

impl ProcFileOps for SysrqTriggerFileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let mut printer = VmPrinter::new_skip(writer, offset);

        Self::print_help(&mut printer)?;

        Ok(printer.bytes_written())
    }

    fn write_at(&self, _offset: usize, reader: &mut VmReader) -> Result<usize> {
        let total_bytes = reader.remain();
        if total_bytes == 0 {
            return Ok(0);
        }

        let key = reader.read_val::<u8>()? as char;

        match key {
            'b' => {
                info!("SysRq : Reboot");
                restart(ExitCode::Success);
            }
            'c' => {
                info!("SysRq : Crash");
                panic!("SysRq : Crash triggered by sysrq-trigger");
            }
            'e' => {
                info!("SysRq : Terminate All Processes");
                send_signal_to_all_except_init(SIGTERM);
            }
            'h' | '?' => {
                info!("SysRq : HELP : sysrq-trigger");
            }
            'i' => {
                info!("SysRq : Kill All Processes");
                send_signal_to_all_except_init(SIGKILL);
            }
            'm' => {
                info!("SysRq : Show Memory");
                show_memory_info();
            }
            'o' => {
                info!("SysRq : Power Off");
                poweroff(ExitCode::Success);
            }
            'p' => {
                info!("SysRq : Show Registers");
                show_registers();
            }
            'r' => {
                info!("SysRq : Unraw");
            }
            's' => {
                info!("SysRq : Sync Filesystems");
                sync_filesystems();
            }
            't' => {
                info!("SysRq : Show Task States");
                show_task_states();
            }
            'u' => {
                warn!("SysRq : Remount Filesystems Read-Only is not implemented yet");
            }
            '0'..='9' => {
                let level = key as u8 - b'0';
                set_console_loglevel(level);
            }
            _ => {
                warn!("SysRq : Unknown command '{}'", key);
            }
        }

        Ok(total_bytes)
    }
}

fn send_signal_to_all_except_init(signum: SigNum) {
    let pid_table = pid_table::pid_table_mut();
    for process in pid_table.iter_processes() {
        if !process.is_init_process() {
            process.enqueue_signal(Box::new(KernelSignal::new(signum)));
        }
    }
}

fn show_memory_info() {
    let total_kb = vm::mem_total() / 1024;
    let free_kb = osdk_frame_allocator::load_total_free_size() / 1024;
    info!(
        "SysRq : MemTotal: {} kB, MemFree: {} kB, MemAvailable: {} kB",
        total_kb, free_kb, free_kb,
    );
}

fn show_registers() {
    if let Some(thread) = crate::thread::Thread::current()
        && let Some(posix_thread) = thread.as_posix_thread()
    {
        let tid = posix_thread.tid();
        let pid = posix_thread.process().pid();
        info!("SysRq : Thread {} (PID {})", tid, pid);
    }
}

fn sync_filesystems() {
    let init_mnt_ns = MountNamespace::get_init_singleton();
    if let Err(e) = init_mnt_ns.sync() {
        warn!("SysRq : Sync failed: {:?}", e);
    }
}

fn show_task_states() {
    let pid_table = pid_table::pid_table_mut();
    let count = pid_table.process_count();
    info!("SysRq : {} process(es):", count);
    for process in pid_table.iter_processes() {
        let pid = process.pid();
        let zombie = process.status().is_zombie();
        let stopped = process.is_stopped();
        info!(
            "SysRq :   PID {}: zombie={}, stopped={}",
            pid, zombie, stopped
        );
    }
}

fn set_console_loglevel(level: u8) {
    let filter = match level {
        0 => LevelFilter::Emerg,
        1 => LevelFilter::Alert,
        2 => LevelFilter::Crit,
        3 => LevelFilter::Error,
        4 => LevelFilter::Warning,
        5 => LevelFilter::Notice,
        6 => LevelFilter::Info,
        7 => LevelFilter::Debug,
        _ => return,
    };
    set_max_level(filter);
    info!("SysRq : Setting console log level to {}", level);
}
