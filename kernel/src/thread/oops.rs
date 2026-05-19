// SPDX-License-Identifier: MPL-2.0

//! Kernel "oops" handling.
//!
//! In Asterinas, a Rust panic leads to a kernel "oops". A kernel oops behaves
//! as an exceptional control flow event. If kernel oopses happened too many
//! times, the kernel panics and the system gets halted. Kernel oops are per-
//! thread, so one thread's oops does not affect other threads.
//!
//! Though we can recover from the Rust panics. It is generally not recommended
//! to make Rust panics as a general exception handling mechanism. Handling
//! exceptions with [`Result`] is more idiomatic.

use alloc::format;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};

use ostd::{cpu::PinCurrentCpu, panic, task::disable_preempt, util::id_set::Id};

use super::Thread;
use crate::prelude::*;

// In Linux, `panic_timeout` controls reboot-on-panic behavior:
//   0 = power off (default), negative = immediate reboot, positive = reboot after N seconds.
static PANIC_TIMEOUT: AtomicI32 = AtomicI32::new(0);
aster_cmdline::define_kv_param!("panic", PANIC_TIMEOUT);

// TODO: Control the kernel commandline parsing from the kernel crate.
// In Linux it can be dynamically changed by writing to
// `/proc/sys/kernel/panic`.
static PANIC_ON_OOPS: AtomicBool = AtomicBool::new(true);

/// The kernel "oops" information.
pub struct OopsInfo {
    /// The "oops" message.
    pub message: String,
    /// The thread where the "oops" happened.
    #[expect(unused)]
    pub thread: Arc<Thread>,
}

/// Executes the given function and catches any panics that occur.
///
/// All the panics in the given function will be regarded as oops. If a oops
/// happens, this function returns `None`. Otherwise, it returns the return
/// value of the given function.
///
/// If the kernel is configured to panic on oops, this function will not return
/// when a oops happens.
pub fn catch_panics_as_oops<F, R>(f: F) -> Result<R, OopsInfo>
where
    F: FnOnce() -> R,
{
    let result = panic::catch_unwind(f);

    match result {
        Ok(result) => Ok(result),
        Err(err) => {
            let info = err.downcast::<OopsInfo>().unwrap();

            ostd::error!("Oops! {}", info.message);

            let count = OOPS_COUNT.fetch_add(1, Ordering::Relaxed);
            if count >= MAX_OOPS_COUNT {
                // Too many oops. The kernel panics.
                ostd::error!("Too many oops. The kernel panics.");
                panic!("Too many oops");
            }

            Err(*info)
        }
    }
}

/// The maximum number of oops allowed before the kernel panics.
///
/// It is the same as Linux's default value.
const MAX_OOPS_COUNT: usize = 10_000;

static OOPS_COUNT: AtomicUsize = AtomicUsize::new(0);

#[ostd::panic_handler]
fn panic_handler(info: &core::panic::PanicInfo) -> ! {
    let message = info.message();

    if let Some(thread) = Thread::current() {
        let panic_on_oops = PANIC_ON_OOPS.load(Ordering::Relaxed);
        if !panic_on_oops && info.can_unwind() {
            // TODO: eliminate the need for heap allocation.
            let message = if let Some(location) = info.location() {
                format!("{} at {}:{}", message, location.file(), location.line())
            } else {
                message.to_string()
            };
            // Raise the panic and expect it to be caught.
            panic::begin_panic(Box::new(OopsInfo { message, thread }));
        }
    }

    let preempt_guard = disable_preempt();
    let thread = Thread::current();
    let cpu = preempt_guard.current_cpu();

    // Halt the system if the panic is not caught.
    if let Some(location) = info.location() {
        ostd::error!(
            "Uncaught panic:\n\t{}\n\tat {}:{}\n\ton CPU {} by thread {:?}",
            message,
            location.file(),
            location.line(),
            cpu.as_usize(),
            thread,
        );
    } else {
        ostd::error!(
            "Uncaught panic:\n\t{}\n\ton CPU {} by thread {:?}",
            message,
            cpu.as_usize(),
            thread,
        );
    }

    if info.can_unwind() {
        panic::print_stack_trace();
    } else {
        ostd::error!("Backtrace is disabled.");
    }

    let panic_timeout = PANIC_TIMEOUT.load(Ordering::Relaxed);
    match panic_timeout {
        0 => {
            // Default: power off
            panic::abort();
        }
        t if t < 0 => {
            // Negative: reboot immediately
            ostd::power::restart(ostd::power::ExitCode::Failure);
        }
        t => {
            // Positive: reboot after t seconds
            ostd::info!("Panic: rebooting in {} seconds...", t);
            panic::spin_delay_secs(t as u64);
            ostd::power::restart(ostd::power::ExitCode::Failure);
        }
    }
}
