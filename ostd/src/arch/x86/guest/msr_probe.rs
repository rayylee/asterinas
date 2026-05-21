// SPDX-License-Identifier: MPL-2.0

//! Safe MSR probe functions using the kernel exception table.
//!
//! These functions attempt to read/write MSRs and recover gracefully
//! from #GP faults instead of panicking. This is essential for
//! detecting whether hardware virtualization (VMX/SVM) is actually
//! usable on the current system.

use core::arch::global_asm;

// Try-wrmsr: attempts to write an MSR. Returns 0 on success, 1 on #GP.
//
// Uses SysV ABI: rdi = MSR index, rsi = value (low 32 bits), rdx = value (high 32 bits)
// The function moves args to the correct wrmsr registers (RCX, EAX, EDX) internally.
global_asm!(
    ".balign 16",
    ".global __try_wrmsr",
    ".type __try_wrmsr, @function",
    "__try_wrmsr:",
    "    mov rcx, rdi", // rcx = MSR index
    "    mov eax, esi", // eax = value low 32
    "    mov edx, edx", // edx = value high 32 (already in rdx from SysV arg 3)
    "2:",
    "    wrmsr",
    "    xor eax, eax", // success: rax = 0
    "    ret",
    // Recovery point: trap handler jumps here on #GP
    "3:",
    "    mov eax, 1", // failure: rax = 1
    "    ret",
    ".size __try_wrmsr, . - __try_wrmsr",
    // Exception table entry: if #GP occurs at label 2, jump to label 3
    ".pushsection .ex_table, \"a\"",
    ".align 8",
    ".quad 2b",
    ".quad 3b",
    ".popsection",
);

// Try-rdmsr: attempts to read an MSR. Returns the value on success,
// or 0xFFFFFFFFFFFFFFFF on #GP.
//
// Uses SysV ABI: rdi = MSR index
// Returns: rax = (edx << 32) | eax on success, or -1 on #GP
global_asm!(
    ".balign 16",
    ".global __try_rdmsr",
    ".type __try_rdmsr, @function",
    "__try_rdmsr:",
    "    mov rcx, rdi", // rcx = MSR index
    "2:",
    "    rdmsr",
    "    shl rdx, 32",
    "    or rax, rdx", // rax = (edx << 32) | eax
    "    ret",
    // Recovery point: trap handler jumps here on #GP
    "3:",
    "    mov rax, -1", // failure: rax = 0xFFFFFFFFFFFFFFFF
    "    ret",
    ".size __try_rdmsr, . - __try_rdmsr",
    // Exception table entry
    ".pushsection .ex_table, \"a\"",
    ".align 8",
    ".quad 2b",
    ".quad 3b",
    ".popsection",
);

unsafe extern "C" {
    /// Tries to write an MSR. Returns 0 on success, 1 on #GP.
    fn __try_wrmsr(msr: u32, value_lo: u32, value_hi: u32) -> u64;
    /// Tries to read an MSR. Returns the value on success,
    /// or 0xFFFFFFFFFFFFFFFF on #GP.
    fn __try_rdmsr(msr: u32) -> u64;
}

/// The sentinel value returned by `try_rdmsr` on #GP.
const RDMSR_FAIL: u64 = u64::MAX;

/// Attempts to write an MSR safely.
///
/// Returns `Ok(())` on success, `Err(())` if the MSR write causes a #GP.
pub fn try_wrmsr(msr: u32, value: u64) -> Result<(), ()> {
    // SAFETY: The __try_wrmsr function uses the exception table to
    // recover from #GP faults. If the wrmsr causes #GP, the trap
    // handler will redirect execution to the recovery label, and
    // the function returns 1.
    let result = unsafe { __try_wrmsr(msr, (value & 0xFFFFFFFF) as u32, (value >> 32) as u32) };
    if result == 0 { Ok(()) } else { Err(()) }
}

/// Attempts to read an MSR safely.
///
/// Returns `Ok(value)` on success, `Err(())` if the MSR read causes a #GP.
pub fn try_rdmsr(msr: u32) -> Result<u64, ()> {
    // SAFETY: The __try_rdmsr function uses the exception table to
    // recover from #GP faults.
    let result = unsafe { __try_rdmsr(msr) };
    if result == RDMSR_FAIL {
        Err(())
    } else {
        Ok(result)
    }
}
