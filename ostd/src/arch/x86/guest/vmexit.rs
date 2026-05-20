// SPDX-License-Identifier: MPL-2.0

//! Shared VM exit reason handling.
//!
//! Provides the `GuestExitReason` enum and related types used by
//! both Intel VT-x and AMD SVM virtualization implementations.

/// I/O port access details from VM exit.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct IoPortAccess {
    /// Port number.
    pub port: u16,
    /// True for OUT, false for IN.
    pub is_write: bool,
    /// Size of the access in bytes (1, 2, or 4).
    pub size: u8,
    /// Data value (for OUT: the value written; for IN: to be filled by handler).
    pub value: u32,
}

/// MMIO access details from VM exit.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct MmioAccess {
    /// Guest physical address that caused the fault.
    pub gpa: u64,
    /// True if the access was a write.
    pub is_write: bool,
    /// Size of the access in bytes.
    pub size: u8,
    /// Data value (for write: the value; for read: to be filled).
    pub value: u64,
}

/// MSR access details from VM exit.
///
/// For RDMSR, `is_write` is false and `value` is 0 (the handler should
/// write the result back via guest EDX:EAX).
/// For WRMSR, `is_write` is true and `value` is the 64-bit value being
/// written, composed from `(RDX << 32) | RAX`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct MsrAccess {
    /// MSR index (from guest RCX).
    pub msr_index: u32,
    /// True for WRMSR, false for RDMSR.
    pub is_write: bool,
    /// For WRMSR: the 64-bit value from `(EDX << 32) | EAX`.
    /// For RDMSR: 0 (handler writes result to guest EDX:EAX).
    pub value: u64,
}

/// EPT violation information.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct EptViolationInfo {
    /// Guest physical address that caused the violation.
    pub gpa: u64,
    /// True if the access was a write.
    pub is_write: bool,
    /// True if the access was an instruction fetch.
    pub is_execute: bool,
}

/// VM entry failure information.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct FailEntryInfo {
    /// Hardware entry failure reason code.
    pub entry_reason: u32,
}

/// CPUID exit details.
///
/// The guest executed a CPUID instruction. The handler must write
/// the results back to guest EAX/EBX/ECX/EDX and advance RIP.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct CpuidAccess {
    /// CPUID leaf (from guest EAX).
    pub leaf: u32,
    /// CPUID sub-leaf (from guest ECX).
    pub sub_leaf: u32,
}

/// Reason for returning from guest execution.
///
/// This is the safe OSTD-level representation of VM exit reasons.
/// The kernel services layer uses this to decide how to handle each exit.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum GuestExitReason {
    /// I/O port access (IN/OUT instruction).
    Io(IoPortAccess),
    /// MMIO access (EPT/NPT violation on non-RAM address).
    Mmio(MmioAccess),
    /// MSR access (RDMSR/WRMSR).
    Msr(MsrAccess),
    /// CPUID instruction execution.
    Cpuid(CpuidAccess),
    /// Guest executed HLT.
    Hlt,
    /// Guest shutdown (triple fault or similar).
    Shutdown,
    /// EPT/NPT violation or misconfiguration.
    MemoryFault(EptViolationInfo),
    /// VM entry failure.
    FailEntry(FailEntryInfo),
    /// Internal OSTD error.
    InternalError,
    /// Kernel event pending (signal, timeout, etc.).
    KernelEvent,
}
