// SPDX-License-Identifier: MPL-2.0

//! VM exit reason handling.
//!
//! Provides the `GuestExitReason` enum and the mapping from VMX exit codes
//! to the safe OSTD API.

use crate::arch::guest::vmx::exit_reason;

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
    /// For OUT, this comes from guest RAX which is in the GPR save area.
    pub value: u32,
}

/// MMIO access details from EPT violation.
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
    /// MMIO access (EPT violation on non-RAM address).
    Mmio(MmioAccess),
    /// MSR access (RDMSR/WRMSR).
    Msr(MsrAccess),
    /// CPUID instruction execution.
    Cpuid(CpuidAccess),
    /// Guest executed HLT.
    Hlt,
    /// Guest shutdown (triple fault or similar).
    Shutdown,
    /// EPT violation or misconfiguration.
    MemoryFault(EptViolationInfo),
    /// VM entry failure.
    FailEntry(FailEntryInfo),
    /// Internal OSTD error.
    InternalError,
    /// Kernel event pending (signal, timeout, etc.).
    KernelEvent,
}

/// Raw exit info populated by the assembly VM exit handler.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct VmxExitInfo {
    /// Exit reason (low 16 bits are the basic exit reason).
    pub exit_reason: u32,
    /// VM exit interrupt information.
    pub exit_intr_info: u32,
    /// Exit qualification.
    pub exit_qualification: u64,
    /// Guest physical address (for EPT violations).
    pub guest_physical_address: u64,
}

/// Decodes a VM exit into a `GuestExitReason`.
///
/// # Arguments
///
/// * `exit_info` - The raw exit info from the assembly handler.
/// * `guest_rax` - Guest RAX value from the GPR save area (needed for I/O and MSR exits).
/// * `guest_rcx` - Guest RCX value from the GPR save area (MSR index for MSR exits).
/// * `guest_rdx` - Guest RDX value from the GPR save area (high 32 bits for WRMSR).
///
/// # Safety
///
/// The VMCS must be loaded on the current CPU and a VM exit must have just occurred.
pub(crate) unsafe fn decode_exit(
    exit_info: &VmxExitInfo,
    guest_rax: u64,
    guest_rcx: u64,
    guest_rdx: u64,
) -> GuestExitReason {
    let exit_reason_code = exit_info.exit_reason & 0xFFFF;
    let exit_qualification = exit_info.exit_qualification;
    let guest_paddr = exit_info.guest_physical_address;

    match exit_reason_code {
        exit_reason::EXTERNAL_INTERRUPT => GuestExitReason::KernelEvent,

        exit_reason::HLT => GuestExitReason::Hlt,

        exit_reason::IO_INSTRUCTION => {
            let is_write = (exit_qualification & 0x1) != 0;
            let size_bits = ((exit_qualification >> 1) & 0x3) as u8;
            let size = match size_bits {
                0 => 1,
                1 => 2,
                3 => 4,
                _ => 1,
            };
            let port = ((exit_qualification >> 16) & 0xFFFF) as u16;

            // For OUT, the data comes from guest RAX (in GPR save area)
            let value = if is_write { guest_rax as u32 } else { 0 };

            GuestExitReason::Io(IoPortAccess {
                port,
                is_write,
                size,
                value,
            })
        }

        exit_reason::EPT_VIOLATION | exit_reason::EPT_MISCONFIGURATION => {
            let is_write = (exit_qualification & 0x2) != 0;
            let is_execute = (exit_qualification & 0x4) != 0;

            GuestExitReason::MemoryFault(EptViolationInfo {
                gpa: guest_paddr,
                is_write,
                is_execute,
            })
        }

        exit_reason::EXCEPTION_OR_NMI => {
            if exit_info.exit_reason & (1 << 31) != 0 {
                GuestExitReason::Shutdown
            } else {
                GuestExitReason::KernelEvent
            }
        }

        exit_reason::TRIPLE_FAULT => GuestExitReason::Shutdown,

        exit_reason::INTERRUPT_WINDOW | exit_reason::NMI_WINDOW => GuestExitReason::KernelEvent,

        exit_reason::CR_ACCESS => GuestExitReason::KernelEvent,

        exit_reason::MSR_READ | exit_reason::MSR_WRITE => {
            let is_write = exit_reason_code == exit_reason::MSR_WRITE;
            let msr_index = guest_rcx as u32;
            let value = if is_write {
                // WRMSR: value = (EDX << 32) | EAX
                (guest_rdx << 32) | (guest_rax & 0xFFFFFFFF)
            } else {
                0
            };
            GuestExitReason::Msr(MsrAccess {
                msr_index,
                is_write,
                value,
            })
        }

        exit_reason::CPUID => GuestExitReason::Cpuid(CpuidAccess {
            leaf: guest_rax as u32,
            sub_leaf: guest_rcx as u32,
        }),

        _ => {
            crate::warn!(
                "Unhandled VM exit reason: {} (qualification: {:#x})",
                exit_reason_code,
                exit_qualification
            );
            GuestExitReason::InternalError
        }
    }
}
