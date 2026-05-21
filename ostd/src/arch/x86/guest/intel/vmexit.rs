// SPDX-License-Identifier: MPL-2.0

//! Intel VMX VM exit reason handling.
//!
//! Provides VMX-specific exit decoding using shared `GuestExitReason`.

use super::vmx::exit_reason;
use crate::arch::guest::{CpuidAccess, EptViolationInfo, GuestExitReason, IoPortAccess, MsrAccess};

/// Raw exit info populated by the Intel VMX assembly VM exit handler.
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

/// Decodes a VMX VM exit into a `GuestExitReason`.
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
