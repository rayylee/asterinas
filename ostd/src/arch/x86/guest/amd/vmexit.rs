// SPDX-License-Identifier: MPL-2.0

//! AMD SVM VM exit reason handling.
//!
//! Provides SVM-specific exit decoding using shared `GuestExitReason`.

use crate::arch::guest::{CpuidAccess, EptViolationInfo, GuestExitReason, IoPortAccess, MsrAccess};

/// SVM exit code values (from AMD APM Vol 2).
#[allow(dead_code)]
pub(crate) mod svm_exit_code {
    pub const INTR: u64 = 0x060;
    pub const NMI: u64 = 0x062;
    pub const INIT: u64 = 0x064;
    pub const FERR_FREEZE: u64 = 0x066;
    pub const SHUTDOWN: u64 = 0x068;
    pub const CPUID: u64 = 0x072;
    pub const INVD: u64 = 0x074;
    pub const INVLPG: u64 = 0x075;
    pub const HLT: u64 = 0x078;
    pub const IOIO: u64 = 0x07B;
    pub const MSR: u64 = 0x07C;
    pub const VMMCALL: u64 = 0x081;
    pub const INTR_SOFT: u64 = 0x082;
    pub const RDPMC: u64 = 0x084;
    pub const RDTSC: u64 = 0x085;
    pub const PUSHF_POPF: u64 = 0x086;
    pub const INVLPG_SOFT: u64 = 0x08A;
    pub const MONITOR: u64 = 0x08B;
    pub const MWAIT: u64 = 0x08C;
    pub const NPF: u64 = 0x400;
}

/// Raw exit info populated from VMCB after SVM #VMEXIT.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SvmExitInfo {
    /// Exit reason code from VMCB control area (offset 0x47C).
    pub exit_reason: u32,
    /// Exit info 1 from VMCB control area (offset 0x480).
    pub exit_info1: u64,
    /// Exit info 2 from VMCB control area (offset 0x488).
    /// For NPT violations this is the guest physical address.
    pub exit_info2: u64,
    /// Exit interrupt info from VMCB control area (offset 0x490).
    pub exit_int_info: u32,
}

/// Decodes an SVM VM exit into a `GuestExitReason`.
///
/// # Safety
///
/// The VMCB must be valid and a VM exit must have just occurred.
pub(crate) unsafe fn decode_exit(
    exit_info: &SvmExitInfo,
    guest_rax: u64,
    guest_rcx: u64,
    guest_rdx: u64,
) -> GuestExitReason {
    let exit_reason_code = exit_info.exit_reason as u64;
    let exit_info1 = exit_info.exit_info1;
    let guest_paddr = exit_info.exit_info2;

    match exit_reason_code {
        svm_exit_code::INTR => GuestExitReason::KernelEvent,
        svm_exit_code::NMI => GuestExitReason::KernelEvent,
        svm_exit_code::INIT => GuestExitReason::KernelEvent,
        svm_exit_code::FERR_FREEZE => GuestExitReason::KernelEvent,

        svm_exit_code::SHUTDOWN => GuestExitReason::Shutdown,

        svm_exit_code::VMMCALL => GuestExitReason::InternalError,

        svm_exit_code::IOIO => {
            // AMD SVM IOIO EXITINFO1 encoding (AMD APM Vol 2, Table 15-20):
            //   Bit 0:     Type (0=OUT, 1=IN)
            //   Bits 6:4:  Access size (0=1b, 1=2b, 2=4b, 3=8b)
            //   Bits 31:16: Port number
            let port = (exit_info1 >> 16) as u16;
            let is_write = (exit_info1 & 1) == 0;
            let size = 1 << ((exit_info1 >> 4) & 0x7);
            let value = if is_write { guest_rax as u32 } else { 0 };

            GuestExitReason::Io(IoPortAccess {
                port,
                is_write,
                size,
                value,
            })
        }

        svm_exit_code::HLT => GuestExitReason::Hlt,

        svm_exit_code::MSR => {
            // MSR exit: EXITINFO1[0] = 0 for RDMSR, 1 for WRMSR
            let is_write = (exit_info1 & 0x1) != 0;
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

        svm_exit_code::CPUID => GuestExitReason::Cpuid(CpuidAccess {
            leaf: guest_rax as u32,
            sub_leaf: guest_rcx as u32,
        }),

        svm_exit_code::NPF => {
            // Nested page fault: exit_info2 has GPA, exit_info1 has error code
            // NPF error code: bit 0=read, 1=write, 2=execute, 3=user, 4=rsvd, 5=present
            let is_write = (exit_info1 & 0x2) != 0;
            let is_execute = (exit_info1 & 0x4) != 0;

            GuestExitReason::MemoryFault(EptViolationInfo {
                gpa: guest_paddr,
                is_write,
                is_execute,
            })
        }

        _ => {
            crate::warn!(
                "Unhandled SVM exit reason: {} (info1: {:#x}, info2: {:#x})",
                exit_reason_code,
                exit_info1,
                guest_paddr
            );
            GuestExitReason::InternalError
        }
    }
}
