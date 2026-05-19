// SPDX-License-Identifier: MPL-2.0

//! Guest CPU context (register state).
//!
//! `GuestContext` holds the complete guest CPU state: general-purpose registers,
//! instruction pointer, flags, segment registers, control registers, and
//! descriptor tables. It is the guest-mode analog of `UserContext`.
//!
//! Note: Guest GPRs (RAX-R15) are NOT VMCS fields in Intel VT-x. They must be
//! saved/restored explicitly by the VM entry/exit assembly trampoline via the
//! `GuestGprSaveArea` struct. The `load_into_vmcs`/`save_from_vmcs` methods
//! only handle VMCS-accessible fields (RIP, RSP, RFLAGS, CRs, segments, EFER).

use crate::arch::guest::vmx::{vmread, vmwrite, vmcs_field};

/// Guest general-purpose register save area.
///
/// This struct is used by the assembly VM entry/exit trampoline to
/// save and restore guest GPRs. The layout must match the assembly code
/// in `asm.S`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GuestGprSaveArea {
    /// RAX
    pub rax: u64,
    /// RBX
    pub rbx: u64,
    /// RCX
    pub rcx: u64,
    /// RDX
    pub rdx: u64,
    /// RSI
    pub rsi: u64,
    /// RDI
    pub rdi: u64,
    /// RBP
    pub rbp: u64,
    /// R8
    pub r8: u64,
    /// R9
    pub r9: u64,
    /// R10
    pub r10: u64,
    /// R11
    pub r11: u64,
    /// R12
    pub r12: u64,
    /// R13
    pub r13: u64,
    /// R14
    pub r14: u64,
    /// R15
    pub r15: u64,
}

/// Guest system registers (segments, CRs, descriptor tables).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GuestSregs {
    /// Guest RSP (managed via VMCS GUEST_RSP, not in GPR save area).
    pub rsp: u64,
    /// Guest CR0.
    pub cr0: u64,
    /// Guest CR2 (not in VMCS, maintained by software).
    pub cr2: u64,
    /// Guest CR3.
    pub cr3: u64,
    /// Guest CR4.
    pub cr4: u64,
    /// Guest EFER.
    pub efer: u64,
    /// Guest APIC base.
    pub apic_base: u64,
}

/// Guest CPU state (GPRs, RIP, RFLAGS, system registers).
///
/// This is the guest-mode analog of `UserContext`. GPRs are saved/restored
/// by the assembly trampoline (not through VMCS), while RIP, RSP, RFLAGS,
/// and system registers are synchronized with VMCS.
#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct GuestContext {
    /// General-purpose registers (saved/restored by assembly, not VMCS).
    pub gprs: GuestGprSaveArea,
    /// Instruction pointer (VMCS field).
    pub rip: u64,
    /// RFLAGS register (VMCS field).
    pub rflags: u64,
    /// System registers (VMCS fields).
    pub sregs: GuestSregs,
}

impl GuestContext {
    /// Creates a new `GuestContext` with all registers zeroed.
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads guest context into VMCS fields before VM entry.
    ///
    /// Only VMCS-accessible fields are written. GPRs are loaded from the
    /// `GuestGprSaveArea` by the assembly trampoline.
    ///
    /// # Safety
    ///
    /// The VMCS must be loaded (VMPTRLD) on the current CPU.
    pub(crate) unsafe fn load_into_vmcs(&self) {
        // SAFETY: VMCS is loaded on the current CPU.
        unsafe {
            vmwrite(vmcs_field::GUEST_RIP, self.rip);
            vmwrite(vmcs_field::GUEST_RFLAGS, self.rflags);
            vmwrite(vmcs_field::GUEST_RSP, self.sregs.rsp);
            vmwrite(vmcs_field::GUEST_CR0, self.sregs.cr0);
            vmwrite(vmcs_field::GUEST_CR3, self.sregs.cr3);
            vmwrite(vmcs_field::GUEST_CR4, self.sregs.cr4);
            vmwrite(vmcs_field::GUEST_IA32_EFER, self.sregs.efer);
        }
    }

    /// Saves guest context from VMCS fields after VM exit.
    ///
    /// Only VMCS-accessible fields are read. GPRs are saved to the
    /// `GuestGprSaveArea` by the assembly trampoline.
    ///
    /// # Safety
    ///
    /// The VMCS must be loaded (VMPTRLD) on the current CPU.
    pub(crate) unsafe fn save_from_vmcs(&mut self) {
        // SAFETY: VMCS is loaded on the current CPU.
        unsafe {
            self.rip = vmread(vmcs_field::GUEST_RIP);
            self.rflags = vmread(vmcs_field::GUEST_RFLAGS);
            self.sregs.rsp = vmread(vmcs_field::GUEST_RSP);
            self.sregs.cr0 = vmread(vmcs_field::GUEST_CR0);
            self.sregs.cr3 = vmread(vmcs_field::GUEST_CR3);
            self.sregs.cr4 = vmread(vmcs_field::GUEST_CR4);
            self.sregs.efer = vmread(vmcs_field::GUEST_IA32_EFER);
        }
    }
}
