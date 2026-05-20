// SPDX-License-Identifier: MPL-2.0

//! Guest CPU context (register state).
//!
//! `GuestContext` holds the complete guest CPU state: general-purpose registers,
//! instruction pointer, flags, segment registers, control registers.
//! It is the guest-mode analog of `UserContext`.

/// Guest general-purpose register save area.
///
/// Used by the assembly VM entry/exit trampoline to save and restore
/// guest GPRs. The layout must match the assembly code.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(missing_docs)]
pub struct GuestGprSaveArea {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

/// Guest system registers.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(missing_docs)]
pub struct GuestSregs {
    pub rsp: u64,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub efer: u64,
    pub apic_base: u64,
}

/// Guest CPU state (GPRs, RIP, RFLAGS, system registers).
#[repr(C)]
#[derive(Clone, Debug, Default)]
#[allow(missing_docs)]
pub struct GuestContext {
    pub gprs: GuestGprSaveArea,
    pub rip: u64,
    pub rflags: u64,
    pub sregs: GuestSregs,
}

impl GuestContext {
    #[allow(missing_docs)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads guest context into VMCS fields before VM entry.
    ///
    /// # Safety
    ///
    /// The VMCS must be loaded (VMPTRLD) on the current CPU.
    pub(crate) unsafe fn load_into_vmcs(&self) {
        use crate::arch::guest::intel::vmx::{vmcs_field, vmwrite};

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
    /// # Safety
    ///
    /// The VMCS must be loaded (VMPTRLD) on the current CPU.
    pub(crate) unsafe fn save_from_vmcs(&mut self) {
        use crate::arch::guest::intel::vmx::{vmcs_field, vmread};

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
