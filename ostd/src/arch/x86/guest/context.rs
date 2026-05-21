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

/// Guest segment register descriptor.
///
/// Stores the full state of a single x86 segment register in a format
/// convenient for converting to/from the KVM `kvm_segment` ABI and
/// VMCS/VMCB hardware formats.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(missing_docs)]
pub struct GuestSegment {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    /// VMCS access-rights format (ar_bytes): type(4) | s(1) | dpl(2) | present(1) |
    /// avl(1) | l(1) | db(1) | g(1) | unusable(1) | padding(5).
    /// This is the raw VMCS format; conversion to/from `kvm_segment` is done
    /// in the kernel services layer.
    pub ar_bytes: u32,
}

/// Guest descriptor table register.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(missing_docs)]
pub struct GuestDtable {
    pub base: u64,
    pub limit: u16,
}

/// Guest system registers.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(missing_docs)]
pub struct GuestSregs {
    pub cs: GuestSegment,
    pub ds: GuestSegment,
    pub es: GuestSegment,
    pub fs: GuestSegment,
    pub gs: GuestSegment,
    pub ss: GuestSegment,
    pub tr: GuestSegment,
    pub ldt: GuestSegment,
    pub gdt: GuestDtable,
    pub idt: GuestDtable,
    pub rsp: u64,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub efer: u64,
    pub apic_base: u64,
}

impl Default for GuestSregs {
    fn default() -> Self {
        // Default 32-bit protected-mode guest state, compatible with common
        // VMM expectations. Long-mode bits (LME/LMA in EFER, L in CS) are NOT
        // set by default — they must be explicitly configured by the VMM.
        let cs = GuestSegment {
            base: 0,
            limit: 0xFFFFFFFF,
            selector: 0x08,
            ar_bytes: 0xC09B, // Code: execute/read, accessed, present, DB=1, G=1
        };
        let data_seg = GuestSegment {
            base: 0,
            limit: 0xFFFFFFFF,
            selector: 0x10,
            ar_bytes: 0xC093, // Data: read/write, accessed, present, DB=1, G=1
        };
        let tr = GuestSegment {
            base: 0,
            limit: 0x67,
            selector: 0x28,
            ar_bytes: 0x008B, // 32-bit TSS, busy, present
        };
        let ldt = GuestSegment {
            base: 0,
            limit: 0xFFFF,
            selector: 0,
            ar_bytes: 0x10000, // Unusable
        };
        Self {
            cs,
            ds: data_seg,
            es: data_seg,
            fs: data_seg,
            gs: data_seg,
            ss: data_seg,
            tr,
            ldt,
            gdt: GuestDtable { base: 0, limit: 0 },
            idt: GuestDtable { base: 0, limit: 0 },
            rsp: 0,
            cr0: (1 << 0) | (1 << 1) | (1 << 4) | (1 << 5) | (1 << 16),
            cr2: 0,
            cr3: 0,
            cr4: 0,
            efer: 1 << 0, // just SCE
            apic_base: 0,
        }
    }
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

            // Segment registers
            load_segment_vmcs(
                vmcs_field::GUEST_ES_SELECTOR,
                vmcs_field::GUEST_ES_LIMIT,
                vmcs_field::GUEST_ES_AR_BYTES,
                vmcs_field::GUEST_ES_BASE,
                &self.sregs.es,
            );
            load_segment_vmcs(
                vmcs_field::GUEST_CS_SELECTOR,
                vmcs_field::GUEST_CS_LIMIT,
                vmcs_field::GUEST_CS_AR_BYTES,
                vmcs_field::GUEST_CS_BASE,
                &self.sregs.cs,
            );
            load_segment_vmcs(
                vmcs_field::GUEST_SS_SELECTOR,
                vmcs_field::GUEST_SS_LIMIT,
                vmcs_field::GUEST_SS_AR_BYTES,
                vmcs_field::GUEST_SS_BASE,
                &self.sregs.ss,
            );
            load_segment_vmcs(
                vmcs_field::GUEST_DS_SELECTOR,
                vmcs_field::GUEST_DS_LIMIT,
                vmcs_field::GUEST_DS_AR_BYTES,
                vmcs_field::GUEST_DS_BASE,
                &self.sregs.ds,
            );
            load_segment_vmcs(
                vmcs_field::GUEST_FS_SELECTOR,
                vmcs_field::GUEST_FS_LIMIT,
                vmcs_field::GUEST_FS_AR_BYTES,
                vmcs_field::GUEST_FS_BASE,
                &self.sregs.fs,
            );
            load_segment_vmcs(
                vmcs_field::GUEST_GS_SELECTOR,
                vmcs_field::GUEST_GS_LIMIT,
                vmcs_field::GUEST_GS_AR_BYTES,
                vmcs_field::GUEST_GS_BASE,
                &self.sregs.gs,
            );
            load_segment_vmcs(
                vmcs_field::GUEST_LDTR_SELECTOR,
                vmcs_field::GUEST_LDTR_LIMIT,
                vmcs_field::GUEST_LDTR_AR_BYTES,
                vmcs_field::GUEST_LDTR_BASE,
                &self.sregs.ldt,
            );
            load_segment_vmcs(
                vmcs_field::GUEST_TR_SELECTOR,
                vmcs_field::GUEST_TR_LIMIT,
                vmcs_field::GUEST_TR_AR_BYTES,
                vmcs_field::GUEST_TR_BASE,
                &self.sregs.tr,
            );

            // GDTR/IDTR
            vmwrite(vmcs_field::GUEST_GDTR_LIMIT, self.sregs.gdt.limit as u64);
            vmwrite(vmcs_field::GUEST_GDTR_BASE, self.sregs.gdt.base);
            vmwrite(vmcs_field::GUEST_IDTR_LIMIT, self.sregs.idt.limit as u64);
            vmwrite(vmcs_field::GUEST_IDTR_BASE, self.sregs.idt.base);
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

            // Segment registers
            save_segment_vmcs(
                vmcs_field::GUEST_ES_SELECTOR,
                vmcs_field::GUEST_ES_LIMIT,
                vmcs_field::GUEST_ES_AR_BYTES,
                vmcs_field::GUEST_ES_BASE,
                &mut self.sregs.es,
            );
            save_segment_vmcs(
                vmcs_field::GUEST_CS_SELECTOR,
                vmcs_field::GUEST_CS_LIMIT,
                vmcs_field::GUEST_CS_AR_BYTES,
                vmcs_field::GUEST_CS_BASE,
                &mut self.sregs.cs,
            );
            save_segment_vmcs(
                vmcs_field::GUEST_SS_SELECTOR,
                vmcs_field::GUEST_SS_LIMIT,
                vmcs_field::GUEST_SS_AR_BYTES,
                vmcs_field::GUEST_SS_BASE,
                &mut self.sregs.ss,
            );
            save_segment_vmcs(
                vmcs_field::GUEST_DS_SELECTOR,
                vmcs_field::GUEST_DS_LIMIT,
                vmcs_field::GUEST_DS_AR_BYTES,
                vmcs_field::GUEST_DS_BASE,
                &mut self.sregs.ds,
            );
            save_segment_vmcs(
                vmcs_field::GUEST_FS_SELECTOR,
                vmcs_field::GUEST_FS_LIMIT,
                vmcs_field::GUEST_FS_AR_BYTES,
                vmcs_field::GUEST_FS_BASE,
                &mut self.sregs.fs,
            );
            save_segment_vmcs(
                vmcs_field::GUEST_GS_SELECTOR,
                vmcs_field::GUEST_GS_LIMIT,
                vmcs_field::GUEST_GS_AR_BYTES,
                vmcs_field::GUEST_GS_BASE,
                &mut self.sregs.gs,
            );
            save_segment_vmcs(
                vmcs_field::GUEST_LDTR_SELECTOR,
                vmcs_field::GUEST_LDTR_LIMIT,
                vmcs_field::GUEST_LDTR_AR_BYTES,
                vmcs_field::GUEST_LDTR_BASE,
                &mut self.sregs.ldt,
            );
            save_segment_vmcs(
                vmcs_field::GUEST_TR_SELECTOR,
                vmcs_field::GUEST_TR_LIMIT,
                vmcs_field::GUEST_TR_AR_BYTES,
                vmcs_field::GUEST_TR_BASE,
                &mut self.sregs.tr,
            );

            // GDTR/IDTR
            self.sregs.gdt.limit = vmread(vmcs_field::GUEST_GDTR_LIMIT) as u16;
            self.sregs.gdt.base = vmread(vmcs_field::GUEST_GDTR_BASE);
            self.sregs.idt.limit = vmread(vmcs_field::GUEST_IDTR_LIMIT) as u16;
            self.sregs.idt.base = vmread(vmcs_field::GUEST_IDTR_BASE);
        }
    }
}

/// Loads a single segment register into VMCS fields.
///
/// # Safety
///
/// The VMCS must be loaded (VMPTRLD) on the current CPU.
#[inline]
unsafe fn load_segment_vmcs(
    sel_field: u32,
    limit_field: u32,
    ar_field: u32,
    base_field: u32,
    seg: &GuestSegment,
) {
    use crate::arch::guest::intel::vmx::vmwrite;

    unsafe {
        vmwrite(sel_field, seg.selector as u64);
        vmwrite(limit_field, seg.limit as u64);
        vmwrite(ar_field, seg.ar_bytes as u64);
        vmwrite(base_field, seg.base);
    }
}

/// Saves a single segment register from VMCS fields.
///
/// # Safety
///
/// The VMCS must be loaded (VMPTRLD) on the current CPU.
#[inline]
unsafe fn save_segment_vmcs(
    sel_field: u32,
    limit_field: u32,
    ar_field: u32,
    base_field: u32,
    seg: &mut GuestSegment,
) {
    use crate::arch::guest::intel::vmx::vmread;

    unsafe {
        seg.selector = vmread(sel_field) as u16;
        seg.limit = vmread(limit_field) as u32;
        seg.ar_bytes = vmread(ar_field) as u32;
        seg.base = vmread(base_field);
    }
}
