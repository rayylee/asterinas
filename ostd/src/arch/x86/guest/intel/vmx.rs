// SPDX-License-Identifier: MPL-2.0

//! VMX capability detection, VMXON/VMXOFF lifecycle, and per-CPU reference counting.

use crate::{
    cpu::CpuId,
    mm::{FrameAllocOptions, UFrame, paddr_to_vaddr},
    prelude::*,
    Error,
};
use crate::cpu_local_cell;

/// VMX instruction result.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum VmxResult {
    /// Operation succeeded.
    Ok,
    /// Operation failed.
    Failed,
    /// VMX error.
    Error,
}

impl VmxResult {
    fn from_asm_result(val: u32) -> Self {
        match val {
            0 => Self::Ok,
            1 => Self::Failed,
            2 => Self::Error,
            _ => Self::Error,
        }
    }
}

unsafe extern "C" {
    fn asm_vmxon(paddr: Paddr) -> u32;
    fn asm_vmxoff() -> u32;
    fn asm_vmptrld(paddr: Paddr) -> u32;
    fn asm_vmclear(paddr: Paddr) -> u32;
    fn asm_vmread(field: u32) -> u64;
    fn asm_vmwrite(field: u32, value: u64) -> u32;
    fn asm_invept(type_: u64, desc: *const u64) -> u32;
}

// Per-CPU VMX reference count and VMXON frame storage.
cpu_local_cell! {
    /// Reference count of active GuestMode instances on this CPU.
    static VMX_REF_COUNT: u32 = 0;
}

fn vmxon_frames() -> &'static spin::Mutex<alloc::collections::BTreeMap<u32, Arc<UFrame>>> {
    static FRAMES: spin::Once<spin::Mutex<alloc::collections::BTreeMap<u32, Arc<UFrame>>>> =
        spin::Once::new();
    FRAMES.call_once(|| spin::Mutex::new(alloc::collections::BTreeMap::new()));
    FRAMES.get().unwrap()
}

/// VMX capability information cached on boot.
#[derive(Debug, Clone, Copy)]
pub(crate) struct VmxCapabilities {
    /// VMCS revision ID (from MSR 0x480).
    pub vmcs_revision_id: u32,
    /// Pin-based VM-execution controls: (must_be_1, allowed_1) from MSR 0x481.
    pub pin_based_ctrls: (u32, u32),
    /// Primary processor-based VM-execution controls: (must_be_1, allowed_1) from MSR 0x482.
    pub primary_proc_ctrls: (u32, u32),
    /// Secondary processor-based VM-execution controls: (must_be_1, allowed_1) from MSR 0x484B.
    pub secondary_proc_ctrls: (u32, u32),
    /// VM-exit controls: (must_be_1, allowed_1) from MSR 0x483.
    pub exit_ctrls: (u32, u32),
    /// VM-entry controls: (must_be_1, allowed_1) from MSR 0x484.
    pub entry_ctrls: (u32, u32),
    /// EPT capabilities (from MSR 0x4849).
    #[expect(dead_code)]
    pub ept_cap: u64,
}

static VMX_CAPS: spin::Once<VmxCapabilities> = spin::Once::new();

/// Checks if VMX is supported on this CPU.
pub(crate) fn is_vmx_supported() -> bool {
    let result = crate::arch::cpu::cpuid::cpuid(0x1, 0x0);
    let ecx = result.map(|r| r.ecx).unwrap_or(0);
    (ecx & (1 << 5)) != 0
}

/// Reads a VMX capability MSR and extracts the (must_be_1, allowed_1) pair.
///
/// VMX capability MSRs are 64-bit values where:
/// - Low 32 bits: bits that are allowed to be 0. If a bit is 0 here, the
///   corresponding control bit MUST be 1.
/// - High 32 bits: bits that are allowed to be 1. If a bit is 0 here, the
///   corresponding control bit MUST be 0.
fn read_vmx_ctl_msr(msr: u32) -> (u32, u32) {
    // SAFETY: Reading a VMX MSR is safe if VMX is supported.
    let val = unsafe { x86_64::registers::model_specific::Msr::new(msr).read() };
    let must_be_1 = !(val as u32); // Bits that are 0 in low half must be 1
    let allowed_1 = (val >> 32) as u32; // Bits allowed to be 1
    (must_be_1, allowed_1)
}

/// Detects and caches VMX capabilities.
///
/// Must be called once during early init on the BSP.
pub fn detect_vmx_capabilities() -> Result<VmxCapabilities> {
    if !is_vmx_supported() {
        return Err(Error::InvalidArgs);
    }

    // Check IA32_FEATURE_CONTROL MSR (0x3A)
    // SAFETY: Reading IA32_FEATURE_CONTROL is safe.
    let feature_control = unsafe { x86_64::registers::model_specific::Msr::new(0x3A).read() };
    let lock_bit = feature_control & (1 << 0);
    let vmx_inside_smx = feature_control & (1 << 1);
    let vmx_outside_smx = feature_control & (1 << 2);

    if lock_bit == 0 {
        return Err(Error::InvalidArgs);
    }

    if vmx_inside_smx == 0 && vmx_outside_smx == 0 {
        return Err(Error::AccessDenied);
    }

    // Read VMX basic MSR (0x480) for revision ID
    // SAFETY: Reading VMX MSR is safe.
    let vmx_basic = unsafe { x86_64::registers::model_specific::Msr::new(0x480).read() };
    let vmcs_revision_id = vmx_basic as u32 & 0x7FFFFFFF;

    let pin_based_ctrls = read_vmx_ctl_msr(0x481);
    let primary_proc_ctrls = read_vmx_ctl_msr(0x482);
    let exit_ctrls = read_vmx_ctl_msr(0x483);
    let entry_ctrls = read_vmx_ctl_msr(0x484);
    let secondary_proc_ctrls = read_vmx_ctl_msr(0x484B);

    // SAFETY: Reading EPT capability MSR is safe.
    let ept_cap = unsafe { x86_64::registers::model_specific::Msr::new(0x4849).read() };

    let caps = VmxCapabilities {
        vmcs_revision_id,
        pin_based_ctrls,
        primary_proc_ctrls,
        secondary_proc_ctrls,
        exit_ctrls,
        entry_ctrls,
        ept_cap,
    };

    VMX_CAPS.call_once(|| caps);

    Ok(caps)
}

/// Returns cached VMX capabilities.
pub(crate) fn vmx_capabilities() -> &'static VmxCapabilities {
    VMX_CAPS.get().expect("VMX capabilities not detected yet")
}

/// Adjusts control value to conform to VMX capability requirements.
///
/// - `must_be_1`: bits that must be set to 1 (from the "allowed 0-settings")
/// - `allowed_1`: bits that are allowed to be 1 (from the "allowed 1-settings")
pub(crate) fn adjust_vmx_control(ctrl: u32, must_be_1: u32, allowed_1: u32) -> u32 {
    (ctrl | must_be_1) & allowed_1
}

/// Enters VMX root operation on the current CPU.
///
/// If this is the first GuestMode on this CPU, performs VMXON.
/// Otherwise, increments the per-CPU reference count.
pub(crate) fn vmx_enter() -> Result<()> {
    let prev_count = VMX_REF_COUNT.load();
    if prev_count > 0 {
        VMX_REF_COUNT.add_assign(1);
        return Ok(());
    }

    // First GuestMode on this CPU: perform VMXON
    // SAFETY: We verified VMX support. Setting CR4.VMXE is required
    // before VMXON and is safe at CPL 0.
    unsafe {
        x86_64::registers::control::Cr4::update(|cr4| {
            *cr4 |= x86_64::registers::control::Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS;
        });
    }

    // Allocate VMXON region (4KB)
    let vmxon_frame = FrameAllocOptions::new()
        .alloc_frame()
        .map_err(|_| Error::NoMemory)?;

    // Write VMCS revision ID at byte 0-3 of VMXON region
    let revision_id = vmx_capabilities().vmcs_revision_id;
    let vaddr = paddr_to_vaddr(vmxon_frame.paddr());
    // SAFETY: We just allocated this frame. Writing the revision ID
    // is required by the VMX specification.
    unsafe {
        core::ptr::write_volatile(vaddr as *mut u32, revision_id);
    }

    let vmxon_paddr = vmxon_frame.paddr();
    // SAFETY: VMXON region is properly initialized, CR4.VMXE is set,
    // and we are at CPL 0.
    let result = unsafe { asm_vmxon(vmxon_paddr) };
    let result = VmxResult::from_asm_result(result);

    if result != VmxResult::Ok {
        // SAFETY: Clearing CR4.VMXE after failed VMXON.
        unsafe {
            x86_64::registers::control::Cr4::update(|cr4| {
                *cr4 -= x86_64::registers::control::Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS;
            });
        }
        return Err(Error::IoError);
    }

    VMX_REF_COUNT.add_assign(1);

    // Store the VMXON frame so it stays alive while VMX root mode is active
    let cpu_id: u32 = CpuId::current_racy().into();
    vmxon_frames().lock().insert(cpu_id, Arc::new(vmxon_frame.into()));

    Ok(())
}

/// Leaves VMX root operation on the current CPU (if last reference).
pub(crate) fn vmx_exit() {
    let prev_count = VMX_REF_COUNT.load();
    assert!(prev_count > 0, "VMX reference count underflow");

    VMX_REF_COUNT.sub_assign(1);

    if VMX_REF_COUNT.load() == 0 {
        // SAFETY: We are the last reference, so no other GuestMode is active.
        let result = unsafe { asm_vmxoff() };
        let result = VmxResult::from_asm_result(result);

        if result != VmxResult::Ok {
            crate::error!("VMXOFF failed on CPU");
        }

        // SAFETY: VMX is now off, clearing VMXE is safe.
        unsafe {
            x86_64::registers::control::Cr4::update(|cr4| {
                *cr4 -= x86_64::registers::control::Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS;
            });
        }

        // Release the VMXON frame for this CPU
        let cpu_id: u32 = CpuId::current_racy().into();
        vmxon_frames().lock().remove(&cpu_id);
    }
}

/// Reads a VMCS field.
///
/// # Safety
///
/// The caller must ensure that a VMCS is loaded (VMPTRLD) on the current CPU.
pub(crate) unsafe fn vmread(field: u32) -> u64 {
    // SAFETY: The caller ensures VMCS is loaded on the current CPU.
    unsafe { asm_vmread(field) }
}

/// Writes a VMCS field.
///
/// # Safety
///
/// The caller must ensure that a VMCS is loaded (VMPTRLD) on the current CPU.
pub(crate) unsafe fn vmwrite(field: u32, value: u64) -> VmxResult {
    // SAFETY: The caller ensures VMCS is loaded on the current CPU.
    VmxResult::from_asm_result(unsafe { asm_vmwrite(field, value) })
}

/// Loads a VMCS on the current CPU.
///
/// # Safety
///
/// The caller must ensure the VMCS region at `paddr` is valid.
pub(crate) unsafe fn vmptrld(paddr: Paddr) -> VmxResult {
    // SAFETY: The caller ensures the VMCS region at `paddr` is valid.
    VmxResult::from_asm_result(unsafe { asm_vmptrld(paddr) })
}

/// Clears a VMCS from the current CPU.
///
/// # Safety
///
/// The caller must ensure the VMCS region at `paddr` is valid.
pub(crate) unsafe fn vmclear(paddr: Paddr) -> VmxResult {
    // SAFETY: The caller ensures the VMCS region at `paddr` is valid.
    VmxResult::from_asm_result(unsafe { asm_vmclear(paddr) })
}

/// Invalidates EPT translations (all contexts).
///
/// # Safety
///
/// The caller must ensure EPT is configured and VMX root mode is active.
pub(crate) unsafe fn invept_all() {
    let desc: [u64; 2] = [0, 0];
    // SAFETY: The caller ensures EPT is configured and VMX root mode is active.
    unsafe { asm_invept(2, desc.as_ptr()); }
}

/// VMCS field encoding constants.
pub(crate) mod vmcs_field {
    // 16-bit guest-state fields
    pub const GUEST_ES_SELECTOR: u32 = 0x0800;
    pub const GUEST_CS_SELECTOR: u32 = 0x0802;
    pub const GUEST_SS_SELECTOR: u32 = 0x0804;
    pub const GUEST_DS_SELECTOR: u32 = 0x0806;
    pub const GUEST_FS_SELECTOR: u32 = 0x0808;
    pub const GUEST_GS_SELECTOR: u32 = 0x080A;
    pub const GUEST_LDTR_SELECTOR: u32 = 0x080C;
    pub const GUEST_TR_SELECTOR: u32 = 0x080E;

    // 16-bit host-state fields
    pub const HOST_ES_SELECTOR: u32 = 0x0C00;
    pub const HOST_CS_SELECTOR: u32 = 0x0C02;
    pub const HOST_SS_SELECTOR: u32 = 0x0C04;
    pub const HOST_DS_SELECTOR: u32 = 0x0C06;
    pub const HOST_FS_SELECTOR: u32 = 0x0C08;
    pub const HOST_GS_SELECTOR: u32 = 0x0C0A;
    pub const HOST_TR_SELECTOR: u32 = 0x0C0C;

    // 64-bit control fields
    #[expect(dead_code)]
    pub const ADDRESS_OF_IO_BITMAP_A: u32 = 0x2000;
    #[expect(dead_code)]
    pub const ADDRESS_OF_IO_BITMAP_B: u32 = 0x2002;
    #[expect(dead_code)]
    pub const ADDRESS_OF_MSR_BITMAP: u32 = 0x2004;
    pub const EPT_POINTER: u32 = 0x201A;

    // 64-bit read-only data fields
    #[expect(dead_code)]
    pub const GUEST_PHYSICAL_ADDRESS: u32 = 0x2400;

    // 64-bit guest-state fields
    pub const GUEST_IA32_EFER: u32 = 0x2806;

    // 64-bit host-state fields
    pub const HOST_IA32_EFER: u32 = 0x2C02;

    // 32-bit control fields
    pub const PIN_BASED_VM_EXEC_CONTROL: u32 = 0x4000;
    pub const CPU_BASED_VM_EXEC_CONTROL: u32 = 0x4002;
    pub const EXCEPTION_BITMAP: u32 = 0x4004;
    pub const PAGE_FAULT_ERROR_CODE_MASK: u32 = 0x4006;
    pub const PAGE_FAULT_ERROR_CODE_MATCH: u32 = 0x4008;
    pub const CR3_TARGET_COUNT: u32 = 0x400A;
    pub const EXIT_CONTROLS: u32 = 0x400C;
    pub const ENTRY_CONTROLS: u32 = 0x4012;
    #[expect(dead_code)]
    pub const ENTRY_INTR_INFO: u32 = 0x4016;
    pub const SECONDARY_VM_EXEC_CONTROL: u32 = 0x401E;
    pub const CR0_GUEST_HOST_MASK: u32 = 0x6000;
    pub const CR4_GUEST_HOST_MASK: u32 = 0x6002;
    #[expect(dead_code)]
    pub const CR0_READ_SHADOW: u32 = 0x6004;
    #[expect(dead_code)]
    pub const CR4_READ_SHADOW: u32 = 0x6006;

    // 32-bit read-only data fields
    #[expect(dead_code)]
    pub const VM_INSTRUCTION_ERROR: u32 = 0x4400;
    #[expect(dead_code)]
    pub const VM_EXIT_REASON: u32 = 0x4402;
    #[expect(dead_code)]
    pub const VM_EXIT_INTR_INFO: u32 = 0x4404;
    #[expect(dead_code)]
    pub const EXIT_QUALIFICATION: u32 = 0x6400;

    // 32-bit guest-state fields
    pub const GUEST_ES_LIMIT: u32 = 0x4800;
    pub const GUEST_CS_LIMIT: u32 = 0x4802;
    pub const GUEST_SS_LIMIT: u32 = 0x4804;
    pub const GUEST_DS_LIMIT: u32 = 0x4806;
    pub const GUEST_FS_LIMIT: u32 = 0x4808;
    pub const GUEST_GS_LIMIT: u32 = 0x480A;
    pub const GUEST_LDTR_LIMIT: u32 = 0x480C;
    pub const GUEST_TR_LIMIT: u32 = 0x480E;
    pub const GUEST_GDTR_LIMIT: u32 = 0x4810;
    pub const GUEST_IDTR_LIMIT: u32 = 0x4812;
    pub const GUEST_ES_AR_BYTES: u32 = 0x4814;
    pub const GUEST_CS_AR_BYTES: u32 = 0x4816;
    pub const GUEST_SS_AR_BYTES: u32 = 0x4818;
    pub const GUEST_DS_AR_BYTES: u32 = 0x481A;
    pub const GUEST_FS_AR_BYTES: u32 = 0x481C;
    pub const GUEST_GS_AR_BYTES: u32 = 0x481E;
    pub const GUEST_LDTR_AR_BYTES: u32 = 0x4820;
    pub const GUEST_TR_AR_BYTES: u32 = 0x4822;
    pub const GUEST_INTERRUPTIBILITY_INFO: u32 = 0x4824;
    pub const GUEST_ACTIVITY_STATE: u32 = 0x4826;

    // Natural-width guest-state fields
    pub const GUEST_CR0: u32 = 0x6800;
    pub const GUEST_CR3: u32 = 0x6802;
    pub const GUEST_CR4: u32 = 0x6804;
    pub const GUEST_ES_BASE: u32 = 0x6806;
    pub const GUEST_CS_BASE: u32 = 0x6808;
    pub const GUEST_SS_BASE: u32 = 0x680A;
    pub const GUEST_DS_BASE: u32 = 0x680C;
    pub const GUEST_FS_BASE: u32 = 0x680E;
    pub const GUEST_GS_BASE: u32 = 0x6810;
    pub const GUEST_LDTR_BASE: u32 = 0x6812;
    pub const GUEST_TR_BASE: u32 = 0x6814;
    pub const GUEST_GDTR_BASE: u32 = 0x6816;
    pub const GUEST_IDTR_BASE: u32 = 0x6818;
    pub const GUEST_RSP: u32 = 0x681C;
    pub const GUEST_RIP: u32 = 0x681E;
    pub const GUEST_RFLAGS: u32 = 0x6820;

    // Natural-width host-state fields
    pub const HOST_CR0: u32 = 0x6C00;
    pub const HOST_CR3: u32 = 0x6C02;
    pub const HOST_CR4: u32 = 0x6C04;
    pub const HOST_GDTR_BASE: u32 = 0x6C0C;
    pub const HOST_IDTR_BASE: u32 = 0x6C0E;
    #[expect(dead_code)]
    pub const HOST_RSP: u32 = 0x6C14;
    pub const HOST_RIP: u32 = 0x6C16;
}

/// VM exit reason codes.
pub(crate) mod exit_reason {
    pub const EXCEPTION_OR_NMI: u32 = 0;
    pub const EXTERNAL_INTERRUPT: u32 = 1;
    pub const TRIPLE_FAULT: u32 = 2;
    pub const INTERRUPT_WINDOW: u32 = 7;
    pub const NMI_WINDOW: u32 = 8;
    #[expect(dead_code)]
    pub const TASK_SWITCH: u32 = 9;
    pub const CPUID: u32 = 10;
    pub const HLT: u32 = 12;
    pub const CR_ACCESS: u32 = 28;
    pub const IO_INSTRUCTION: u32 = 30;
    pub const MSR_READ: u32 = 31;
    pub const MSR_WRITE: u32 = 32;
    pub const EPT_VIOLATION: u32 = 48;
    pub const EPT_MISCONFIGURATION: u32 = 49;
}
