// SPDX-License-Identifier: MPL-2.0

//! VMCS (Virtual Machine Control Structure) management.
//!
//! Each vCPU has one VMCS. The VMCS is a 4KB-aligned region of memory
//! that holds all VMX configuration and state.

use core::sync::atomic::{AtomicU32, Ordering};

use super::vmx::{
    VmxResult, adjust_vmx_control, vmclear, vmcs_field, vmptrld, vmwrite, vmx_capabilities,
};
use crate::{
    Error,
    cpu::CpuId,
    mm::{FrameAllocOptions, UFrame, paddr_to_vaddr},
    prelude::*,
};

/// A VMCS (Virtual Machine Control Structure).
///
/// Each vCPU owns one VMCS. The VMCS holds all VMX configuration,
/// host state, guest state, and control fields.
pub struct Vmcs {
    /// The 4KB frame that holds the VMCS region.
    frame: UFrame,
    /// The CPU ID where this VMCS was last loaded (for migration tracking).
    /// `u32::MAX` means not loaded on any CPU.
    loaded_cpu: AtomicU32,
    /// Whether this VMCS has been launched (VMLAUNCH vs VMRESUME).
    launched: AtomicU32,
}

impl Vmcs {
    /// Allocates a new VMCS.
    pub fn new() -> Result<Self> {
        let frame = FrameAllocOptions::new()
            .alloc_frame()
            .map_err(|_| Error::NoMemory)?;

        // Write VMCS revision ID at byte 0-3
        let revision_id = vmx_capabilities().vmcs_revision_id;
        let vaddr = paddr_to_vaddr(frame.paddr());
        // SAFETY: We just allocated this frame. Writing the revision ID
        // is required by the VMX specification before VMPTRLD.
        unsafe {
            core::ptr::write_volatile(vaddr as *mut u32, revision_id);
        }

        Ok(Self {
            frame: frame.into(),
            loaded_cpu: AtomicU32::new(u32::MAX),
            launched: AtomicU32::new(0),
        })
    }

    /// Returns the physical address of the VMCS region.
    pub fn paddr(&self) -> Paddr {
        self.frame.paddr()
    }

    /// Returns whether this VMCS has been launched (VMLAUNCH done).
    pub fn is_launched(&self) -> bool {
        self.launched.load(Ordering::Acquire) != 0
    }

    /// Marks this VMCS as launched after the first successful VMLAUNCH.
    pub fn mark_launched(&self) {
        self.launched.store(1, Ordering::Release);
    }

    /// Loads this VMCS on the current CPU via VMPTRLD.
    ///
    /// If the VMCS was previously loaded on a different CPU, performs
    /// VMCLEAR on the old CPU first.
    ///
    /// # Safety
    ///
    /// The caller must ensure VMX root mode is active on the current CPU.
    pub unsafe fn load_on_current_cpu(&self) -> Result<()> {
        let current_cpu: u32 = CpuId::current_racy().into();
        let prev_cpu = self.loaded_cpu.load(Ordering::Acquire);
        println!(
            "KVM: load_on_current_cpu - current={}, prev={}, paddr={:#x}",
            current_cpu,
            prev_cpu,
            self.paddr()
        );

        if prev_cpu == current_cpu {
            return Ok(());
        }

        // VMCLEAR on old CPU if it was loaded elsewhere
        if prev_cpu != u32::MAX {
            // SAFETY: The VMCS was loaded on the previous CPU.
            let result = unsafe { vmclear(self.paddr()) };
            if result != VmxResult::Ok {
                println!("KVM: load_on_current_cpu - vmclear FAILED");
                return Err(Error::IoError);
            }
        }

        // SAFETY: The VMCS region is properly initialized, and we are in VMX root mode.
        let result = unsafe { vmptrld(self.paddr()) };
        if result != VmxResult::Ok {
            println!(
                "KVM: load_on_current_cpu - vmptrld FAILED, result={:?}",
                result
            );
            return Err(Error::IoError);
        }

        println!("KVM: load_on_current_cpu - vmptrld OK");
        self.loaded_cpu.store(current_cpu, Ordering::Release);
        Ok(())
    }

    /// Clears this VMCS from any CPU it was loaded on.
    ///
    /// # Safety
    ///
    /// The caller must ensure VMX root mode is active on the current CPU
    /// if the VMCS was previously loaded on this CPU.
    pub unsafe fn clear(&self) {
        let prev_cpu = self.loaded_cpu.swap(u32::MAX, Ordering::AcqRel);
        if prev_cpu != u32::MAX {
            // SAFETY: The caller ensures VMX root mode is active on the current CPU
            // if this VMCS was loaded here. VMCLEAR releases the VMCS from the CPU.
            let _ = unsafe { vmclear(self.paddr()) };
        }
    }

    /// Initializes all VMCS fields for guest execution.
    ///
    /// # Safety
    ///
    /// The caller must ensure this VMCS is loaded on the current CPU.
    pub unsafe fn initialize(&self, eptp: u64) -> Result<()> {
        println!("KVM: vmcs.initialize - starting, eptp={:#x}", eptp);
        let caps = vmx_capabilities();

        // SAFETY: VMCS is loaded on the current CPU.
        println!("KVM: vmcs.initialize - calling init_host_state");
        unsafe {
            self.init_host_state()?;
        }
        println!("KVM: vmcs.initialize - calling init_controls");
        unsafe {
            self.init_controls(caps)?;
        }
        println!("KVM: vmcs.initialize - calling init_guest_state");
        unsafe {
            self.init_guest_state()?;
        }

        // SAFETY: VMCS is loaded on current CPU.
        unsafe {
            vmwrite(vmcs_field::EPT_POINTER, eptp);
        }
        println!("KVM: vmcs.initialize - done");

        Ok(())
    }

    /// Initializes host state fields in the VMCS.
    ///
    /// # Safety
    ///
    /// VMCS must be loaded on current CPU.
    unsafe fn init_host_state(&self) -> Result<()> {
        use x86_64::registers::{
            control::{Cr0, Cr3, Cr4},
            segmentation::{CS, DS, ES, FS, GS, SS, Segment},
        };

        // Host CR0, CR3, CR4
        let cr0 = Cr0::read_raw();
        let cr3 = Cr3::read_raw().0.start_address().as_u64();
        let cr4 = Cr4::read_raw();

        // Host EFER
        // SAFETY: Reading EFER MSR is safe in kernel mode.
        let efer = x86_64::registers::model_specific::Efer::read_raw();

        // Host segment selectors
        let cs = CS::get_reg();
        let ss = SS::get_reg();
        let ds = DS::get_reg();
        let es = ES::get_reg();
        let fs = FS::get_reg();
        let gs = GS::get_reg();
        let tr: u64;
        // SAFETY: The STR instruction reads the Task Register selector.
        unsafe {
            core::arch::asm!("str {}", out(reg) tr);
        }

        // Host GDTR/IDTR base - read using inline asm
        // sgdt/sidt store a 10-byte descriptor: 2 bytes limit + 8 bytes base
        let mut gdt_desc: [u8; 10] = [0; 10];
        let mut idt_desc: [u8; 10] = [0; 10];
        // SAFETY: sgdt/sidt are non-destructive instructions that write to memory.
        unsafe {
            core::arch::asm!("sgdt [{}]", in(reg) gdt_desc.as_mut_ptr());
            core::arch::asm!("sidt [{}]", in(reg) idt_desc.as_mut_ptr());
        }
        let gdt_base = u64::from(gdt_desc[2])
            | (u64::from(gdt_desc[3]) << 8)
            | (u64::from(gdt_desc[4]) << 16)
            | (u64::from(gdt_desc[5]) << 24)
            | (u64::from(gdt_desc[6]) << 32)
            | (u64::from(gdt_desc[7]) << 40)
            | (u64::from(gdt_desc[8]) << 48)
            | (u64::from(gdt_desc[9]) << 56);
        let idt_base = u64::from(idt_desc[2])
            | (u64::from(idt_desc[3]) << 8)
            | (u64::from(idt_desc[4]) << 16)
            | (u64::from(idt_desc[5]) << 24)
            | (u64::from(idt_desc[6]) << 32)
            | (u64::from(idt_desc[7]) << 40)
            | (u64::from(idt_desc[8]) << 48)
            | (u64::from(idt_desc[9]) << 56);

        // SAFETY: VMCS is loaded on the current CPU.
        unsafe {
            vmwrite(vmcs_field::HOST_CR0, cr0);
            vmwrite(vmcs_field::HOST_CR3, cr3);
            vmwrite(vmcs_field::HOST_CR4, cr4);
            vmwrite(vmcs_field::HOST_IA32_EFER, efer);
            vmwrite(vmcs_field::HOST_ES_SELECTOR, es.0 as u64);
            vmwrite(vmcs_field::HOST_CS_SELECTOR, cs.0 as u64);
            vmwrite(vmcs_field::HOST_SS_SELECTOR, ss.0 as u64);
            vmwrite(vmcs_field::HOST_DS_SELECTOR, ds.0 as u64);
            vmwrite(vmcs_field::HOST_FS_SELECTOR, fs.0 as u64);
            vmwrite(vmcs_field::HOST_GS_SELECTOR, gs.0 as u64);
            vmwrite(vmcs_field::HOST_TR_SELECTOR, tr);
            vmwrite(vmcs_field::HOST_GDTR_BASE, gdt_base);
            vmwrite(vmcs_field::HOST_IDTR_BASE, idt_base);
        }

        Ok(())
    }

    /// Initializes execution control fields in the VMCS.
    ///
    /// # Safety
    ///
    /// VMCS must be loaded on current CPU.
    unsafe fn init_controls(&self, caps: &super::vmx::VmxCapabilities) -> Result<()> {
        // Pin-based VM-execution controls
        let pin_ctrls = adjust_vmx_control(
            (1 << 0) // External interrupt exiting
            | (1 << 1) // NMI exiting
            | (1 << 5), // Virtual NMIs
            caps.pin_based_ctrls.0,
            caps.pin_based_ctrls.1,
        );

        // Primary processor-based VM-execution controls
        let primary_ctrls = adjust_vmx_control(
            (1 << 2)   // Interrupt window exiting
            | (1 << 3) // HLT exiting
            | (1 << 6) // INVLPG exiting
            | (1 << 7) // MWAIT exiting
            | (1 << 9) // RDPMC exiting
            | (1 << 10) // RDTSC exiting
            | (1 << 15) // Use MSR bitmaps
            | (1 << 17) // MOV-DR exiting
            | (1 << 19) // Use I/O bitmaps
            | (1 << 21) // Use MSR bitmaps
            | (1 << 25) // PAUSE exiting
            | (1 << 26), // Secondary controls enabled
            caps.primary_proc_ctrls.0,
            caps.primary_proc_ctrls.1,
        );

        // Secondary processor-based VM-execution controls
        let secondary_ctrls = adjust_vmx_control(
            (1 << 0)   // Virtualize APIC accesses
            | (1 << 1) // EPT enabled
            | (1 << 3) // Enable RDTSCP
            | (1 << 7), // Enable VPID
            caps.secondary_proc_ctrls.0,
            caps.secondary_proc_ctrls.1,
        );

        // VM-exit controls
        let exit_ctrls = adjust_vmx_control(
            (1 << 0)   // Save debug controls
            | (1 << 2) // Host address-space size (IA-32e mode)
            | (1 << 12) // Save IA32_EFER
            | (1 << 15) // Load IA32_EFER
            | (1 << 18), // Save VMX preemption timer
            caps.exit_ctrls.0,
            caps.exit_ctrls.1,
        );

        // VM-entry controls
        let entry_ctrls = adjust_vmx_control(
            (1 << 2)   // IA-32e mode guest
            | (1 << 15), // Load IA32_EFER
            caps.entry_ctrls.0,
            caps.entry_ctrls.1,
        );

        // SAFETY: VMCS is loaded on the current CPU.
        unsafe {
            vmwrite(vmcs_field::PIN_BASED_VM_EXEC_CONTROL, pin_ctrls as u64);
            vmwrite(vmcs_field::CPU_BASED_VM_EXEC_CONTROL, primary_ctrls as u64);
            vmwrite(
                vmcs_field::SECONDARY_VM_EXEC_CONTROL,
                secondary_ctrls as u64,
            );
            vmwrite(vmcs_field::EXIT_CONTROLS, exit_ctrls as u64);
            vmwrite(vmcs_field::ENTRY_CONTROLS, entry_ctrls as u64);
            vmwrite(
                vmcs_field::EXCEPTION_BITMAP,
                (1u64 << 1) | (1u64 << 3) | (1u64 << 14),
            );
            vmwrite(vmcs_field::PAGE_FAULT_ERROR_CODE_MASK, 0);
            vmwrite(vmcs_field::PAGE_FAULT_ERROR_CODE_MATCH, 0);
            vmwrite(vmcs_field::CR0_GUEST_HOST_MASK, 0);
            vmwrite(vmcs_field::CR4_GUEST_HOST_MASK, 0);
            vmwrite(vmcs_field::CR3_TARGET_COUNT, 0);
        }

        Ok(())
    }

    /// Initializes guest state fields in the VMCS to a minimal state.
    ///
    /// # Safety
    ///
    /// VMCS must be loaded on current CPU.
    unsafe fn init_guest_state(&self) -> Result<()> {
        // Guest CR0: PE + NE + WP + PG + MP + ET
        let cr0 = (1 << 0) | (1 << 2) | (1 << 5) | (1 << 16) | (1 << 18) | (1 << 29) | (1 << 30);

        // Guest CR4: PAE + OSFXSR + OSXMMEXCPT + OSXSAVE + VME
        let cr4 = (1 << 0) | (1 << 4) | (1 << 7) | (1 << 9) | (1 << 10);

        // Guest EFER: LME + LMA + NXE
        let efer = (1 << 0) | (1 << 8) | (1 << 10);

        // SAFETY: VMCS is loaded on the current CPU.
        unsafe {
            vmwrite(vmcs_field::GUEST_CR0, cr0);
            vmwrite(vmcs_field::GUEST_CR3, 0);
            vmwrite(vmcs_field::GUEST_CR4, cr4);
            vmwrite(vmcs_field::GUEST_IA32_EFER, efer);
            vmwrite(vmcs_field::GUEST_CS_SELECTOR, 0x08);
            vmwrite(vmcs_field::GUEST_CS_LIMIT, 0xFFFFFFFF);
            vmwrite(vmcs_field::GUEST_CS_AR_BYTES, 0xA09B);
            vmwrite(vmcs_field::GUEST_CS_BASE, 0);

            // Guest DS/ES/SS/FS/GS: data segments
            for (sel, limit_f, ar_f, base_f) in [
                (
                    vmcs_field::GUEST_DS_SELECTOR,
                    vmcs_field::GUEST_DS_LIMIT,
                    vmcs_field::GUEST_DS_AR_BYTES,
                    vmcs_field::GUEST_DS_BASE,
                ),
                (
                    vmcs_field::GUEST_ES_SELECTOR,
                    vmcs_field::GUEST_ES_LIMIT,
                    vmcs_field::GUEST_ES_AR_BYTES,
                    vmcs_field::GUEST_ES_BASE,
                ),
                (
                    vmcs_field::GUEST_SS_SELECTOR,
                    vmcs_field::GUEST_SS_LIMIT,
                    vmcs_field::GUEST_SS_AR_BYTES,
                    vmcs_field::GUEST_SS_BASE,
                ),
                (
                    vmcs_field::GUEST_FS_SELECTOR,
                    vmcs_field::GUEST_FS_LIMIT,
                    vmcs_field::GUEST_FS_AR_BYTES,
                    vmcs_field::GUEST_FS_BASE,
                ),
                (
                    vmcs_field::GUEST_GS_SELECTOR,
                    vmcs_field::GUEST_GS_LIMIT,
                    vmcs_field::GUEST_GS_AR_BYTES,
                    vmcs_field::GUEST_GS_BASE,
                ),
            ] {
                vmwrite(sel, 0x10);
                vmwrite(limit_f, 0xFFFFFFFF);
                vmwrite(ar_f, 0xA093);
                vmwrite(base_f, 0);
            }

            vmwrite(vmcs_field::GUEST_TR_SELECTOR, 0x28);
            vmwrite(vmcs_field::GUEST_TR_LIMIT, 0x67);
            vmwrite(vmcs_field::GUEST_TR_AR_BYTES, 0x008B);
            vmwrite(vmcs_field::GUEST_TR_BASE, 0);
            vmwrite(vmcs_field::GUEST_LDTR_SELECTOR, 0);
            vmwrite(vmcs_field::GUEST_LDTR_LIMIT, 0xFFFF);
            vmwrite(vmcs_field::GUEST_LDTR_AR_BYTES, 0x10000);
            vmwrite(vmcs_field::GUEST_LDTR_BASE, 0);
            vmwrite(vmcs_field::GUEST_GDTR_LIMIT, 0);
            vmwrite(vmcs_field::GUEST_GDTR_BASE, 0);
            vmwrite(vmcs_field::GUEST_IDTR_LIMIT, 0);
            vmwrite(vmcs_field::GUEST_IDTR_BASE, 0);
            vmwrite(vmcs_field::GUEST_RFLAGS, (1 << 1) | (1 << 9));
            vmwrite(vmcs_field::GUEST_ACTIVITY_STATE, 0);
            vmwrite(vmcs_field::GUEST_INTERRUPTIBILITY_INFO, 0);
        }

        Ok(())
    }
}

impl Drop for Vmcs {
    fn drop(&mut self) {
        // If the VMCS is still loaded on a CPU when dropped, this is a logic error.
        // The VMCS should have been cleared via GuestMode::drop() before reaching here.
        // We cannot call VMCLEAR here because we may not be in VMX root mode.
        let prev_cpu = self.loaded_cpu.load(Ordering::Acquire);
        if prev_cpu != u32::MAX {
            crate::warn!(
                "Vmcs dropped while still loaded on CPU {} (possible resource leak)",
                prev_cpu
            );
        }
    }
}
