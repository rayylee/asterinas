// SPDX-License-Identifier: MPL-2.0

//! AMD SVM capability detection and lifecycle management.
#![allow(dead_code)]

use crate::{
    Error,
    cpu::CpuId,
    cpu_local_cell,
    mm::{FrameAllocOptions, UFrame, paddr_to_vaddr},
    prelude::*,
};

// Per-CPU SVM reference count and host save area storage.
cpu_local_cell! {
    /// Reference count of active guest runs on this CPU.
    static SVM_REF_COUNT: u32 = 0;
}

fn host_save_areas() -> &'static spin::Mutex<alloc::collections::BTreeMap<u32, Arc<UFrame>>> {
    static FRAMES: spin::Once<spin::Mutex<alloc::collections::BTreeMap<u32, Arc<UFrame>>>> =
        spin::Once::new();
    FRAMES.call_once(|| spin::Mutex::new(alloc::collections::BTreeMap::new()));
    FRAMES.get().unwrap()
}

/// SVM capabilities, cached on boot.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SvmCapabilities {
    /// SVM revision and features from CPUID 0x8000_000A.
    pub svm_rev: u32,
    pub nasid: u32,
    /// Features from EAX of CPUID 0x8000_000A.
    pub features: u32,
}

static SVM_CAPS: spin::Once<SvmCapabilities> = spin::Once::new();

/// Checks if AMD SVM is supported on this CPU.
pub(crate) fn is_svm_supported() -> bool {
    let result = crate::arch::cpu::cpuid::cpuid(0x8000_0001, 0x0);
    let ecx = result.map(|r| r.ecx).unwrap_or(0);
    if (ecx & (1 << 2)) == 0 {
        return false;
    }

    // Probe EFER.SVME writeability by trying to write EFER with SVME set.
    // If the write succeeds (or SVME was already set), SVM is usable.
    // If it causes #GP, SVM is locked by the BIOS/hypervisor.
    let current_efer = x86_64::registers::model_specific::Efer::read_raw();
    if current_efer & (1 << 12) != 0 {
        // SVME already set, SVM is available.
        return true;
    }

    // Try to set SVME bit. Use the safe MSR probe to avoid #GP crash.
    super::super::msr_probe::try_wrmsr(0xC0000080, current_efer | (1 << 12)).is_ok()
}

/// Detects and caches AMD SVM capabilities.
pub fn detect_svm_capabilities() -> Result<()> {
    if !is_svm_supported() {
        return Err(Error::AccessDenied);
    }

    let Some(result) = crate::arch::cpu::cpuid::cpuid(0x8000_000A, 0x0) else {
        return Err(Error::InvalidArgs);
    };

    let caps = SvmCapabilities {
        svm_rev: result.eax & 0xFF,
        nasid: (result.eax >> 8) & 0xFF,
        features: result.edx,
    };

    SVM_CAPS.call_once(|| caps);
    Ok(())
}

/// Returns cached SVM capabilities.
pub(crate) fn svm_capabilities() -> &'static SvmCapabilities {
    SVM_CAPS.get().expect("SVM capabilities not detected yet")
}

/// Checks whether we are running under a hypervisor (nested virtualization).
///
/// Uses CPUID leaf 1, ECX bit 31 (the "hypervisor present" bit).
/// When set, writes to VM_HSAVE_PA must be skipped because the outer hypervisor
/// manages the host save area and will intercept our VMRUN instruction.
fn is_running_under_hypervisor() -> bool {
    let Some(result) = crate::arch::cpu::cpuid::cpuid(0x1, 0x0) else {
        return false;
    };
    (result.ecx & (1 << 31)) != 0
}

/// Enters SVM context on the current CPU.
///
/// Enables SVM via EFER.SVME if this is the first use on this CPU.
/// Allocates and sets up the host save area (HSA) via MSR VM_HSAVE_PA.
///
/// In nested virtualization (running under KVM), the outer hypervisor
/// has already enabled SVME and manages the host save area itself.
/// We skip the VM_HSAVE_PA write in that case.
pub(crate) fn svm_enter() -> Result<()> {
    println!("KVM: svm_enter - start");
    let prev_count = SVM_REF_COUNT.load();
    if prev_count > 0 {
        SVM_REF_COUNT.add_assign(1);
        return Ok(());
    }

    let efer = x86_64::registers::model_specific::Efer::read_raw();
    let svme_was_set = (efer & (1 << 12)) != 0;
    let under_hypervisor = is_running_under_hypervisor();
    println!(
        "KVM: svm_enter - EFER={:#x}, svme={}, hypervisor={}",
        efer, svme_was_set, under_hypervisor
    );

    if under_hypervisor {
        // Running nested: the outer hypervisor (e.g. KVM) manages SVM
        // and intercepts our VMRUN. We do NOT need to write VM_HSAVE_PA
        // because the outer hypervisor handles host save/restore.
        // SVME is expected to already be set by the outer hypervisor.
        if !svme_was_set {
            println!("KVM: svm_enter - SVME not set under hypervisor; enabling");
            super::super::msr_probe::try_wrmsr(0xC0000080, efer | (1 << 12)).map_err(|_| {
                println!("KVM: svm_enter - EFER.SVME write failed under hypervisor");
                Error::AccessDenied
            })?;
        }
        println!("KVM: svm_enter - nested mode, skipping HSA setup");
        SVM_REF_COUNT.add_assign(1);
        return Ok(());
    }

    // Bare-metal path (not nested):

    // Enable SVM by setting EFER.SVME if not already set.
    if !svme_was_set {
        super::super::msr_probe::try_wrmsr(0xC0000080, efer | (1 << 12)).map_err(|_| {
            println!("KVM: svm_enter - EFER.SVME write failed (SVM locked)");
            Error::AccessDenied
        })?;
    }

    // Check if VM_HSAVE_PA already has a valid value (e.g., set by BIOS).
    let hsa_paddr = match super::super::msr_probe::try_rdmsr(0xC001_0111) {
        Ok(val) if val != 0 => {
            println!(
                "KVM: svm_enter - VM_HSAVE_PA already set to {:#x}, skipping write",
                val
            );
            SVM_REF_COUNT.add_assign(1);
            return Ok(());
        }
        _ => {
            println!("KVM: svm_enter - VM_HSAVE_PA not set, allocating HSA frame");
            let hsa_frame = FrameAllocOptions::new()
                .alloc_frame()
                .map_err(|_| Error::NoMemory)?;
            println!("KVM: svm_enter - HSA frame paddr={:#x}", hsa_frame.paddr());

            // Zero the HSA (SVM spec requires this).
            let vaddr = paddr_to_vaddr(hsa_frame.paddr());
            // SAFETY: Just allocated, zeroing is safe.
            unsafe {
                core::ptr::write_bytes(vaddr as *mut u8, 0, 4096);
            }

            let paddr = hsa_frame.paddr();

            // AMD requires VM_HSAVE_PA to be written only when SVM is disabled.
            // If SVME was already set (e.g., by BIOS), temporarily clear it.
            if svme_was_set {
                super::super::msr_probe::try_wrmsr(0xC0000080, efer & !(1 << 12)).map_err(
                    |_| {
                        println!("KVM: svm_enter - EFER.SVME clear failed");
                        Error::AccessDenied
                    },
                )?;
            }

            super::super::msr_probe::try_wrmsr(0xC001_0111, paddr as u64).map_err(|_| {
                println!("KVM: svm_enter - VM_HSAVE_PA write failed");
                Error::AccessDenied
            })?;

            if svme_was_set {
                super::super::msr_probe::try_wrmsr(0xC0000080, efer).map_err(|_| {
                    println!("KVM: svm_enter - EFER.SVME restore failed");
                    Error::AccessDenied
                })?;
            }

            let cpu_id: u32 = CpuId::current_racy().into();
            host_save_areas()
                .lock()
                .insert(cpu_id, Arc::new(hsa_frame.into()));

            paddr
        }
    };

    SVM_REF_COUNT.add_assign(1);

    println!("KVM: svm_enter - done, HSA at {:#x}", hsa_paddr);
    Ok(())
}

/// Leaves SVM context on the current CPU (if last reference).
pub(crate) fn svm_exit() {
    let prev_count = SVM_REF_COUNT.load();
    assert!(prev_count > 0, "SVM reference count underflow");

    SVM_REF_COUNT.sub_assign(1);

    if SVM_REF_COUNT.load() == 0 {
        // In nested mode, we never set up HSA or host_save_areas, so skip cleanup.
        if is_running_under_hypervisor() {
            return;
        }

        // Clear VM_HSAVE_PA MSR.
        let current_efer = x86_64::registers::model_specific::Efer::read_raw();
        let svme_was_set = (current_efer & (1 << 12)) != 0;
        if svme_was_set {
            let _ = super::super::msr_probe::try_wrmsr(0xC0000080, current_efer & !(1 << 12));
        }
        // SAFETY: SVM is now disabled.
        unsafe {
            x86_64::registers::model_specific::Msr::new(0xC001_0111).write(0);
        }
        if svme_was_set {
            let _ = super::super::msr_probe::try_wrmsr(0xC0000080, current_efer);
        }

        // Release the HSA frame for this CPU.
        let cpu_id: u32 = CpuId::current_racy().into();
        host_save_areas().lock().remove(&cpu_id);
    }
}
