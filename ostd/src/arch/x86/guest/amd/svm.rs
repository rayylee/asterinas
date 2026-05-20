// SPDX-License-Identifier: MPL-2.0

//! AMD SVM capability detection and lifecycle management.
#![allow(dead_code)]

use crate::{
    cpu::CpuId,
    mm::{FrameAllocOptions, UFrame, paddr_to_vaddr},
    prelude::*,
    Error,
};
use crate::cpu_local_cell;

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
    (ecx & (1 << 2)) != 0
}

/// Detects and caches AMD SVM capabilities.
pub fn detect_svm_capabilities() -> Result<()> {
    if !is_svm_supported() {
        return Err(Error::InvalidArgs);
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

/// Enters SVM context on the current CPU.
///
/// Enables SVM via EFER.SVME if this is the first use on this CPU.
/// Allocates and sets up the host save area (HSA) via MSR VM_HSAVE_PA.
pub(crate) fn svm_enter() -> Result<()> {
    let prev_count = SVM_REF_COUNT.load();
    if prev_count > 0 {
        SVM_REF_COUNT.add_assign(1);
        return Ok(());
    }

    // First use on this CPU: enable SVM and set up host save area.

    // Enable SVM by setting EFER.SVME
    // SAFETY: We verified SVM support via CPUID.
    let efer = x86_64::registers::model_specific::Efer::read_raw();
    if efer & (1 << 12) == 0 {
        // SAFETY: SVME bit safe to set when SVM is supported.
        unsafe {
            x86_64::registers::model_specific::Efer::write_raw(efer | (1 << 12));
        }
    }

    // Allocate a 4KB frame for the host save area (HSA).
    let hsa_frame = FrameAllocOptions::new()
        .alloc_frame()
        .map_err(|_| Error::NoMemory)?;

    // Zero the HSA (SVM spec requires this).
    let vaddr = paddr_to_vaddr(hsa_frame.paddr());
    // SAFETY: Just allocated, zeroing is safe.
    unsafe {
        core::ptr::write_bytes(vaddr as *mut u8, 0, 4096);
    }

    // Set VM_HSAVE_PA MSR (0xC001_0111) to point to HSA.
    // SAFETY: Valid frame physical address.
    unsafe {
        x86_64::registers::model_specific::Msr::new(0xC001_0111)
            .write(hsa_frame.paddr() as u64);
    }

    SVM_REF_COUNT.add_assign(1);

    let cpu_id: u32 = CpuId::current_racy().into();
    host_save_areas().lock().insert(cpu_id, Arc::new(hsa_frame.into()));

    Ok(())
}

/// Leaves SVM context on the current CPU (if last reference).
pub(crate) fn svm_exit() {
    let prev_count = SVM_REF_COUNT.load();
    assert!(prev_count > 0, "SVM reference count underflow");

    SVM_REF_COUNT.sub_assign(1);

    if SVM_REF_COUNT.load() == 0 {
        // Clear VM_HSAVE_PA MSR.
        // SAFETY: We are the last reference.
        unsafe {
            x86_64::registers::model_specific::Msr::new(0xC001_0111).write(0);
        }

        // Release the HSA frame for this CPU.
        let cpu_id: u32 = CpuId::current_racy().into();
        host_save_areas().lock().remove(&cpu_id);

        // Optionally clear SVME, but leave it set for efficiency.
    }
}
