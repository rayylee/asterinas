// SPDX-License-Identifier: MPL-2.0

//! Architecture-specific guest (virtualization) module for x86_64.
//!
//! Provides hardware-assisted virtualization abstractions for both
//! Intel VT-x (VMX + EPT) and AMD SVM (SVM + NPT).
//!
//! CPU vendor is detected at runtime; the correct implementation is
//! selected automatically.

pub mod amd;
pub(crate) mod context;
pub mod intel;
pub(crate) mod vmexit;

use core::ops::Range;

use crate::mm::{
    PagingLevel,
    page_prop::{CachePolicy, PageFlags, PageProperty},
    vm_space::VmQueriedItem,
};
use crate::prelude::*;
use crate::task::atomic_mode::AsAtomicModeGuard;

// Re-export shared public types
pub use context::{GuestContext, GuestGprSaveArea, GuestSregs};
pub use vmexit::{
    CpuidAccess, EptViolationInfo, FailEntryInfo, GuestExitReason, IoPortAccess, MmioAccess,
    MsrAccess,
};

// Re-export Intel-specific types (still used by kernel for now)
pub use intel::{EptPageFlags, EptPageProperty};

/// Vendor-agnostic page property for guest physical memory mappings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuestPageProperty {
    /// Read/Write/Execute permissions.
    pub flags: GuestPageFlags,
    /// Memory type (6 = WB).
    pub mem_type: u8,
}

bitflags::bitflags! {
    /// Guest page permission flags (vendor-agnostic).
    ///
    /// These flags map to both Intel EPT and AMD NPT permissions.
    pub struct GuestPageFlags: u8 {
        /// Read permission.
        const READ    = 0b001;
        /// Write permission.
        const WRITE   = 0b010;
        /// Execute permission.
        const EXECUTE = 0b100;
        /// Read + Write.
        const RW      = Self::READ.bits() | Self::WRITE.bits();
        /// Read + Write + Execute.
        const RWX     = Self::READ.bits() | Self::WRITE.bits() | Self::EXECUTE.bits();
    }
}

impl Default for GuestPageProperty {
    fn default() -> Self {
        Self {
            flags: GuestPageFlags::RWX,
            mem_type: 6,
        }
    }
}

impl GuestPageProperty {
    fn to_page_property(&self) -> PageProperty {
        let mut flags = PageFlags::empty();
        if self.flags.contains(GuestPageFlags::READ) {
            flags |= PageFlags::R;
        }
        if self.flags.contains(GuestPageFlags::WRITE) {
            flags |= PageFlags::W;
        }
        if self.flags.contains(GuestPageFlags::EXECUTE) {
            flags |= PageFlags::X;
        }
        let cache = match self.mem_type {
            0 => CachePolicy::Uncacheable,
            1 => CachePolicy::WriteCombining,
            4 => CachePolicy::Writethrough,
            5 => CachePolicy::WriteProtected,
            6 => CachePolicy::Writeback,
            _ => CachePolicy::Writeback,
        };
        PageProperty::new_user(flags, cache)
    }
}

/// Vendor-agnostic guest control block.
///
/// Wraps either an Intel VMCS or an AMD VMCB, allowing
/// `GuestMode::new()` to create the appropriate guest mode.
/// Cloning this type just clones the inner `Arc` reference.
#[derive(Clone)]
pub enum GuestControlBlock {
    /// Intel VT-x VMCS.
    Intel(Arc<intel::vmcs::Vmcs>),
    /// AMD SVM VMCB.
    #[allow(dead_code)]
    Amd(Arc<amd::vmcb::Vmcb>),
}

impl GuestControlBlock {
    /// Returns `true` if the guest has been launched at least once.
    pub fn is_launched(&self) -> bool {
        match self {
            GuestControlBlock::Intel(vmcs) => vmcs.is_launched(),
            GuestControlBlock::Amd(vmcb) => vmcb.is_launched(),
        }
    }

    /// Marks the guest as launched after the first successful entry.
    pub fn mark_launched(&self) {
        match self {
            GuestControlBlock::Intel(vmcs) => vmcs.mark_launched(),
            GuestControlBlock::Amd(vmcb) => vmcb.mark_launched(),
        }
    }
}

/// Guest physical address space.
///
/// This is the hypervisor analog of `VmSpace`. It wraps either an Intel EPT
/// page table or an AMD NPT page table depending on the CPU vendor.
pub struct GuestPhysMemSpace {
    inner: GuestPhysMemSpaceInner,
}

enum GuestPhysMemSpaceInner {
    Intel(intel::ept::GuestPhysMemSpace),
    #[allow(dead_code)]
    Amd(amd::npt::GuestPhysMemSpace),
}

impl GuestPhysMemSpace {
    /// Creates a new empty guest physical address space.
    pub fn new() -> Self {
        if is_amd_cpu() {
            Self {
                inner: GuestPhysMemSpaceInner::Amd(amd::npt::GuestPhysMemSpace::new()),
            }
        } else {
            Self {
                inner: GuestPhysMemSpaceInner::Intel(intel::ept::GuestPhysMemSpace::new()),
            }
        }
    }

    /// Returns a mutable cursor for mapping frames into guest physical memory.
    pub fn cursor_mut<'a, G: AsAtomicModeGuard>(
        &'a self,
        guard: &'a G,
        gpa_range: &Range<u64>,
    ) -> Result<GuestCursorMut<'a>> {
        match &self.inner {
            GuestPhysMemSpaceInner::Intel(intel_space) => {
                let cursor = intel_space.cursor_mut(guard, gpa_range)?;
                Ok(GuestCursorMut::Intel(cursor))
            }
            GuestPhysMemSpaceInner::Amd(amd_space) => {
                let cursor = amd_space.cursor_mut(guard, gpa_range)?;
                Ok(GuestCursorMut::Amd(cursor))
            }
        }
    }

    /// Returns the page table pointer value for hardware use.
    ///
    /// For Intel EPT, returns the EPTP value.
    /// For AMD NPT, returns the nCR3 value.
    pub fn eptp(&self) -> u64 {
        match &self.inner {
            GuestPhysMemSpaceInner::Intel(intel_space) => intel_space.eptp(),
            GuestPhysMemSpaceInner::Amd(amd_space) => amd_space.nptp(),
        }
    }
}

impl Default for GuestPhysMemSpace {
    fn default() -> Self {
        Self::new()
    }
}

/// Cursor for mapping frames into guest physical address space.
pub enum GuestCursorMut<'a> {
    /// Intel EPT cursor.
    Intel(intel::ept::GuestCursorMut<'a>),
    /// AMD NPT cursor.
    Amd(amd::npt::GuestCursorMut<'a>),
}

impl GuestCursorMut<'_> {
    /// Maps a host physical frame at the current GPA.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the physical address is valid and
    /// mapping it into the guest page tables does not violate isolation.
    pub unsafe fn map(&mut self, paddr: Paddr, level: PagingLevel, prop: GuestPageProperty) {
        let page_prop = prop.to_page_property();
        match self {
            GuestCursorMut::Intel(cursor) => {
                // SAFETY: Caller guarantees address validity.
                unsafe { cursor.map(paddr, level, page_prop) };
            }
            GuestCursorMut::Amd(cursor) => {
                // SAFETY: Caller guarantees address validity.
                unsafe { cursor.map(paddr, level, page_prop) };
            }
        }
    }

    /// Maps a typed frame into the guest page tables at the current GPA.
    pub fn map_frame(
        &mut self,
        frame: &impl HasPaddr,
        level: PagingLevel,
        prop: GuestPageProperty,
    ) {
        let page_prop = prop.to_page_property();
        match self {
            GuestCursorMut::Intel(cursor) => cursor.map_frame(frame, level, page_prop),
            GuestCursorMut::Amd(cursor) => cursor.map_frame(frame, level, page_prop),
        }
    }

    /// Maps a zero page as a placeholder at the current GPA.
    pub fn map_zero(&mut self, level: PagingLevel, prop: GuestPageProperty) {
        let page_prop = prop.to_page_property();
        match self {
            GuestCursorMut::Intel(cursor) => cursor.map_zero(level, page_prop),
            GuestCursorMut::Amd(cursor) => cursor.map_zero(level, page_prop),
        }
    }

    /// Maps an item from a VmSpace query result into the guest page tables.
    pub fn map_vm_item(&mut self, item: &VmQueriedItem<'_>, level: PagingLevel, prop: GuestPageProperty) {
        let page_prop = prop.to_page_property();
        match self {
            GuestCursorMut::Intel(cursor) => cursor.map_vm_item(item, level, page_prop),
            GuestCursorMut::Amd(cursor) => cursor.map_vm_item(item, level, page_prop),
        }
    }

    /// Moves the cursor forward to the next page-sized GPA.
    pub fn find_next(&mut self, len: usize) -> Option<u64> {
        match self {
            GuestCursorMut::Intel(cursor) => cursor.find_next(len),
            GuestCursorMut::Amd(cursor) => cursor.find_next(len),
        }
    }
}

/// Detects if the current CPU is AMD.
pub fn is_amd_cpu() -> bool {
    let result = crate::arch::cpu::cpuid::cpuid(0x0, 0x0);
    if let Some(r) = result {
        // CPUID leaf 0 returns vendor string in EBX:ECX:EDX
        // "AuthenticAMD" = EBX=0x68747541, ECX=0x444D4163, EDX=0x69746E65
        r.ebx == 0x68747541 && r.ecx == 0x444D4163 && r.edx == 0x69746E65
    } else {
        false
    }
}

/// Returns true if Intel VMX is supported on this CPU.
pub fn is_vmx_supported() -> bool {
    intel::vmx::is_vmx_supported()
}

/// Returns true if AMD SVM is supported on this CPU.
pub fn is_svm_supported() -> bool {
    amd::svm::is_svm_supported()
}

/// Detects and caches Intel VMX capabilities.
pub fn detect_vmx_capabilities() -> Result<()> {
    intel::vmx::detect_vmx_capabilities().map(|_| ())
}

/// Detects and caches AMD SVM capabilities.
pub fn detect_svm_capabilities() -> Result<()> {
    amd::svm::detect_svm_capabilities()
}
