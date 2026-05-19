// SPDX-License-Identifier: MPL-2.0

//! Extended Page Table (EPT) implementation.
//!
//! EPT provides a second level of address translation that maps guest
//! physical addresses (GPAs) to host physical addresses (HPAs). This
//! is the foundation of memory isolation for virtual machines.

use core::marker::PhantomData;
use core::ops::Range;

use bitflags::bitflags;

use crate::prelude::Result;
use crate::mm::{
    HasPaddr, Paddr, PagingConstsTrait, PagingLevel, PodOnce, Vaddr,
    page_prop::{CachePolicy, PageFlags, PageProperty, PageTableFlags, PrivilegedPageFlags as PrivFlags},
    page_table::{PageTable, PageTableConfig, PteScalar, PteTrait, CursorMut},
    vm_space::VmQueriedItem,
};
use crate::task::atomic_mode::AsAtomicModeGuard;

/// EPT paging constants.
///
/// EPT uses 4 levels of page tables (PML4 -> PDPT -> PD -> PT),
/// mapping a 48-bit guest physical address space.
#[derive(Clone, Debug, Default)]
pub(crate) struct EptPagingConsts {}

impl PagingConstsTrait for EptPagingConsts {
    const BASE_PAGE_SIZE: usize = 4096;
    const NR_LEVELS: PagingLevel = 4;
    const ADDRESS_WIDTH: usize = 48;
    /// EPT addresses are not sign-extended (unlike regular x86-64 virtual addresses).
    const VA_SIGN_EXT: bool = false;
    /// Support 2MB huge pages at level 2.
    const HIGHEST_TRANSLATION_LEVEL: PagingLevel = 2;
    const PTE_SIZE: usize = size_of::<EptPageTableEntry>();
}

bitflags! {
    /// EPT PTE flags.
    ///
    /// The EPT PTE format differs from regular page table entries:
    /// - bits[0:2] = R/W/X permissions (at least one must be set for a valid entry)
    /// - bits[5:3] = Memory type (0=UC, 1=WC, 4=WT, 5=WP, 6=WB)
    /// - bits[6] = Ignore PAT
    /// - bits[7] = Page size (huge page)
    /// - bits[8] = Accessed
    /// - bits[9] = Dirty
    /// - bits[10] = Execute-only (if supported)
    /// - bits[12:N] = Physical address
    #[repr(C)]
    #[derive(Pod)]
    pub(crate) struct EptPteFlags: u64 {
        /// Read permission.
        const READ       = 1 << 0;
        /// Write permission.
        const WRITE      = 1 << 1;
        /// Execute permission.
        const EXECUTE    = 1 << 2;
        /// Accessed flag.
        const ACCESSED   = 1 << 8;
        /// Dirty flag.
        const DIRTY      = 1 << 9;
        /// Execute-only (if VMX supports it).
        const EXEC_ONLY  = 1 << 10;
        /// Page size (huge page at level 2 or 3).
        const HUGE       = 1 << 7;
        /// Ignored by hardware, free for software use.
        const AVAIL1     = 1 << 52;
        /// Ignored by hardware.
        const AVAIL2     = 1 << 53;
    }
}

/// EPT page table entry (8 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod)]
pub(crate) struct EptPageTableEntry(u64);

impl EptPageTableEntry {
    /// Physical address mask for EPT entries (bits 12:N).
    const PHYS_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

    /// Physical address mask for 2MB huge pages (bits 21:N).
    const PHYS_ADDR_MASK_2M: u64 = 0x000F_FFFF_FFC0_0000;

    /// Physical address mask for 1GB huge pages (bits 30:N).
    const PHYS_ADDR_MASK_1G: u64 = 0x000F_FFFF_FC00_0000;

    fn pa_mask_at_level(level: PagingLevel) -> u64 {
        match level {
            1 => Self::PHYS_ADDR_MASK,
            2 => Self::PHYS_ADDR_MASK_2M,
            3 => Self::PHYS_ADDR_MASK_1G,
            _ => Self::PHYS_ADDR_MASK,
        }
    }

    fn is_present(&self) -> bool {
        // An EPT entry is present if at least one of R/W/X is set
        self.0 & (EptPteFlags::READ | EptPteFlags::WRITE | EptPteFlags::EXECUTE).bits() != 0
    }

    fn is_huge(&self) -> bool {
        self.0 & EptPteFlags::HUGE.bits() != 0
    }

    fn is_last(&self, level: PagingLevel) -> bool {
        // Level 1 is always a leaf. Higher levels are leaf if HUGE is set.
        level == 1 || self.is_huge()
    }

    fn prop(&self) -> PageProperty {
        let mut flags_val = 0u8;
        if self.0 & EptPteFlags::READ.bits() != 0 {
            flags_val |= PageFlags::R.bits();
        }
        if self.0 & EptPteFlags::WRITE.bits() != 0 {
            flags_val |= PageFlags::W.bits();
        }
        if self.0 & EptPteFlags::EXECUTE.bits() != 0 {
            flags_val |= PageFlags::X.bits();
        }
        if self.0 & EptPteFlags::AVAIL2.bits() != 0 {
            flags_val |= PageFlags::AVAIL2.bits();
        }

        let mut priv_val = 0u8;
        if self.0 & EptPteFlags::AVAIL1.bits() != 0 {
            priv_val |= PrivFlags::AVAIL1.bits();
        }

        // Memory type from bits[5:3]
        let mem_type = ((self.0 >> 3) & 0x7) as u8;
        let cache = match mem_type {
            0 => CachePolicy::Uncacheable,
            1 => CachePolicy::WriteCombining,
            4 => CachePolicy::Writethrough,
            5 => CachePolicy::WriteProtected,
            6 => CachePolicy::Writeback,
            _ => CachePolicy::Writeback,
        };

        PageProperty {
            flags: PageFlags::from_bits(flags_val).unwrap_or(PageFlags::RWX),
            cache,
            priv_flags: PrivFlags::from_bits(priv_val).unwrap_or(PrivFlags::empty()),
        }
    }

    fn pt_flags(&self) -> PageTableFlags {
        let mut bits = 0u8;
        if self.0 & EptPteFlags::AVAIL1.bits() != 0 {
            bits |= PageTableFlags::AVAIL1.bits();
        }
        if self.0 & EptPteFlags::AVAIL2.bits() != 0 {
            bits |= PageTableFlags::AVAIL2.bits();
        }
        PageTableFlags::from_bits(bits).unwrap_or(PageTableFlags::empty())
    }

    fn new_page(paddr: Paddr, level: PagingLevel, prop: PageProperty) -> Self {
        let pa_mask = Self::pa_mask_at_level(level);
        let mut flags = EptPteFlags::empty().bits();

        // Permissions
        if prop.flags.contains(PageFlags::R) {
            flags |= EptPteFlags::READ.bits();
        }
        if prop.flags.contains(PageFlags::W) {
            flags |= EptPteFlags::WRITE.bits();
        }
        if prop.flags.contains(PageFlags::X) {
            flags |= EptPteFlags::EXECUTE.bits();
        }
        if prop.flags.contains(PageFlags::AVAIL2) {
            flags |= EptPteFlags::AVAIL2.bits();
        }

        // Memory type
        let mem_type = match prop.cache {
            CachePolicy::Uncacheable => 0u64,
            CachePolicy::WriteCombining => 1,
            CachePolicy::Writethrough => 4,
            CachePolicy::WriteProtected => 5,
            CachePolicy::Writeback => 6,
        };
        flags |= mem_type << 3;

        // Accessed/Dirty not set initially

        // Available bits
        if prop.priv_flags.contains(PrivFlags::AVAIL1) {
            flags |= EptPteFlags::AVAIL1.bits();
        }

        Self((paddr as u64) & pa_mask | flags)
    }

    fn new_pt(paddr: Paddr, flags: PageTableFlags) -> Self {
        let mut ept_flags = EptPteFlags::READ | EptPteFlags::WRITE | EptPteFlags::EXECUTE;

        if flags.contains(PageTableFlags::AVAIL1) {
            ept_flags |= EptPteFlags::AVAIL1;
        }
        if flags.contains(PageTableFlags::AVAIL2) {
            ept_flags |= EptPteFlags::AVAIL2;
        }

        Self((paddr as u64) & Self::PHYS_ADDR_MASK | ept_flags.bits())
    }
}

impl PodOnce for EptPageTableEntry {}

// SAFETY: The implementation is safe because:
//  - `from_usize` and `into_usize` are not overridden;
//  - `from_repr` and `repr` are correctly implemented;
//  - a zeroed PTE represents an absent entry (no R/W/X bits set).
unsafe impl PteTrait for EptPageTableEntry {
    fn from_repr(repr: &PteScalar, level: PagingLevel) -> Self {
        match repr {
            PteScalar::Absent => EptPageTableEntry(0),
            PteScalar::PageTable(paddr, flags) => Self::new_pt(*paddr, *flags),
            PteScalar::Mapped(paddr, prop) => Self::new_page(*paddr, level, *prop),
        }
    }

    fn to_repr(&self, level: PagingLevel) -> PteScalar {
        if !self.is_present() {
            return PteScalar::Absent;
        }

        let paddr = (self.0 & Self::pa_mask_at_level(level)) as Paddr;
        if self.is_last(level) {
            PteScalar::Mapped(paddr, self.prop())
        } else {
            PteScalar::PageTable(paddr, self.pt_flags())
        }
    }
}

/// EPT page table configuration.
///
/// This is the `PageTableConfig` implementation that adapts the generic
/// `PageTable` infrastructure for EPT use.
#[derive(Clone, Debug)]
pub(crate) struct EptConfig {}

// SAFETY: `item_raw_info`, `item_from_raw`, and `item_ref_from_raw` are correctly
// implemented. Items are tuples of (Paddr, PagingLevel, PageProperty) that
// faithfully represent the EPT entry state.
unsafe impl PageTableConfig for EptConfig {
    /// Full 48-bit GPA space: top-level index 0..512.
    const TOP_LEVEL_INDEX_RANGE: Range<usize> = 0..512;

    type E = EptPageTableEntry;
    type C = EptPagingConsts;

    /// EPT uses untracked items (like IommuPtConfig).
    type Item = (Paddr, PagingLevel, PageProperty);
    type ItemRef<'a> = PhantomData<&'a ()>;

    fn item_raw_info(item: &Self::Item) -> (Paddr, PagingLevel, PageProperty) {
        (item.0, item.1, item.2)
    }

    unsafe fn item_from_raw(paddr: Paddr, level: PagingLevel, prop: PageProperty) -> Self::Item {
        (paddr, level, prop)
    }

    unsafe fn item_ref_from_raw<'a>(
        _paddr: Paddr,
        _level: PagingLevel,
        _prop: PageProperty,
    ) -> Self::ItemRef<'a> {
        PhantomData
    }
}

/// EPT page property (simpler than PageProperty -- no user/kernel distinction).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EptPageProperty {
    /// Read/Write/Execute permissions.
    pub flags: EptPageFlags,
    /// Memory type (0=UC, 1=WC, 4=WT, 5=WP, 6=WB).
    pub mem_type: u8,
}

bitflags! {
    /// EPT page permission flags.
    pub struct EptPageFlags: u8 {
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

impl Default for EptPageProperty {
    fn default() -> Self {
        Self {
            flags: EptPageFlags::RWX,
            mem_type: 6, // WB
        }
    }
}

impl From<EptPageProperty> for PageProperty {
    fn from(ept_prop: EptPageProperty) -> Self {
        let mut flags = PageFlags::empty();
        if ept_prop.flags.contains(EptPageFlags::READ) {
            flags |= PageFlags::R;
        }
        if ept_prop.flags.contains(EptPageFlags::WRITE) {
            flags |= PageFlags::W;
        }
        if ept_prop.flags.contains(EptPageFlags::EXECUTE) {
            flags |= PageFlags::X;
        }

        let cache = match ept_prop.mem_type {
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

/// Guest physical address space backed by EPT.
///
/// This is the hypervisor analog of `VmSpace`. It wraps an EPT page table
/// and provides a cursor API for mapping host frames into guest physical memory.
pub struct GuestPhysMemSpace {
    ept: PageTable<EptConfig>,
}

impl GuestPhysMemSpace {
    /// Creates a new empty guest physical address space.
    pub fn new() -> Self {
        Self {
            ept: PageTable::empty(),
        }
    }

    /// Returns a mutable cursor for mapping frames into guest physical memory.
    pub fn cursor_mut<'a, G: AsAtomicModeGuard>(
        &'a self,
        guard: &'a G,
        gpa_range: &Range<u64>,
    ) -> Result<GuestCursorMut<'a>> {
        let gpa_range = (gpa_range.start as Vaddr)..(gpa_range.end as Vaddr);
        let pt_cursor = self.ept.cursor_mut(guard, &gpa_range)?;
        Ok(GuestCursorMut { pt_cursor })
    }

    /// Returns the EPTP value for VMCS initialization.
    ///
    /// The EPTP format (64 bits):
    /// - bits[2:0] = 0 (must be 0)
    /// - bits[5:3] = memory type (6 = WB)
    /// - bits[7:6] = page walk length minus 1 (3 for 4 levels)
    /// - bits[8] = 0 (no access/dirty flags unless supported)
    /// - bits[51:12] = PML4 physical address
    pub fn eptp(&self) -> u64 {
        let pml4_paddr = self.ept.root_paddr();
        // Memory type WB (6) in bits[5:3], page walk length 4 in bits[7:6]
        (6u64 << 3) | (3u64 << 6) | ((pml4_paddr as u64) & 0x000F_FFFF_FFFF_F000)
    }
}

impl Default for GuestPhysMemSpace {
    fn default() -> Self {
        Self::new()
    }
}

/// Cursor for mapping frames into guest physical address space.
///
/// When dropped, issues INVEPT to maintain EPT TLB coherence.
pub struct GuestCursorMut<'a> {
    pt_cursor: CursorMut<'a, EptConfig>,
}

impl GuestCursorMut<'_> {
    /// Maps a host physical frame at the current GPA.
    ///
    /// Only untyped frames (UFrame) can be mapped into guest EPT.
    /// This ensures the guest cannot access typed kernel data structures.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the physical address is valid and
    /// mapping it into the guest EPT does not violate isolation.
    pub unsafe fn map(&mut self, paddr: Paddr, level: PagingLevel, prop: EptPageProperty) {
        let page_prop: PageProperty = prop.into();
        // SAFETY: The caller guarantees the physical address is valid
        // and the mapping does not violate guest isolation.
        unsafe { self.pt_cursor.map((paddr, level, page_prop)) };
    }

    /// Maps a typed frame into the guest EPT at the current GPA.
    ///
    /// The frame type guarantees a valid physical address, making
    /// this a safe operation.
    pub fn map_frame(
        &mut self,
        frame: &impl HasPaddr,
        level: PagingLevel,
        prop: EptPageProperty,
    ) {
        let paddr = frame.paddr();
        let page_prop: PageProperty = prop.into();
        // SAFETY: The frame type guarantees a valid physical address.
        // Mapping untyped frames into guest EPT is safe because the guest
        // is allowed to access these pages.
        unsafe { self.pt_cursor.map((paddr, level, page_prop)) };
    }

    /// Maps a zero page as a placeholder in the guest EPT at the current GPA.
    ///
    /// This is used for unmapped regions in the host VmSpace. The physical
    /// address 0 is a safe sentinel that can be mapped into EPT.
    pub fn map_zero(&mut self, level: PagingLevel, prop: EptPageProperty) {
        let page_prop: PageProperty = prop.into();
        // SAFETY: Physical address 0 is used as a safe placeholder sentinel.
        // It is a valid GPA within the EPT address space.
        unsafe { self.pt_cursor.map((0, level, page_prop)) };
    }

    /// Maps an item from a VmSpace query result into the guest EPT.
    ///
    /// The `VmQueriedItem` is produced by [`crate::mm::vm_space::Cursor::query`],
    /// which guarantees that any returned physical address is valid.
    /// This makes the operation safe without requiring the caller to
    /// verify the address.
    pub fn map_vm_item(
        &mut self,
        item: &VmQueriedItem<'_>,
        level: PagingLevel,
        prop: EptPageProperty,
    ) {
        let page_prop: PageProperty = prop.into();
        match item {
            VmQueriedItem::MappedRam { frame, .. } => {
                let paddr = frame.paddr();
                // SAFETY: The frame is a valid allocated page from the frame allocator.
                unsafe { self.pt_cursor.map((paddr, level, page_prop)) };
            }
            VmQueriedItem::MappedIoMem { paddr, .. } => {
                // SAFETY: The VmSpace guarantees that MappedIoMem addresses
                // are valid I/O memory regions.
                unsafe { self.pt_cursor.map((*paddr, level, page_prop)) };
            }
        }
    }

    /// Moves the cursor forward to the next page-sized GPA.
    ///
    /// Returns the GPA of the next mapping position, or `None` if
    /// the cursor has reached the end of its range.
    pub fn find_next(&mut self, len: usize) -> Option<u64> {
        self.pt_cursor.find_next(len).map(|va| va as u64)
    }
}

impl Drop for GuestCursorMut<'_> {
    fn drop(&mut self) {
        // Issue INVEPT to flush EPT TLB entries.
        // SAFETY: INVEPT is safe to call when EPT is active.
        unsafe {
            crate::arch::guest::vmx::invept_all();
        }
    }
}
