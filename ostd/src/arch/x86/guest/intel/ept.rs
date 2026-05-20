// SPDX-License-Identifier: MPL-2.0

//! Extended Page Table (EPT) implementation for Intel VT-x.
//!
//! EPT provides a second level of address translation that maps guest
//! physical addresses (GPAs) to host physical addresses (HPAs).

use core::marker::PhantomData;
use core::ops::Range;

use bitflags::bitflags;

use crate::mm::{
    HasPaddr, Paddr, PagingConstsTrait, PagingLevel, PodOnce, Vaddr,
    page_prop::{CachePolicy, PageFlags, PageProperty, PageTableFlags, PrivilegedPageFlags as PrivFlags},
    page_table::{PageTable, PageTableConfig, PteScalar, PteTrait, CursorMut},
    vm_space::VmQueriedItem,
};
use crate::prelude::Result;
use crate::task::atomic_mode::AsAtomicModeGuard;

/// EPT paging constants.
#[derive(Clone, Debug, Default)]
pub(crate) struct EptPagingConsts {}

impl PagingConstsTrait for EptPagingConsts {
    const BASE_PAGE_SIZE: usize = 4096;
    const NR_LEVELS: PagingLevel = 4;
    const ADDRESS_WIDTH: usize = 48;
    const VA_SIGN_EXT: bool = false;
    const HIGHEST_TRANSLATION_LEVEL: PagingLevel = 2;
    const PTE_SIZE: usize = size_of::<EptPageTableEntry>();
}

bitflags! {
    /// EPT PTE flags.
    #[repr(C)]
    #[derive(Pod)]
    pub(crate) struct EptPteFlags: u64 {
        const READ       = 1 << 0;
        const WRITE      = 1 << 1;
        const EXECUTE    = 1 << 2;
        const ACCESSED   = 1 << 8;
        const DIRTY      = 1 << 9;
        const EXEC_ONLY  = 1 << 10;
        const HUGE       = 1 << 7;
        const AVAIL1     = 1 << 52;
        const AVAIL2     = 1 << 53;
    }
}

/// EPT page table entry (8 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod)]
pub(crate) struct EptPageTableEntry(u64);

impl EptPageTableEntry {
    const PHYS_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
    const PHYS_ADDR_MASK_2M: u64 = 0x000F_FFFF_FFC0_0000;
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
        self.0 & (EptPteFlags::READ | EptPteFlags::WRITE | EptPteFlags::EXECUTE).bits() != 0
    }

    fn is_huge(&self) -> bool {
        self.0 & EptPteFlags::HUGE.bits() != 0
    }

    fn is_last(&self, level: PagingLevel) -> bool {
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
        let mut flags = 0u64;

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

        let mem_type = match prop.cache {
            CachePolicy::Uncacheable => 0u64,
            CachePolicy::WriteCombining => 1,
            CachePolicy::Writethrough => 4,
            CachePolicy::WriteProtected => 5,
            CachePolicy::Writeback => 6,
        };
        flags |= mem_type << 3;

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
#[derive(Clone, Debug)]
pub(crate) struct EptConfig {}

// SAFETY: `item_raw_info`, `item_from_raw`, and `item_ref_from_raw` are correctly
// implemented. Items are tuples of (Paddr, PagingLevel, PageProperty) that
// faithfully represent the EPT entry state.
unsafe impl PageTableConfig for EptConfig {
    const TOP_LEVEL_INDEX_RANGE: Range<usize> = 0..512;

    type E = EptPageTableEntry;
    type C = EptPagingConsts;

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

/// EPT page property.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(missing_docs)]
pub struct EptPageProperty {
    pub flags: EptPageFlags,
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
            mem_type: 6,
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

/// Intel EPT-based guest physical address space.
pub struct GuestPhysMemSpace {
    ept: PageTable<EptConfig>,
}

impl GuestPhysMemSpace {
    /// Creates a new empty guest physical address space with EPT.
    pub fn new() -> Self {
        Self {
            ept: PageTable::empty(),
        }
    }

    pub fn cursor_mut<'a, G: AsAtomicModeGuard>(
        &'a self,
        guard: &'a G,
        gpa_range: &Range<u64>,
    ) -> Result<GuestCursorMut<'a>> {
        let gpa_range = (gpa_range.start as Vaddr)..(gpa_range.end as Vaddr);
        let pt_cursor = self.ept.cursor_mut(guard, &gpa_range)?;
        Ok(GuestCursorMut { pt_cursor })
    }

    pub fn eptp(&self) -> u64 {
        let pml4_paddr = self.ept.root_paddr();
        (6u64 << 3) | (3u64 << 6) | ((pml4_paddr as u64) & 0x000F_FFFF_FFFF_F000)
    }
}

impl Default for GuestPhysMemSpace {
    fn default() -> Self {
        Self::new()
    }
}

/// Intel EPT cursor for mapping frames.
pub struct GuestCursorMut<'a> {
    pt_cursor: CursorMut<'a, EptConfig>,
}

impl GuestCursorMut<'_> {
    pub unsafe fn map(&mut self, paddr: Paddr, level: PagingLevel, prop: PageProperty) {
        // SAFETY: The caller guarantees the physical address is valid
        // and the mapping does not violate guest isolation.
        unsafe { self.pt_cursor.map((paddr, level, prop)) };
    }

    pub fn map_frame(
        &mut self,
        frame: &impl HasPaddr,
        level: PagingLevel,
        prop: PageProperty,
    ) {
        let paddr = frame.paddr();
        // SAFETY: The frame type guarantees a valid physical address.
        unsafe { self.pt_cursor.map((paddr, level, prop)) };
    }

    pub fn map_zero(&mut self, level: PagingLevel, prop: PageProperty) {
        // SAFETY: Physical address 0 is a safe placeholder sentinel.
        unsafe { self.pt_cursor.map((0, level, prop)) };
    }

    pub fn map_vm_item(
        &mut self,
        item: &VmQueriedItem<'_>,
        level: PagingLevel,
        prop: PageProperty,
    ) {
        match item {
            VmQueriedItem::MappedRam { frame, .. } => {
                let paddr = frame.paddr();
                // SAFETY: The frame is a valid allocated page from the frame allocator.
                unsafe { self.pt_cursor.map((paddr, level, prop)) };
            }
            VmQueriedItem::MappedIoMem { paddr, .. } => {
                // SAFETY: The VmSpace guarantees that MappedIoMem addresses
                // are valid I/O memory regions.
                unsafe { self.pt_cursor.map((*paddr, level, prop)) };
            }
        }
    }

    pub fn find_next(&mut self, len: usize) -> Option<u64> {
        self.pt_cursor.find_next(len).map(|va| va as u64)
    }
}

impl Drop for GuestCursorMut<'_> {
    fn drop(&mut self) {
        // SAFETY: INVEPT is safe to call when EPT is active.
        unsafe {
            super::vmx::invept_all();
        }
    }
}
