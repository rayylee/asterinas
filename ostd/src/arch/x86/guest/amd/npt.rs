// SPDX-License-Identifier: MPL-2.0

//! Nested Page Table (NPT) implementation for AMD SVM.
//!
//! NPT provides a second level of address translation that maps guest
//! physical addresses (GPAs) to host physical addresses (HPAs).
//! This is the AMD equivalent of Intel's EPT.

use core::{marker::PhantomData, ops::Range};

use bitflags::bitflags;

use crate::{
    mm::{
        HasPaddr, Paddr, PagingConstsTrait, PagingLevel, PodOnce, Vaddr,
        page_prop::{
            CachePolicy, PageFlags, PageProperty, PageTableFlags, PrivilegedPageFlags as PrivFlags,
        },
        page_table::{CursorMut, PageTable, PageTableConfig, PteScalar, PteTrait},
        vm_space::VmQueriedItem,
    },
    prelude::Result,
    task::atomic_mode::AsAtomicModeGuard,
};

/// NPT paging constants.
///
/// NPT uses 4 levels of page tables (PML4 -> PDPT -> PD -> PT),
/// mapping a 48-bit guest physical address space.
#[derive(Clone, Debug, Default)]
pub(crate) struct NptPagingConsts {}

impl PagingConstsTrait for NptPagingConsts {
    const BASE_PAGE_SIZE: usize = 4096;
    const NR_LEVELS: PagingLevel = 4;
    const ADDRESS_WIDTH: usize = 48;
    const VA_SIGN_EXT: bool = false;
    const HIGHEST_TRANSLATION_LEVEL: PagingLevel = 2;
    const PTE_SIZE: usize = size_of::<NptPageTableEntry>();
}

bitflags! {
    /// NPT PTE flags (AMD NPT format).
    ///
    /// AMD NPT uses a similar format to regular x86 page tables:
    /// - bit 0: Read
    /// - bit 1: Write
    /// - bit 2: Execute
    /// - bit 3-5: Reserved (must be 0 for NPT)
    /// - bit 6: Accessed
    /// - bit 7: Dirty
    /// - bit 8-10: Reserved
    /// - bit 11: Page size (huge page at level 2 or 3)
    /// - bit 12-51: Physical address
    /// - bit 52-62: Available for software
    /// - bit 63: NX (No Execute)
    #[repr(C)]
    #[derive(Pod)]
    pub(crate) struct NptPteFlags: u64 {
        const READ       = 1 << 0;
        const WRITE      = 1 << 1;
        const EXECUTE    = 1 << 2;
        const ACCESSED   = 1 << 6;
        const DIRTY      = 1 << 7;
        const HUGE       = 1 << 11;
        const AVAIL1     = 1 << 52;
        const AVAIL2     = 1 << 53;
        const NX         = 1 << 63;
    }
}

/// NPT page table entry (8 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod)]
pub(crate) struct NptPageTableEntry(u64);

impl NptPageTableEntry {
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
        self.0 & (NptPteFlags::READ | NptPteFlags::WRITE | NptPteFlags::EXECUTE).bits() != 0
    }

    fn is_huge(&self) -> bool {
        self.0 & NptPteFlags::HUGE.bits() != 0
    }

    fn is_last(&self, level: PagingLevel) -> bool {
        level == 1 || self.is_huge()
    }

    fn prop(&self) -> PageProperty {
        let mut flags_val = 0u8;
        if self.0 & NptPteFlags::READ.bits() != 0 {
            flags_val |= PageFlags::R.bits();
        }
        if self.0 & NptPteFlags::WRITE.bits() != 0 {
            flags_val |= PageFlags::W.bits();
        }
        if self.0 & NptPteFlags::EXECUTE.bits() != 0 {
            flags_val |= PageFlags::X.bits();
        }
        if self.0 & NptPteFlags::AVAIL2.bits() != 0 {
            flags_val |= PageFlags::AVAIL2.bits();
        }

        let mut priv_val = 0u8;
        if self.0 & NptPteFlags::AVAIL1.bits() != 0 {
            priv_val |= PrivFlags::AVAIL1.bits();
        }

        // NPT doesn't encode memory type in the PTE (uses PAT MTRRs).
        // Default to Writeback.
        PageProperty {
            flags: PageFlags::from_bits(flags_val).unwrap_or(PageFlags::RWX),
            cache: CachePolicy::Writeback,
            priv_flags: PrivFlags::from_bits(priv_val).unwrap_or(PrivFlags::empty()),
        }
    }

    fn pt_flags(&self) -> PageTableFlags {
        let mut bits = 0u8;
        if self.0 & NptPteFlags::AVAIL1.bits() != 0 {
            bits |= PageTableFlags::AVAIL1.bits();
        }
        if self.0 & NptPteFlags::AVAIL2.bits() != 0 {
            bits |= PageTableFlags::AVAIL2.bits();
        }
        PageTableFlags::from_bits(bits).unwrap_or(PageTableFlags::empty())
    }

    fn new_page(paddr: Paddr, level: PagingLevel, prop: PageProperty) -> Self {
        let pa_mask = Self::pa_mask_at_level(level);
        let mut flags = 0u64;

        if prop.flags.contains(PageFlags::R) {
            flags |= NptPteFlags::READ.bits();
        }
        if prop.flags.contains(PageFlags::W) {
            flags |= NptPteFlags::WRITE.bits();
        }
        if prop.flags.contains(PageFlags::X) {
            flags |= NptPteFlags::EXECUTE.bits();
        } else {
            flags |= NptPteFlags::NX.bits();
        }
        if prop.flags.contains(PageFlags::AVAIL2) {
            flags |= NptPteFlags::AVAIL2.bits();
        }

        if prop.priv_flags.contains(PrivFlags::AVAIL1) {
            flags |= NptPteFlags::AVAIL1.bits();
        }

        Self((paddr as u64) & pa_mask | flags)
    }

    fn new_pt(paddr: Paddr, flags: PageTableFlags) -> Self {
        let mut npt_flags = NptPteFlags::READ | NptPteFlags::WRITE | NptPteFlags::EXECUTE;

        if flags.contains(PageTableFlags::AVAIL1) {
            npt_flags |= NptPteFlags::AVAIL1;
        }
        if flags.contains(PageTableFlags::AVAIL2) {
            npt_flags |= NptPteFlags::AVAIL2;
        }

        Self((paddr as u64) & Self::PHYS_ADDR_MASK | npt_flags.bits())
    }
}

impl PodOnce for NptPageTableEntry {}

// SAFETY: The implementation follows the same pattern as `EptPageTableEntry`.
// A zeroed NPT entry represents an absent entry (no R/W/X bits set).
unsafe impl PteTrait for NptPageTableEntry {
    fn from_repr(repr: &PteScalar, level: PagingLevel) -> Self {
        match repr {
            PteScalar::Absent => NptPageTableEntry(0),
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

/// NPT page table configuration.
#[derive(Clone, Debug)]
pub(crate) struct NptConfig {}

// SAFETY: Implementation matches the pattern of EptConfig.
unsafe impl PageTableConfig for NptConfig {
    const TOP_LEVEL_INDEX_RANGE: Range<usize> = 0..512;

    type E = NptPageTableEntry;
    type C = NptPagingConsts;

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

/// NPT page property.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(missing_docs)]
pub struct NptPageProperty {
    pub flags: NptPageFlags,
    pub mem_type: u8,
}

bitflags! {
    /// NPT page permission flags.
    pub struct NptPageFlags: u8 {
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

impl Default for NptPageProperty {
    fn default() -> Self {
        Self {
            flags: NptPageFlags::RWX,
            mem_type: 6,
        }
    }
}

impl From<NptPageProperty> for PageProperty {
    fn from(npt_prop: NptPageProperty) -> Self {
        let mut flags = PageFlags::empty();
        if npt_prop.flags.contains(NptPageFlags::READ) {
            flags |= PageFlags::R;
        }
        if npt_prop.flags.contains(NptPageFlags::WRITE) {
            flags |= PageFlags::W;
        }
        if npt_prop.flags.contains(NptPageFlags::EXECUTE) {
            flags |= PageFlags::X;
        }

        PageProperty::new_user(flags, CachePolicy::Writeback)
    }
}

/// AMD NPT-based guest physical address space.
pub struct GuestPhysMemSpace {
    npt: PageTable<NptConfig>,
}

impl GuestPhysMemSpace {
    /// Creates a new empty guest physical address space with NPT.
    pub fn new() -> Self {
        Self {
            npt: PageTable::empty(),
        }
    }

    pub fn cursor_mut<'a, G: AsAtomicModeGuard>(
        &'a self,
        guard: &'a G,
        gpa_range: &Range<u64>,
    ) -> Result<GuestCursorMut<'a>> {
        let gpa_range = (gpa_range.start as Vaddr)..(gpa_range.end as Vaddr);
        let pt_cursor = self.npt.cursor_mut(guard, &gpa_range)?;
        Ok(GuestCursorMut { pt_cursor })
    }

    /// Returns the NPT pointer value (nCR3) for VMCB initialization.
    ///
    /// nCR3 format (VMCB offset 0x450):
    ///   Bit 0:     NP_ENABLE (must be 1 to enable nested paging)
    ///   Bits 11:1: Reserved (0)
    ///   Bits 63:12: NPT root physical address
    pub fn nptp(&self) -> u64 {
        let root_paddr = self.npt.root_paddr() as u64;
        root_paddr | 1 // NP_ENABLE
    }
}

impl Default for GuestPhysMemSpace {
    fn default() -> Self {
        Self::new()
    }
}

/// AMD NPT cursor for mapping frames.
pub struct GuestCursorMut<'a> {
    pt_cursor: CursorMut<'a, NptConfig>,
}

impl GuestCursorMut<'_> {
    pub unsafe fn map(&mut self, paddr: Paddr, level: PagingLevel, prop: PageProperty) {
        // SAFETY: The caller guarantees the physical address is valid
        // and the mapping does not violate guest isolation.
        unsafe { self.pt_cursor.map((paddr, level, prop)) };
    }

    pub fn map_frame(&mut self, frame: &impl HasPaddr, level: PagingLevel, prop: PageProperty) {
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

    pub fn map_paddr(&mut self, paddr: Paddr, level: PagingLevel, prop: PageProperty) {
        // SAFETY: The caller is responsible for ensuring the physical address is valid.
        unsafe { self.pt_cursor.map((paddr, level, prop)) };
    }

    pub fn find_next(&mut self, len: usize) -> Option<u64> {
        self.pt_cursor.find_next(len).map(|va| va as u64)
    }
}

impl Drop for GuestCursorMut<'_> {
    fn drop(&mut self) {
        // SAFETY: INVLPGA is safe to call when NPT is active.
        // ASID=0, address=0 flushes all guest TLB entries.
        unsafe {
            crate::arch::guest::amd::asm::invlpga_all();
        }
    }
}
