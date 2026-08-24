// SPDX-License-Identifier: MPL-2.0

//! The x86 boot module defines the entrypoints of Asterinas and
//! the corresponding headers for different x86 boot protocols.
//!
//! We directly support
//!
//!  - Multiboot
//!  - Multiboot2
//!  - Linux x86 Boot Protocol
//!  - PVH
//!
//! without any additional configurations.
//!
//! Asterinas differentiates the boot protocol by the entry point
//! chosen by the boot loader. In each entry point function,
//! the universal callback registration method from
//! `crate::boot` will be called. Thus the initialization of
//! boot information is transparent for the upper level kernel.
//!

mod linux_boot;
mod multiboot;
mod multiboot2;
mod pvh;

pub(crate) mod smp;

use core::{arch::global_asm, num::NonZeroUsize};

use acpi::rsdp::Rsdp;

use crate::{
    arch::kernel::acpi::AcpiMemoryHandler, boot::memory_region::MemoryRegionType,
    mm::kspace::paddr_to_vaddr,
};

global_asm!(
    include_str!("bsp_boot.S"),
    KCODE64 = const super::trap::gdt::KCODE64,
    KDATA = const super::trap::gdt::KDATA,
    KCODE32 = const super::trap::gdt::KCODE32,
);
global_asm!(include_str!("ap_boot.S"));

/// Finds the physical address of the ACPI root table.
pub(super) fn find_acpi_root_table_address(rsdp_paddr: Option<u64>) -> Option<NonZeroUsize> {
    match rsdp_paddr {
        Some(rsdp_paddr) => rsdp_root_table_address(rsdp_paddr),
        None => bios_scan_root_table_address(),
    }
}

fn rsdp_root_table_address(rsdp_paddr: u64) -> Option<NonZeroUsize> {
    // Reference: <https://uefi.org/specs/ACPI/6.6/05_ACPI_Software_Programming_Model.html#root-system-description-pointer-rsdp-structure>

    let rsdp = paddr_to_vaddr(rsdp_paddr as usize) as *const u8;
    // SAFETY: The boot protocol guarantees a valid, readable RSDP at
    // `rsdp_paddr`, and only its header fields are read.
    unsafe {
        if core::slice::from_raw_parts(rsdp, 8) != *b"RSD PTR " {
            return None;
        }

        if *rsdp.add(15) == 0 {
            NonZeroUsize::new(rsdp.cast::<u32>().byte_add(16).read_unaligned() as usize)
        } else {
            NonZeroUsize::new(rsdp.cast::<u64>().byte_add(24).read_unaligned() as usize)
        }
    }
}

fn bios_scan_root_table_address() -> Option<NonZeroUsize> {
    // Multiboot v1 is BIOS-oriented: its entry state and boot information are
    // based on the legacy PC BIOS model, and it has no standard EFI System
    // Table field. So we use the BIOS RSDP scan as the legacy fallback.
    //
    // SAFETY: The Multiboot v1 entry path is treated as BIOS-compatible.
    let Ok(rsdp) = (unsafe { Rsdp::search_for_on_bios(AcpiMemoryHandler {}) }) else {
        return None;
    };

    if rsdp.revision() == 0 {
        NonZeroUsize::new(rsdp.rsdt_address() as usize)
    } else {
        NonZeroUsize::new(rsdp.xsdt_address() as usize)
    }
}

/// Returns the effective type of a loader-reported memory region, promoting a
/// reserved region that contains the ACPI root table to `Reclaimable`.
///
/// Some loaders (e.g., QEMU's PVH loader) place the ACPI tables in a region
/// that they report as reserved, above the highest usable memory region. The
/// kernel reads ACPI tables through the linear mapping, which only covers
/// regions whose type [`MemoryRegionType::is_physical`] accepts. Promoting the
/// region containing the root table keeps the tables accessible.
///
/// FIXME: The ACPI specification does not guarantee that all ACPI tables are
/// contiguous and do not cross region boundaries. See ACPI 6.4, Section 5.1,
/// "Overview of the System Description Table Architecture". A full ACPI table
/// graph scan may eventually be unavoidable.
pub(super) fn effective_region_type(
    typ: MemoryRegionType,
    base: usize,
    len: usize,
    acpi_root_table_address: Option<NonZeroUsize>,
) -> MemoryRegionType {
    if typ == MemoryRegionType::Reserved
        && acpi_root_table_address.is_some_and(|addr| (base..(base + len)).contains(&addr.get()))
    {
        MemoryRegionType::Reclaimable
    } else {
        typ
    }
}
