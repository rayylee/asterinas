// SPDX-License-Identifier: MPL-2.0

//! VMCB (Virtual Machine Control Block) management for AMD SVM.
//!
//! Each vCPU has one VMCB, a 4KB-aligned region of memory that holds
//! all SVM configuration and guest/host state. The layout is split into
//! a state-save area (offset 0x000–0x3FF) and a control area (offset 0x400–0xFFF).

use core::sync::atomic::{AtomicU32, Ordering};

use crate::{
    cpu::CpuId,
    mm::{FrameAllocOptions, UFrame, paddr_to_vaddr},
    prelude::*,
    Error,
};

/// A VMCB (Virtual Machine Control Block).
///
/// Each vCPU owns one VMCB. The VMCB holds all SVM configuration,
/// guest state, and control fields.
pub struct Vmcb {
    /// The 4KB frame that holds the VMCB region.
    frame: UFrame,
    /// The CPU ID where this VMCB was last used (for migration tracking).
    /// `u32::MAX` means not used on any CPU.
    loaded_cpu: AtomicU32,
    /// Whether this VMCB has been used for a VMRUN.
    launched: AtomicU32,
}

impl Vmcb {
    /// Allocates a new VMCB, zeroed.
    pub fn new() -> Result<Self> {
        let frame = FrameAllocOptions::new()
            .alloc_frame()
            .map_err(|_| Error::NoMemory)?;

        // Zero the VMCB (required by SVM specification for unused fields)
        let vaddr = paddr_to_vaddr(frame.paddr()) as *mut u8;
        // SAFETY: We just allocated this frame; zeroing is safe.
        unsafe {
            core::ptr::write_bytes(vaddr, 0, 4096);
        }

        Ok(Self {
            frame: frame.into(),
            loaded_cpu: AtomicU32::new(u32::MAX),
            launched: AtomicU32::new(0),
        })
    }

    /// Returns the physical address of the VMCB region.
    pub fn paddr(&self) -> Paddr {
        self.frame.paddr()
    }

    fn vaddr(&self) -> *mut u8 {
        paddr_to_vaddr(self.frame.paddr()) as *mut u8
    }

    /// Returns whether this VMCB has been launched (VMRUN done).
    pub fn is_launched(&self) -> bool {
        self.launched.load(Ordering::Acquire) != 0
    }

    /// Marks this VMCB as launched after the first successful VMRUN.
    pub fn mark_launched(&self) {
        self.launched.store(1, Ordering::Release);
    }

    /// Reads a u64 field from the VMCB at the given byte offset.
    ///
    /// # Safety
    ///
    /// The offset must be within the VMCB region (0..4096).
    pub unsafe fn read_u64(&self, offset: u16) -> u64 {
        // SAFETY: Caller ensures offset is within VMCB bounds.
        unsafe {
            let ptr = self.vaddr().add(offset as usize) as *mut u64;
            core::ptr::read_volatile(ptr)
        }
    }

    /// Writes a u64 field to the VMCB at the given byte offset.
    ///
    /// # Safety
    ///
    /// The offset must be within the VMCB region (0..4096).
    pub unsafe fn write_u64(&self, offset: u16, value: u64) {
        // SAFETY: Caller ensures offset is within VMCB bounds.
        unsafe {
            let ptr = self.vaddr().add(offset as usize) as *mut u64;
            core::ptr::write_volatile(ptr, value)
        }
    }

    /// Reads a u32 field from the VMCB at the given byte offset.
    ///
    /// # Safety
    ///
    /// The offset must be within the VMCB region (0..4096).
    pub unsafe fn read_u32(&self, offset: u16) -> u32 {
        // SAFETY: Caller ensures offset is within VMCB bounds.
        unsafe {
            let ptr = self.vaddr().add(offset as usize) as *mut u32;
            core::ptr::read_volatile(ptr)
        }
    }

    /// Writes a u32 field to the VMCB at the given byte offset.
    ///
    /// # Safety
    ///
    /// The offset must be within the VMCB region (0..4096).
    pub unsafe fn write_u32(&self, offset: u16, value: u32) {
        // SAFETY: Caller ensures offset is within VMCB bounds.
        unsafe {
            let ptr = self.vaddr().add(offset as usize) as *mut u32;
            core::ptr::write_volatile(ptr, value)
        }
    }

    /// Initializes VMCB control and state fields for guest execution.
    ///
    /// # Safety
    ///
    /// This VMCB must be ready for VMRUN (allocation done, not shared).
    pub unsafe fn initialize(&self, nptp: u64) -> Result<()> {
        // SAFETY: Self is a valid VMCB.
        unsafe {
            self.init_controls()?;
            self.init_guest_state()?;
            self.init_npt(nptp)?;
        }
        Ok(())
    }

    /// Initializes the control area of the VMCB.
    ///
    /// # Safety
    ///
    /// VMCB must be valid.
    unsafe fn init_controls(&self) -> Result<()> {
        // VMCB control area starts at offset 0x400.
        // Enable intercepts for specific instructions.

        // Intercept vectors: three 64-bit fields at offsets 0x400, 0x408, 0x410
        // Each bit corresponds to an instruction to intercept.

        // SAFETY: Writing to valid VMCB offsets.
        unsafe {
            // First intercept vector (offset 0x400):
            // Bit 0:   INTR (external interrupt) - do NOT intercept
            // Bit 1:   NMI - intercept
            // Bit 3:   INVLPG - intercept
            // Bit 4:   CPUID - intercept
            // Bit 5:   HLT - intercept
            // Bit 6:   INVD - intercept
            // Bit 7:   HLT - intercept
            // Bit 8:   INVLPG - intercept
            // For now: intercept CPUID, HLT, IO, MSR, CR access, etc.
            self.write_u64(0x400, 0);

            // Enable CPUID (bit 4), HLT (bit 5), IO (bit 12), MSR (bit 28) intercepts
            self.write_u64(0x400,
                (1 << 4)  | // CPUID
                (1 << 5)  | // HLT
                (1 << 12) | // IN/OUT
                (1 << 28)   // MSR
            );

            // Intercept CR accesses: CR0, CR3, CR4 reads/writes at offset 0x408
            // uint16 at offset 0x408, 0x40A
            // Bits 0-15: CR0-CR15 read intercept
            // Bits 16-31: CR0-CR15 write intercept
            self.write_u16(0x408, 0);
            self.write_u16(0x40A, 0);

            // Exception intercept bitmap (offset 0x40C, u32)
            // Bit <vector> = intercept exception <vector>
            // For now: intercept #DE (0), #DB (1), #BP (3), #OF (4)
            //           #BR (5), #UD (6), #NM (7), #DF (8), #TS (10)
            //           #NP (11), #SS (12), #GP (13), #PF (14), #MF (16)
            self.write_u32(0x40C, 0);

            // I/O bitmap base (offset 0x420, u64) - 0 means no I/O bitmap
            self.write_u64(0x420, 0);

            // MSRPM base (offset 0x428, u64) - 0 means no MSR bitmap
            self.write_u64(0x428, 0);

            // TSC offset (offset 0x430, u64)
            self.write_u64(0x430, 0);

            // Guest ASID (offset 0x438, u32) - for TLB tagging
            self.write_u32(0x438, 1);

            // TLB control (offset 0x43C, u8)
            self.write_u8(0x43C, 0);

            // V_INTR (offset 0x440, u32) - virtual interrupt control
            self.write_u32(0x440, 0);

            // V_INTR_VECTOR (offset 0x444, u32)
            self.write_u32(0x444, 0);

            // V_INTR_PRIO (offset 0x448, u32)
            self.write_u32(0x448, 0);

            // V_IGN_TPR (offset 0x44C, u32)
            self.write_u32(0x44C, 0);

            // NPT (offset 0x450, u64) - nCR3 / NPT pointer
            // Set by init_npt

            // LBR VIRT (offset 0x460, u64)
            self.write_u64(0x460, 0);

            // Clean field (offset 0x474, u32)
            // Bit 0: I intercepts clean
            // Bit 1: CRx intercepts clean
            // ...
            // Set to 0 to indicate nothing clean (all fields need reloading)
            self.write_u32(0x474, 0);
        }

        Ok(())
    }

    /// Initializes the state save area for a minimal 64-bit guest.
    ///
    /// # Safety
    ///
    /// VMCB must be valid.
    unsafe fn init_guest_state(&self) -> Result<()> {
        // SAFETY: Writing to valid VMCB state save area offsets.
        unsafe {
            // CS: Selector=0x08, Limit=0xFFFFFFFF, Attr=0xA09B, Base=0
            self.write_u16(0x014, 0x08);   // CS selector
            self.write_u32(0x018, 0xFFFFFFFF); // CS limit
            self.write_u32(0x01C, 0xA09B);    // CS attributes
            self.write_u64(0x010, 0);          // CS base

            // DS/ES/SS/FS/GS: data segments
            // ES at 0x000, DS at 0x070, etc.
            // For simplicity, set all data segments similarly.
            self.write_u16(0x004, 0x10);   // ES selector
            self.write_u32(0x008, 0xFFFFFFFF); // ES limit
            self.write_u32(0x00C, 0xA093);    // ES attributes

            self.write_u16(0x074, 0x10);   // DS selector
            self.write_u32(0x078, 0xFFFFFFFF); // DS limit
            self.write_u32(0x07C, 0xA093);    // DS attributes

            self.write_u16(0x09C, 0x10);   // SS selector
            self.write_u32(0x0A0, 0xFFFFFFFF); // SS limit
            self.write_u32(0x0A4, 0xA093);    // SS attributes

            // RIP (offset 0x268)
            self.write_u64(0x268, 0);

            // RSP (offset 0x270)
            self.write_u64(0x270, 0);

            // RFLAGS (offset 0x278)
            self.write_u64(0x278, (1 << 1) | (1 << 9)); // IF=1, always 1

            // CR0 (offset 0x230): PE + NE + WP + PG + MP + ET
            let cr0 = (1 << 0) | (1 << 2) | (1 << 5) | (1 << 16) | (1 << 18) | (1 << 29) | (1 << 30);
            self.write_u64(0x230, cr0);

            // CR2 (offset 0x238)
            self.write_u64(0x238, 0);

            // CR3 (offset 0x240)
            self.write_u64(0x240, 0);

            // CR4 (offset 0x248): PAE + OSFXSR + OSXMMEXCPT + OSXSAVE + VME
            let cr4 = (1 << 0) | (1 << 4) | (1 << 7) | (1 << 9) | (1 << 10);
            self.write_u64(0x248, cr4);

            // EFER (offset 0x250): LME + LMA + NXE + SVME
            let efer = (1 << 0) | (1 << 8) | (1 << 10) | (1 << 12);
            self.write_u64(0x250, efer);
        }

        Ok(())
    }

    /// Sets the NPT pointer in the VMCB control area.
    ///
    /// # Safety
    ///
    /// VMCB must be valid.
    unsafe fn init_npt(&self, nptp: u64) -> Result<()> {
        // nCR3 / NPT pointer at VMCB control area offset 0x450
        // SAFETY: Valid VMCB and valid page table pointer.
        unsafe {
            self.write_u64(0x450, nptp);
        }
        Ok(())
    }

    /// Writes a u16 field at the given byte offset.
    ///
    /// # Safety
    ///
    /// Offset must be valid.
    unsafe fn write_u16(&self, offset: u16, value: u16) {
        // SAFETY: Caller ensures offset is within VMCB bounds.
        unsafe {
            let ptr = self.vaddr().add(offset as usize) as *mut u16;
            core::ptr::write_volatile(ptr, value)
        }
    }

    /// Writes a u8 field at the given byte offset.
    ///
    /// # Safety
    ///
    /// Offset must be valid.
    unsafe fn write_u8(&self, offset: u16, value: u8) {
        // SAFETY: Caller ensures offset is within VMCB bounds.
        unsafe {
            let ptr = self.vaddr().add(offset as usize) as *mut u8;
            core::ptr::write_volatile(ptr, value)
        }
    }

    /// Loads this VMCB's context on the current CPU.
    ///
    /// For SVM, this means ensuring the VMCB is ready for VMRUN.
    /// No specific instruction is needed (unlike Intel's VMPTRLD) -
    /// VMRUN just uses the physical address.
    pub fn prepare_for_run(&self) -> Result<()> {
        // Track current CPU for migration
        let current_cpu: u32 = CpuId::current_racy().into();
        self.loaded_cpu.store(current_cpu, Ordering::Release);
        Ok(())
    }
}

impl Drop for Vmcb {
    fn drop(&mut self) {
        let prev_cpu = self.loaded_cpu.load(Ordering::Acquire);
        if prev_cpu != u32::MAX {
            crate::warn!(
                "Vmcb dropped while still loaded on CPU {} (possible resource leak)",
                prev_cpu
            );
        }
    }
}

/// VMCB state save area field offsets (byte offsets from VMCB base).
#[allow(dead_code)]
pub(crate) mod vmcb_offset {
    // State save area
    pub const ES_BASE: u16 = 0x000;
    pub const CS_BASE: u16 = 0x010;
    pub const DS_BASE: u16 = 0x070;
    pub const SS_BASE: u16 = 0x098;
    pub const GDTR_BASE: u16 = 0x0C0;
    pub const LDTR_BASE: u16 = 0x0D0;
    pub const IDTR_BASE: u16 = 0x0E0;
    pub const TR_BASE: u16 = 0x0F0;

    pub const CR0: u16 = 0x230;
    pub const CR2: u16 = 0x238;
    pub const CR3: u16 = 0x240;
    pub const CR4: u16 = 0x248;
    pub const EFER: u16 = 0x250;

    pub const RAX: u16 = 0x1F8;
    pub const RIP: u16 = 0x268;
    pub const RSP: u16 = 0x270;
    pub const RFLAGS: u16 = 0x278;

    // Control area
    pub const NP_ENABLE: u16 = 0x450;
    pub const EXITCODE: u16 = 0x47C;
    pub const EXITINFO1: u16 = 0x480;
    pub const EXITINFO2: u16 = 0x488;
    pub const EXITINTINFO: u16 = 0x490;
}
