// SPDX-License-Identifier: MPL-2.0

//! KVM ioctl definitions.
//!
//! Defines the ioctl command types for the KVM device, VM, and vCPU file
//! descriptors. All KVM ioctls use the magic byte `0xAE`.

use crate::util::ioctl::{ioc, InData, NoData, OutData, PassByVal};

// /dev/kvm ioctls
pub type GetApiVersion = ioc!(KVM_GET_API_VERSION, 0xAE00, NoData);
pub type CreateVm = ioc!(KVM_CREATE_VM, 0xAE01, NoData);
pub type CheckExtension = ioc!(KVM_CHECK_EXTENSION, 0xAE03, InData<i32, PassByVal>);
pub type GetVcpuMmapSize = ioc!(KVM_GET_VCPU_MMAP_SIZE, 0xAE04, NoData);

// VM fd ioctls
pub type CreateVcpu = ioc!(KVM_CREATE_VCPU, 0xAE41, InData<i32, PassByVal>);
pub type SetUserMemoryRegion = ioc!(KVM_SET_USER_MEMORY_REGION, 0xAE, 0x46, InData<KvmUserspaceMemoryRegion>);
pub type SetTssAddr = ioc!(KVM_SET_TSS_ADDR, 0xAE47, InData<u64, PassByVal>);
pub type SetIdentityMapAddr = ioc!(KVM_SET_IDENTITY_MAP_ADDR, 0xAE, 0x48, InData<u64>);

// vCPU fd ioctls
pub type Run = ioc!(KVM_RUN, 0xAE80, NoData);
pub type GetRegs = ioc!(KVM_GET_REGS, 0xAE, 0x81, OutData<KvmRegs>);
pub type SetRegs = ioc!(KVM_SET_REGS, 0xAE, 0x82, InData<KvmRegs>);
pub type GetSregs = ioc!(KVM_GET_SREGS, 0xAE, 0x83, OutData<KvmSregs>);
pub type SetSregs = ioc!(KVM_SET_SREGS, 0xAE, 0x84, InData<KvmSregs>);

/// KVM userspace memory region descriptor.
///
/// Corresponds to `struct kvm_userspace_memory_region` in Linux.
#[derive(Debug, Clone, Copy, Pod)]
#[repr(C)]
pub struct KvmUserspaceMemoryRegion {
    /// Slot identifier for this memory region.
    pub slot: u32,
    /// Flags (e.g., KVM_MEM_LOG_DIRTY_PAGES).
    pub flags: u32,
    /// Guest physical address where this region starts.
    pub guest_phys_addr: u64,
    /// Size of the memory region in bytes.
    pub memory_size: u64,
    /// Userspace address of the memory backing this region.
    pub userspace_addr: u64,
}

/// KVM general-purpose registers.
///
/// Corresponds to `struct kvm_regs` in Linux.
#[derive(Debug, Clone, Copy, Default, Pod)]
#[repr(C)]
pub struct KvmRegs {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

/// KVM segment register descriptor.
///
/// Corresponds to `struct kvm_segment` in Linux.
#[derive(Debug, Clone, Copy, Default, Pod)]
#[repr(C)]
pub struct KvmSegment {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    pub type_: u8,
    pub present: u8,
    pub dpl: u8,
    pub db: u8,
    pub s: u8,
    pub l: u8,
    pub g: u8,
    pub avl: u8,
    pub unusable: u8,
    pub padding: u8,
}

/// KVM descriptor table register.
///
/// Corresponds to `struct kvm_dtable` in Linux.
#[derive(Debug, Clone, Copy, Default, Pod)]
#[repr(C)]
pub struct KvmDtable {
    pub base: u64,
    pub limit: u16,
    pub padding: [u16; 3],
}

/// KVM special registers.
///
/// Corresponds to `struct kvm_sregs` in Linux.
#[derive(Debug, Clone, Copy, Default, Pod)]
#[repr(C)]
pub struct KvmSregs {
    pub cs: KvmSegment,
    pub ds: KvmSegment,
    pub es: KvmSegment,
    pub fs: KvmSegment,
    pub gs: KvmSegment,
    pub ss: KvmSegment,
    pub tr: KvmSegment,
    pub ldt: KvmSegment,
    pub gdt: KvmDtable,
    pub idt: KvmDtable,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub apic_base: u64,
    pub interrupt_bitmap: [u64; 4],
}

// KVM exit reason constants (matching Linux `include/uapi/linux/kvm.h`).
pub const KVM_EXIT_UNKNOWN: u32 = 0;
pub const KVM_EXIT_EXCEPTION: u32 = 1;
pub const KVM_EXIT_IO: u32 = 2;
pub const KVM_EXIT_HYPERCALL: u32 = 3;
pub const KVM_EXIT_DEBUG: u32 = 4;
pub const KVM_EXIT_HLT: u32 = 5;
pub const KVM_EXIT_MMIO: u32 = 6;
pub const KVM_EXIT_IRQ_WINDOW_OPEN: u32 = 7;
pub const KVM_EXIT_SHUTDOWN: u32 = 8;
pub const KVM_EXIT_FAIL_ENTRY: u32 = 9;
pub const KVM_EXIT_INTR: u32 = 10;
pub const KVM_EXIT_INTERNAL_ERROR: u32 = 17;

/// I/O direction constants.
pub const KVM_EXIT_IO_IN: u8 = 0;
pub const KVM_EXIT_IO_OUT: u8 = 1;

/// KVM capability constants (matching Linux `KVM_CAP_*`).
pub const KVM_CAP_IRQCHIP: i32 = 0;
pub const KVM_CAP_HLT: i32 = 1;
pub const KVM_CAP_USER_MEMORY: i32 = 3;
pub const KVM_CAP_SET_TSS_ADDR: i32 = 4;
pub const KVM_CAP_EXT_CPUID: i32 = 7;
pub const KVM_CAP_NR_VCPUS: i32 = 9;
pub const KVM_CAP_NR_MEMSLOTS: i32 = 10;

/// Offset from the start of `kvm_run` where I/O data is stored.
/// Placed after the `KvmRun` header struct (288 bytes) with some alignment padding.
pub const KVM_RUN_IO_DATA_OFFSET: usize = 512;

/// The `kvm_run` shared memory structure.
///
/// Corresponds to `struct kvm_run` in Linux (`include/uapi/linux/kvm.h`).
/// This structure is shared between the kernel and userspace via the vCPU fd
/// mmap region. The kernel writes exit information here; userspace reads it.
///
/// We only model the header fields directly. The union portion (256 bytes)
/// and sync regs (2048 bytes) are written via Vmo::write at known offsets.
#[derive(Debug, Clone, Copy, Pod)]
#[repr(C)]
pub struct KvmRun {
    // --- "in" fields (8 bytes) ---
    pub request_interrupt_window: u8,
    pub immediate_exit: u8,
    pub padding1: [u8; 6],

    // --- "out" fields (8 bytes) ---
    pub exit_reason: u32,
    pub ready_for_interrupt_injection: u8,
    pub if_flag: u8,
    pub flags: u16,

    // --- "in/out" fields (16 bytes) ---
    pub cr8: u64,
    pub apic_base: u64,

    // --- union area (256 bytes) ---
    /// The union in `struct kvm_run` is 256 bytes. We model it as raw bytes.
    /// Individual union members are written via Vmo::write at UNION_OFFSET.
    pub union_padding: [u8; 256],
}

impl Default for KvmRun {
    fn default() -> Self {
        Self {
            request_interrupt_window: 0,
            immediate_exit: 0,
            padding1: [0; 6],
            exit_reason: 0,
            ready_for_interrupt_injection: 0,
            if_flag: 0,
            flags: 0,
            cr8: 0,
            apic_base: 0,
            union_padding: [0u8; 256],
        }
    }
}

impl KvmRun {
    /// Byte offset of the `exit_reason` field.
    pub const EXIT_REASON_OFFSET: usize = 8;

    /// Byte offset of the `cr8` field.
    pub const CR8_OFFSET: usize = 16;

    /// Byte offset of the `apic_base` field.
    pub const APIC_BASE_OFFSET: usize = 24;

    /// Byte offset of the union (I/O data, etc.).
    pub const UNION_OFFSET: usize = 32;
}

/// I/O port exit information within `kvm_run` (written at UNION_OFFSET).
#[derive(Debug, Clone, Copy, Pod)]
#[repr(C)]
pub struct KvmRunIo {
    pub direction: u8,
    pub size: u8,
    pub port: u16,
    pub count: u32,
    pub data_offset: u64,
}

/// Fail-entry exit information within `kvm_run` (written at UNION_OFFSET).
#[derive(Debug, Clone, Copy, Pod)]
#[repr(C)]
pub struct KvmRunFailEntry {
    pub hardware_entry_failure_reason: u64,
    pub cpu: u32,
    pub pad: u32,
}
