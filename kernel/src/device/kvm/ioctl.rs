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
pub type SetUserMemoryRegion = ioc!(KVM_SET_USER_MEMORY_REGION, 0xAE46, InData<KvmUserspaceMemoryRegion>);

// vCPU fd ioctls
pub type Run = ioc!(KVM_RUN, 0xAE80, NoData);
pub type GetRegs = ioc!(KVM_GET_REGS, 0xAE81, OutData<KvmRegs>);
pub type SetRegs = ioc!(KVM_SET_REGS, 0xAE82, InData<KvmRegs>);
pub type GetSregs = ioc!(KVM_GET_SREGS, 0xAE83, OutData<KvmSregs>);
pub type SetSregs = ioc!(KVM_SET_SREGS, 0xAE84, InData<KvmSregs>);

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
