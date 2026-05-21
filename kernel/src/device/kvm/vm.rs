// SPDX-License-Identifier: MPL-2.0

//! KVM virtual machine (VM) implementation.
//!
//! A `KvmVm` represents a virtual machine created by `KVM_CREATE_VM`.
//! It holds the guest physical address space and a list of vCPUs.

use core::fmt::Display;

use ostd::guest::{GuestDtable, GuestPageFlags, GuestPageProperty, GuestPhysMemSpace, GuestSegment};
use ostd::task::{disable_preempt, Task};

use crate::{
    device::kvm::vcpu::KvmVcpu,
    events::IoEvents,
    fs::{
        file::{AccessMode, FileLike, Mappable, file_table::FdFlags},
        pseudofs::AnonInodeFs,
        vfs::path::Path,
    },
    prelude::*,
    process::signal::{PollHandle, Pollable},
    util::ioctl::{RawIoctl, dispatch_ioctl},
};

const PAGE_SIZE: u64 = 4096;

/// A KVM virtual machine.
pub struct KvmVm {
    /// Guest physical address space backed by EPT.
    phys_mem: Arc<GuestPhysMemSpace>,
    /// vCPUs belonging to this VM.
    vcpus: Mutex<Vec<Arc<KvmVcpu>>>,
    /// Memory region slots.
    mem_regions: Mutex<Vec<super::ioctl::KvmUserspaceMemoryRegion>>,
    /// TSS address set by KVM_SET_TSS_ADDR.
    tss_addr: Mutex<Option<u64>>,
}

impl KvmVm {
    /// Creates a new KVM VM.
    pub fn new() -> Result<Arc<Self>> {
        let phys_mem = Arc::new(GuestPhysMemSpace::new());
        Ok(Arc::new(Self {
            phys_mem,
            vcpus: Mutex::new(Vec::new()),
            mem_regions: Mutex::new(Vec::new()),
            tss_addr: Mutex::new(None),
        }))
    }

    /// Registers this VM as a file descriptor and returns the fd number.
    pub fn register_fd(self: &Arc<Self>) -> Result<u32> {
        let vm_file = KvmVmFile::new(self.clone());
        let task = Task::current().unwrap();
        let thread_local = task.as_thread_local().unwrap();
        let file_table = thread_local.borrow_file_table();
        let mut file_table_locked = file_table.unwrap().write();
        let fd: u32 = file_table_locked.insert(Arc::new(vm_file), FdFlags::empty()).into();
        Ok(fd)
    }

    /// Returns the guest physical address space.
    pub fn phys_mem(&self) -> &Arc<GuestPhysMemSpace> {
        &self.phys_mem
    }

    /// Sets a user memory region, mapping user memory into the guest EPT.
    pub fn set_user_memory_region(
        &self,
        region: &super::ioctl::KvmUserspaceMemoryRegion,
    ) -> Result<()> {
        if region.memory_size == 0 {
            return Ok(());
        }

        // Map each page from the user VmSpace into the guest EPT.
        let preempt_guard = disable_preempt();
        let prop = GuestPageProperty {
            flags: GuestPageFlags::RWX,
            mem_type: 6, // WB
        };

        let task = Task::current().unwrap();
        let thread_local = task.as_thread_local().unwrap();
        let vmar_borrow = thread_local.vmar().borrow();
        let vm_space = vmar_borrow.as_ref().unwrap().vm_space();

        let gpa_range = region.guest_phys_addr..(region.guest_phys_addr + region.memory_size);
        let mut ept_cursor = self.phys_mem.cursor_mut(&preempt_guard, &gpa_range)?;

        let va_range =
            region.userspace_addr as usize..(region.userspace_addr + region.memory_size) as usize;
        let mut va_cursor = vm_space.cursor(&preempt_guard, &va_range)?;

        let mut gpa = region.guest_phys_addr;
        loop {
            let (_, item) = va_cursor.query()?;
            match item {
                Some(ref item) => {
                    ept_cursor.map_vm_item(item, 1, prop);
                }
                None => {
                    // Page not yet mapped in user space. Map a zero page as placeholder.
                    ept_cursor.map_zero(1, prop);
                }
            }

            gpa += PAGE_SIZE;
            if gpa >= region.guest_phys_addr + region.memory_size {
                break;
            }
            let _ = va_cursor.find_next(1);
            // ept_cursor advances automatically after map()
        }

        self.mem_regions.lock().push(*region);
        Ok(())
    }

    /// Creates a new vCPU for this VM.
    pub fn create_vcpu(self: &Arc<Self>, vcpu_id: u32) -> Result<u32> {
        let vcpu = KvmVcpu::new(self.clone(), vcpu_id)?;
        let vcpu_arc = Arc::new(vcpu);
        self.vcpus.lock().push(vcpu_arc.clone());

        let vcpu_file = KvmVcpuFile::new(vcpu_arc);
        let task = Task::current().unwrap();
        let thread_local = AsThreadLocal::as_thread_local(&task).unwrap();
        let file_table = thread_local.borrow_file_table();
        let mut file_table_locked = file_table.unwrap().write();
        let fd: u32 = file_table_locked.insert(Arc::new(vcpu_file), FdFlags::empty()).into();
        Ok(fd)
    }
}

/// File handle for a KVM VM.
struct KvmVmFile {
    vm: Arc<KvmVm>,
    /// The pseudo path associated with this file.
    pseudo_path: Path,
}

impl KvmVmFile {
    fn new(vm: Arc<KvmVm>) -> Self {
        let pseudo_path = AnonInodeFs::new_path(|_| "anon_inode:kvm-vm".to_string());
        Self { vm, pseudo_path }
    }
}

impl Pollable for KvmVmFile {
    fn poll(&self, mask: IoEvents, _poller: Option<&mut PollHandle>) -> IoEvents {
        mask & (IoEvents::IN | IoEvents::OUT)
    }
}

impl FileLike for KvmVmFile {
    fn ioctl(&self, raw_ioctl: RawIoctl) -> Result<i32> {
        use super::ioctl::*;

        dispatch_ioctl!(match raw_ioctl {
            cmd @ CreateVcpu => {
                let vcpu_id = cmd.get() as u32;
                let fd = self.vm.create_vcpu(vcpu_id)?;
                Ok(fd as i32)
            }
            cmd @ SetUserMemoryRegion => {
                let region = cmd.read()?;
                self.vm.set_user_memory_region(&region)?;
                Ok(0)
            }
            cmd @ SetTssAddr => {
                let addr = cmd.get();
                *self.vm.tss_addr.lock() = Some(addr);
                Ok(0)
            }
            _cmd @ SetIdentityMapAddr => {
                // No-op: just acknowledge the ioctl.
                Ok(0)
            }
            _ => return_errno_with_message!(Errno::ENOTTY, "unknown KVM VM ioctl"),
        })
    }

    fn access_mode(&self) -> AccessMode {
        AccessMode::O_RDWR
    }

    fn path(&self) -> &Path {
        &self.pseudo_path
    }

    fn dump_proc_fdinfo(self: Arc<Self>, fd_flags: FdFlags) -> Box<dyn Display> {
        struct FdInfo {
            inner: Arc<KvmVmFile>,
            fd_flags: FdFlags,
        }

        impl Display for FdInfo {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                let mut flags = self.inner.access_mode() as u32;
                if self.fd_flags.contains(FdFlags::CLOEXEC) {
                    flags |= crate::fs::file::CreationFlags::O_CLOEXEC.bits();
                }
                writeln!(f, "pos:\t{}", 0)?;
                writeln!(f, "flags:\t0{:o}", flags)?;
                writeln!(f, "mnt_id:\t{}", AnonInodeFs::mount_node().id())?;
                writeln!(f, "ino:\t{}", AnonInodeFs::shared_inode().ino())
            }
        }

        Box::new(FdInfo {
            inner: self,
            fd_flags,
        })
    }
}

// ---- Segment register conversion functions ----

/// Converts a `GuestSegment` (VMCS ar_bytes format) to a `KvmSegment` (Linux ABI).
fn guest_seg_to_kvm(seg: &GuestSegment) -> super::ioctl::KvmSegment {
    let ar = seg.ar_bytes;
    super::ioctl::KvmSegment {
        base: seg.base,
        limit: seg.limit,
        selector: seg.selector,
        type_: (ar & 0xF) as u8,
        present: ((ar >> 7) & 1) as u8,
        dpl: ((ar >> 5) & 3) as u8,
        db: ((ar >> 14) & 1) as u8,
        s: ((ar >> 4) & 1) as u8,
        l: ((ar >> 13) & 1) as u8,
        g: ((ar >> 15) & 1) as u8,
        avl: ((ar >> 12) & 1) as u8,
        unusable: ((ar >> 16) & 1) as u8,
        padding: 0,
    }
}

/// Converts a `KvmSegment` (Linux ABI) to a `GuestSegment` (VMCS ar_bytes format).
fn kvm_seg_to_guest(kvm: &super::ioctl::KvmSegment) -> GuestSegment {
    let ar_bytes = (kvm.type_ as u32 & 0xF)
        | ((kvm.s as u32 & 1) << 4)
        | ((kvm.dpl as u32 & 3) << 5)
        | ((kvm.present as u32 & 1) << 7)
        | ((kvm.avl as u32 & 1) << 12)
        | ((kvm.l as u32 & 1) << 13)
        | ((kvm.db as u32 & 1) << 14)
        | ((kvm.g as u32 & 1) << 15)
        | ((kvm.unusable as u32 & 1) << 16);
    GuestSegment {
        base: kvm.base,
        limit: kvm.limit,
        selector: kvm.selector,
        ar_bytes,
    }
}

/// Converts a `GuestDtable` to a `KvmDtable`.
fn guest_dtable_to_kvm(dt: &GuestDtable) -> super::ioctl::KvmDtable {
    super::ioctl::KvmDtable {
        base: dt.base,
        limit: dt.limit,
        padding: [0; 3],
    }
}

/// Converts a `KvmDtable` to a `GuestDtable`.
fn kvm_dtable_to_guest(kvm: &super::ioctl::KvmDtable) -> GuestDtable {
    GuestDtable {
        base: kvm.base,
        limit: kvm.limit,
    }
}
struct KvmVcpuFile {
    vcpu: Arc<KvmVcpu>,
    /// The pseudo path associated with this file.
    pseudo_path: Path,
}

impl KvmVcpuFile {
    fn new(vcpu: Arc<KvmVcpu>) -> Self {
        let pseudo_path = AnonInodeFs::new_path(|_| "anon_inode:kvm-vcpu".to_string());
        Self { vcpu, pseudo_path }
    }
}

impl Pollable for KvmVcpuFile {
    fn poll(&self, mask: IoEvents, _poller: Option<&mut PollHandle>) -> IoEvents {
        mask & (IoEvents::IN | IoEvents::OUT)
    }
}

impl FileLike for KvmVcpuFile {
    fn ioctl(&self, raw_ioctl: RawIoctl) -> Result<i32> {
        use super::ioctl::*;

        dispatch_ioctl!(match raw_ioctl {
            _cmd @ Run => {
                self.vcpu.run()?;
                Ok(0)
            }
            cmd @ GetRegs => {
                let ctx = self.vcpu.guest_context().lock();
                let regs = KvmRegs {
                    rax: ctx.gprs.rax,
                    rbx: ctx.gprs.rbx,
                    rcx: ctx.gprs.rcx,
                    rdx: ctx.gprs.rdx,
                    rsi: ctx.gprs.rsi,
                    rdi: ctx.gprs.rdi,
                    rsp: ctx.sregs.rsp,
                    rbp: ctx.gprs.rbp,
                    r8: ctx.gprs.r8,
                    r9: ctx.gprs.r9,
                    r10: ctx.gprs.r10,
                    r11: ctx.gprs.r11,
                    r12: ctx.gprs.r12,
                    r13: ctx.gprs.r13,
                    r14: ctx.gprs.r14,
                    r15: ctx.gprs.r15,
                    rip: ctx.rip,
                    rflags: ctx.rflags,
                };
                cmd.write(&regs)?;
                Ok(0)
            }
            cmd @ SetRegs => {
                let regs: KvmRegs = cmd.read()?;
                let mut ctx = self.vcpu.guest_context().lock();
                ctx.gprs.rax = regs.rax;
                ctx.gprs.rbx = regs.rbx;
                ctx.gprs.rcx = regs.rcx;
                ctx.gprs.rdx = regs.rdx;
                ctx.gprs.rsi = regs.rsi;
                ctx.gprs.rdi = regs.rdi;
                ctx.sregs.rsp = regs.rsp;
                ctx.gprs.rbp = regs.rbp;
                ctx.gprs.r8 = regs.r8;
                ctx.gprs.r9 = regs.r9;
                ctx.gprs.r10 = regs.r10;
                ctx.gprs.r11 = regs.r11;
                ctx.gprs.r12 = regs.r12;
                ctx.gprs.r13 = regs.r13;
                ctx.gprs.r14 = regs.r14;
                ctx.gprs.r15 = regs.r15;
                ctx.rip = regs.rip;
                ctx.rflags = regs.rflags;
                Ok(0)
            }
            cmd @ GetSregs => {
                let ctx = self.vcpu.guest_context().lock();
                let sregs = KvmSregs {
                    cs: guest_seg_to_kvm(&ctx.sregs.cs),
                    ds: guest_seg_to_kvm(&ctx.sregs.ds),
                    es: guest_seg_to_kvm(&ctx.sregs.es),
                    fs: guest_seg_to_kvm(&ctx.sregs.fs),
                    gs: guest_seg_to_kvm(&ctx.sregs.gs),
                    ss: guest_seg_to_kvm(&ctx.sregs.ss),
                    tr: guest_seg_to_kvm(&ctx.sregs.tr),
                    ldt: guest_seg_to_kvm(&ctx.sregs.ldt),
                    gdt: guest_dtable_to_kvm(&ctx.sregs.gdt),
                    idt: guest_dtable_to_kvm(&ctx.sregs.idt),
                    cr0: ctx.sregs.cr0,
                    cr2: ctx.sregs.cr2,
                    cr3: ctx.sregs.cr3,
                    cr4: ctx.sregs.cr4,
                    cr8: 0,
                    efer: ctx.sregs.efer,
                    apic_base: ctx.sregs.apic_base,
                    interrupt_bitmap: [0; 4],
                };
                cmd.write(&sregs)?;
                Ok(0)
            }
            cmd @ SetSregs => {
                let sregs: KvmSregs = cmd.read()?;
                let mut ctx = self.vcpu.guest_context().lock();
                ctx.sregs.cs = kvm_seg_to_guest(&sregs.cs);
                ctx.sregs.ds = kvm_seg_to_guest(&sregs.ds);
                ctx.sregs.es = kvm_seg_to_guest(&sregs.es);
                ctx.sregs.fs = kvm_seg_to_guest(&sregs.fs);
                ctx.sregs.gs = kvm_seg_to_guest(&sregs.gs);
                ctx.sregs.ss = kvm_seg_to_guest(&sregs.ss);
                ctx.sregs.tr = kvm_seg_to_guest(&sregs.tr);
                ctx.sregs.ldt = kvm_seg_to_guest(&sregs.ldt);
                ctx.sregs.gdt = kvm_dtable_to_guest(&sregs.gdt);
                ctx.sregs.idt = kvm_dtable_to_guest(&sregs.idt);
                ctx.sregs.cr0 = sregs.cr0;
                ctx.sregs.cr2 = sregs.cr2;
                ctx.sregs.cr3 = sregs.cr3;
                ctx.sregs.cr4 = sregs.cr4;
                ctx.sregs.efer = sregs.efer;
                ctx.sregs.apic_base = sregs.apic_base;
                Ok(0)
            }
            _ => return_errno_with_message!(Errno::ENOTTY, "unknown KVM vCPU ioctl"),
        })
    }

    fn access_mode(&self) -> AccessMode {
        AccessMode::O_RDWR
    }

    fn mappable(&self) -> Result<Mappable> {
        Ok(Mappable::Vmo(self.vcpu.kvm_run_vmo().clone()))
    }

    fn path(&self) -> &Path {
        &self.pseudo_path
    }

    fn dump_proc_fdinfo(self: Arc<Self>, fd_flags: FdFlags) -> Box<dyn Display> {
        struct FdInfo {
            inner: Arc<KvmVcpuFile>,
            fd_flags: FdFlags,
        }

        impl Display for FdInfo {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                let mut flags = self.inner.access_mode() as u32;
                if self.fd_flags.contains(FdFlags::CLOEXEC) {
                    flags |= crate::fs::file::CreationFlags::O_CLOEXEC.bits();
                }
                writeln!(f, "pos:\t{}", 0)?;
                writeln!(f, "flags:\t0{:o}", flags)?;
                writeln!(f, "mnt_id:\t{}", AnonInodeFs::mount_node().id())?;
                writeln!(f, "ino:\t{}", AnonInodeFs::shared_inode().ino())
            }
        }

        Box::new(FdInfo {
            inner: self,
            fd_flags,
        })
    }
}
