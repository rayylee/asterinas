// SPDX-License-Identifier: MPL-2.0

//! KVM virtual CPU (vCPU) implementation.
//!
//! A `KvmVcpu` represents a virtual CPU within a VM. It holds the guest
//! register state, VMCS, and the `kvm_run` shared memory page.

use ostd::guest::{
    CpuidAccess, GuestContext, GuestControlBlock, GuestExitReason, GuestMode, IoPortAccess,
    MsrAccess,
};

use crate::{
    device::kvm::{
        ioctl::{
            KVM_EXIT_FAIL_ENTRY, KVM_EXIT_HLT, KVM_EXIT_INTERNAL_ERROR, KVM_EXIT_IO,
            KVM_EXIT_IO_OUT, KVM_EXIT_SHUTDOWN, KVM_RUN_IO_DATA_OFFSET, KvmRun, KvmRunIo,
        },
        vm::KvmVm,
    },
    prelude::*,
    vm::page_cache::{Vmo, VmoOptions},
};

/// Size of the `kvm_run` shared memory region.
/// One page is sufficient for `struct kvm_run` plus I/O data area.
pub const KVM_RUN_SIZE: usize = 4096;

/// A KVM virtual CPU.
pub struct KvmVcpu {
    /// The VM this vCPU belongs to.
    vm: Arc<KvmVm>,
    /// vCPU identifier.
    vcpu_id: u32,
    /// Guest register state.
    guest_context: Mutex<GuestContext>,
    /// Guest control block (VMCS for Intel, VMCB for AMD), lazily initialized.
    control_block: Mutex<Option<GuestControlBlock>>,
    /// Shared memory page for `kvm_run` structure, mapped to userspace.
    kvm_run_vmo: Arc<Vmo>,
}

impl KvmVcpu {
    /// Creates a new vCPU.
    pub fn new(vm: Arc<KvmVm>, vcpu_id: u32) -> Result<Self> {
        let guest_context = GuestContext::new();

        // Create the kvm_run shared memory VMO.
        let kvm_run_vmo = VmoOptions::new(KVM_RUN_SIZE).alloc()?;
        // Pre-commit the page so it is always available without page faults.
        kvm_run_vmo.commit_on(0)?;

        Ok(Self {
            vm,
            vcpu_id,
            guest_context: Mutex::new(guest_context),
            control_block: Mutex::new(None),
            kvm_run_vmo,
        })
    }

    /// Returns the guest context.
    pub fn guest_context(&self) -> &Mutex<GuestContext> {
        &self.guest_context
    }

    /// Returns the vCPU ID.
    #[expect(dead_code)]
    pub fn vcpu_id(&self) -> u32 {
        self.vcpu_id
    }

    /// Returns the `kvm_run` VMO for mmap.
    pub fn kvm_run_vmo(&self) -> &Arc<Vmo> {
        &self.kvm_run_vmo
    }

    /// Gets or creates the guest control block (VMCS or VMCB) for this vCPU.
    fn ensure_control_block(&self) -> Result<GuestControlBlock> {
        let mut cb_guard = self.control_block.lock();
        if let Some(cb) = cb_guard.as_ref() {
            return Ok(cb.clone());
        }

        let cb = if ostd::arch::guest::is_amd_cpu() {
            let vmcb = Arc::new(ostd::arch::guest::amd::vmcb::Vmcb::new()?);
            GuestControlBlock::Amd(vmcb)
        } else {
            let vmcs = Arc::new(ostd::arch::guest::intel::vmcs::Vmcs::new()?);
            GuestControlBlock::Intel(vmcs)
        };
        *cb_guard = Some(cb.clone());
        Ok(cb)
    }

    /// Executes the guest until an exit occurs (KVM_RUN).
    ///
    /// Handles CPUID and MSR exits internally by emulating the instructions.
    /// I/O port and HLT exits are written to the `kvm_run` shared page
    /// and returned to userspace for handling.
    pub fn run(&self) -> Result<()> {
        let cb = self.ensure_control_block()?;

        let eptp = self.vm.phys_mem().eptp();

        loop {
            let context = self.guest_context().lock().clone();

            let mut guest_mode = if !cb.is_launched() {
                GuestMode::new_initialized(cb.clone(), context, eptp)?
            } else {
                GuestMode::new(cb.clone(), context)?
            };
            let exit_reason = guest_mode.execute(|| false);

            // Save the updated guest context
            let updated_context = guest_mode.context().clone();
            *self.guest_context().lock() = updated_context;

            match exit_reason {
                GuestExitReason::Cpuid(cpuid) => {
                    self.handle_cpuid(cpuid);
                    continue;
                }
                GuestExitReason::Msr(msr) => {
                    if self.handle_msr(msr) {
                        continue;
                    }
                    // MSR not handled internally; return to userspace
                    self.write_simple_exit(KVM_EXIT_INTERNAL_ERROR);
                    return Ok(());
                }
                GuestExitReason::Io(io_info) => {
                    debug!(
                        "KVM: I/O exit - port={:#x}, write={}, size={}, value={:#x}",
                        io_info.port, io_info.is_write, io_info.size, io_info.value
                    );
                    self.write_io_exit(&io_info);
                    return Ok(());
                }
                GuestExitReason::Hlt => {
                    debug!("KVM: HLT exit");
                    self.write_simple_exit(KVM_EXIT_HLT);
                    return Ok(());
                }
                GuestExitReason::Shutdown => {
                    debug!("KVM: Shutdown exit");
                    self.write_simple_exit(KVM_EXIT_SHUTDOWN);
                    return Ok(());
                }
                GuestExitReason::FailEntry(info) => {
                    debug!("KVM: Fail entry - reason={:#x}", info.entry_reason);
                    self.write_fail_entry_exit(info.entry_reason as u64);
                    return Ok(());
                }
                _ => {
                    debug!("KVM: exit reason {:?}", exit_reason);
                    self.write_simple_exit(KVM_EXIT_INTERNAL_ERROR);
                    return Ok(());
                }
            }
        }
    }

    // ---- kvm_run shared memory writers ----

    /// Writes a simple exit (no extra data) to the `kvm_run` shared page.
    fn write_simple_exit(&self, exit_reason: u32) {
        let mut kvm_run = KvmRun::default();
        kvm_run.exit_reason = exit_reason;
        self.write_kvm_run(&kvm_run);
    }

    /// Writes an I/O exit to the `kvm_run` shared page.
    fn write_io_exit(&self, io_info: &IoPortAccess) {
        let direction: u8 = if io_info.is_write {
            KVM_EXIT_IO_OUT
        } else {
            0 // KVM_EXIT_IO_IN
        };

        let io = KvmRunIo {
            direction,
            size: io_info.size,
            port: io_info.port,
            count: 1,
            data_offset: KVM_RUN_IO_DATA_OFFSET as u64,
        };

        // Build the kvm_run header manually by writing individual fields
        // to avoid unsafe union access. We write the header bytes first,
        // then overlay the I/O union data.
        let mut kvm_run = KvmRun::default();
        kvm_run.exit_reason = KVM_EXIT_IO;
        self.write_kvm_run(&kvm_run);

        // Write the I/O union at UNION_OFFSET (offset 32)
        let io_bytes = io.as_bytes();
        let mut reader = VmReader::from(io_bytes).to_fallible();
        self.kvm_run_vmo
            .write(KvmRun::UNION_OFFSET, &mut reader)
            .unwrap_or_else(|e| {
                debug!("KVM: failed to write I/O union to kvm_run: {:?}", e);
            });

        // Write the I/O data value at the data_offset.
        // For OUT instructions, write the value from the guest.
        if io_info.is_write {
            let data_bytes = match io_info.size {
                1 => (io_info.value as u8).to_ne_bytes().to_vec(),
                2 => (io_info.value as u16).to_ne_bytes().to_vec(),
                4 => io_info.value.to_ne_bytes().to_vec(),
                _ => io_info.value.to_ne_bytes().to_vec(),
            };
            let mut reader = VmReader::from(&data_bytes[..io_info.size as usize]).to_fallible();
            self.kvm_run_vmo
                .write(KVM_RUN_IO_DATA_OFFSET, &mut reader)
                .unwrap_or_else(|e| {
                    debug!("KVM: failed to write I/O data to kvm_run: {:?}", e);
                });
        }
    }

    /// Writes a fail-entry exit to the `kvm_run` shared page.
    fn write_fail_entry_exit(&self, hardware_entry_failure_reason: u64) {
        let mut kvm_run = KvmRun::default();
        kvm_run.exit_reason = KVM_EXIT_FAIL_ENTRY;
        self.write_kvm_run(&kvm_run);

        // Write fail_entry fields at the union offset
        let mut buf = [0u8; 12];
        buf[..8].copy_from_slice(&hardware_entry_failure_reason.to_ne_bytes());
        let mut reader = VmReader::from(&buf[..12]).to_fallible();
        self.kvm_run_vmo
            .write(KvmRun::UNION_OFFSET, &mut reader)
            .unwrap_or_else(|e| {
                debug!("KVM: failed to write fail_entry data to kvm_run: {:?}", e);
            });
    }

    /// Writes a `KvmRun` struct to the shared memory page.
    fn write_kvm_run(&self, kvm_run: &KvmRun) {
        let bytes = kvm_run.as_bytes();
        let mut reader = VmReader::from(bytes).to_fallible();
        self.kvm_run_vmo
            .write(0, &mut reader)
            .unwrap_or_else(|e| {
                debug!("KVM: failed to write kvm_run: {:?}", e);
            });
    }

    // ---- CPUID / MSR emulation ----

    /// Handles a CPUID exit by emulating the instruction.
    fn handle_cpuid(&self, cpuid: CpuidAccess) {
        let result = core::arch::x86_64::__cpuid_count(cpuid.leaf, cpuid.sub_leaf);
        let mut eax = result.eax;
        let mut ebx = result.ebx;
        let mut ecx = result.ecx;
        let mut edx = result.edx;

        match cpuid.leaf {
            0x01 => {
                ecx &= !(1 << 5); // No VMX
                ecx &= !(1 << 31); // No hypervisor
                edx &= !(1 << 28); // No hyper-threading
            }
            0x07 => {
                if cpuid.sub_leaf == 0 {
                    ebx &= !(1 << 2); // No SGX
                }
            }
            0x0B => {
                eax = 0;
                ebx = 0;
                ecx = 0;
                edx = 0;
            }
            0x80000001 => {
                edx &= !(1 << 2); // No SVM
                ecx &= !(1 << 6); // No SVM lock
            }
            _ => {}
        }

        let mut ctx = self.guest_context().lock();
        ctx.gprs.rax = eax as u64;
        ctx.gprs.rbx = ebx as u64;
        ctx.gprs.rcx = ecx as u64;
        ctx.gprs.rdx = edx as u64;
    }

    /// Handles an MSR exit. Returns true if handled internally.
    fn handle_msr(&self, msr: MsrAccess) -> bool {
        if msr.is_write {
            self.handle_wrmsr(msr.msr_index, msr.value)
        } else {
            self.handle_rdmsr(msr.msr_index)
        }
    }

    /// Handles RDMSR by writing the result to guest EDX:EAX.
    fn handle_rdmsr(&self, msr_index: u32) -> bool {
        let value = match msr_index {
            0x0000001B => {
                let ctx = self.guest_context().lock();
                ctx.sregs.apic_base
            }
            0xC0000080 => {
                let ctx = self.guest_context().lock();
                ctx.sregs.efer
            }
            0xC0000081 | 0xC0000082 | 0xC0000083 | 0xC0000084 => 0,
            0xC0000100 | 0xC0000101 | 0xC0000102 | 0xC0000103 => 0,
            0x00000174 | 0x00000175 | 0x00000176 => 0,
            0x000001A0 | 0x000000CE => 0,
            _ => {
                debug!("KVM: RDMSR unknown MSR {:#x}, returning 0", msr_index);
                0
            }
        };

        let mut ctx = self.guest_context().lock();
        ctx.gprs.rax = value & 0xFFFFFFFF;
        ctx.gprs.rdx = (value >> 32) & 0xFFFFFFFF;

        true
    }

    /// Handles WRMSR. Returns true if handled (including ignored).
    fn handle_wrmsr(&self, msr_index: u32, value: u64) -> bool {
        match msr_index {
            0xC0000080 => {
                let mut ctx = self.guest_context().lock();
                // On AMD, ensure SVME bit stays set for SVM to work
                let efer = if ostd::arch::guest::is_amd_cpu() {
                    value | (1 << 12) // SVME
                } else {
                    value
                };
                ctx.sregs.efer = efer;
            }
            0x0000001B => {
                let mut ctx = self.guest_context().lock();
                ctx.sregs.apic_base = value;
            }
            0xC0000081 | 0xC0000082 | 0xC0000083 | 0xC0000084
            | 0xC0000100 | 0xC0000101 | 0xC0000102 | 0xC0000103
            | 0x00000174 | 0x00000175 | 0x00000176 => {}
            0x000001A0 | 0x00000079 | 0x0000008B => {}
            0x00000010 => {}
            _ => {
                debug!("KVM: WRMSR unknown MSR {:#x} = {:#x}, ignoring", msr_index, value);
            }
        }

        true
    }
}
