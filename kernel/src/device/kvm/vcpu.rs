// SPDX-License-Identifier: MPL-2.0

//! KVM virtual CPU (vCPU) implementation.
//!
//! A `KvmVcpu` represents a virtual CPU within a VM. It holds the guest
//! register state, VMCS, and the `kvm_run` shared memory page.

use ostd::guest::{
    CpuidAccess, GuestContext, GuestControlBlock, GuestExitReason, GuestMode, MsrAccess,
};

use crate::{
    device::kvm::vm::KvmVm,
    prelude::*,
};

/// Size of the `kvm_run` shared memory page.
/// This must be at least as large as the Linux `struct kvm_run`.
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
}

impl KvmVcpu {
    /// Creates a new vCPU.
    pub fn new(vm: Arc<KvmVm>, vcpu_id: u32) -> Result<Self> {
        let guest_context = GuestContext::new();

        Ok(Self {
            vm,
            vcpu_id,
            guest_context: Mutex::new(guest_context),
            control_block: Mutex::new(None),
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
    /// I/O port and MMIO exits are left for userspace to handle.
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
                    // Continue guest execution
                    continue;
                }
                GuestExitReason::Msr(msr) => {
                    if self.handle_msr(msr) {
                        // Handled internally, continue guest execution
                        continue;
                    }
                    // MSR not handled internally; fall through to return to userspace
                    debug!(
                        "KVM: Unhandled MSR exit - index={:#x}, write={}",
                        msr.msr_index,
                        msr.is_write,
                    );
                    return Ok(());
                }
                GuestExitReason::Io(io_info) => {
                    debug!(
                        "KVM: I/O exit - port={:#x}, write={}, size={}, value={:#x}",
                        io_info.port,
                        io_info.is_write,
                        io_info.size,
                        io_info.value
                    );
                    return Ok(());
                }
                GuestExitReason::Hlt => {
                    debug!("KVM: HLT exit");
                    return Ok(());
                }
                GuestExitReason::Shutdown => {
                    debug!("KVM: Shutdown exit");
                    return Ok(());
                }
                _ => {
                    debug!("KVM: exit reason {:?}", exit_reason);
                    return Ok(());
                }
            }
        }
    }

    /// Handles a CPUID exit by emulating the instruction.
    ///
    /// Writes results to guest EAX/EBX/ECX/EDX and advances RIP.
    fn handle_cpuid(&self, cpuid: CpuidAccess) {
        // Use host CPUID as baseline, then override specific leaves
        let result = core::arch::x86_64::__cpuid_count(cpuid.leaf, cpuid.sub_leaf);
        let mut eax = result.eax;
        let mut ebx = result.ebx;
        let mut ecx = result.ecx;
        let mut edx = result.edx;

        // Override specific leaves for guest visibility
        match cpuid.leaf {
            0x01 => {
                // Clear VMX bit (bit 5 of ECX) since we don't expose VMX to guests.
                // Clear hypervisor bit. Set APIC present.
                ecx &= !(1 << 5); // No VMX
                ecx &= !(1 << 31); // No hypervisor
                // Mask out some features not available to guest
                edx &= !(1 << 28); // No hyper-threading
            }
            0x07 => {
                // Sub-leaf 0: clear SGX, MPX, etc.
                if cpuid.sub_leaf == 0 {
                    ebx &= !(1 << 2); // No SGX
                }
            }
            0x0B => {
                // Topology enumeration - return 0 to indicate no topology
                eax = 0;
                ebx = 0;
                ecx = 0;
                edx = 0;
            }
            0x80000001 => {
                // Extended features: clear SVM, make sure syscall available
                edx &= !(1 << 2); // No SVM
                ecx &= !(1 << 6); // No SVM lock
            }
            _ => {}
        }

        // Write results to guest context and advance RIP
        let mut ctx = self.guest_context().lock();
        ctx.gprs.rax = eax as u64;
        ctx.gprs.rbx = ebx as u64;
        ctx.gprs.rcx = ecx as u64;
        ctx.gprs.rdx = edx as u64;
        // CPUID is a 2-byte instruction; RIP is already advanced by VMX
        // (VMX advances RIP past the instruction on exit)
    }

    /// Handles an MSR exit. Returns true if handled internally.
    ///
    /// For RDMSR: writes the result to guest EDX:EAX.
    /// For WRMSR: applies the write (or ignores it for safe MSRs).
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
            // IA32_APICBASE
            0x0000001B => {
                let ctx = self.guest_context().lock();
                ctx.sregs.apic_base
            }
            // IA32_EFER
            0xC0000080 => {
                let ctx = self.guest_context().lock();
                ctx.sregs.efer
            }
            // IA32_STAR
            0xC0000081 => 0,
            // IA32_LSTAR
            0xC0000082 => 0,
            // IA32_CSTAR
            0xC0000083 => 0,
            // IA32_FMASK
            0xC0000084 => 0,
            // IA32_KERNEL_GS_BASE
            0xC0000102 => 0,
            // IA32_FS_BASE
            0xC0000100 => 0,
            // IA32_GS_BASE
            0xC0000101 => 0,
            // IA32_SYSENTER_CS
            0x00000174 => 0,
            // IA32_SYSENTER_ESP
            0x00000175 => 0,
            // IA32_SYSENTER_EIP
            0x00000176 => 0,
            // IA32_MISC_ENABLE
            0x000001A0 => 0,
            // MSR_IA32_PLATFORM_INFO
            0x000000CE => 0,
            // MSR_IA32_TSC_AUX (for RDTSCP)
            0xC0000103 => 0,
            // Unknown MSR: return 0 and log
            _ => {
                debug!("KVM: RDMSR unknown MSR {:#x}, returning 0", msr_index);
                0
            }
        };

        let mut ctx = self.guest_context().lock();
        ctx.gprs.rax = value & 0xFFFFFFFF;
        ctx.gprs.rdx = (value >> 32) & 0xFFFFFFFF;
        // RIP is advanced by VMX past the RDMSR instruction

        true
    }

    /// Handles WRMSR. Returns true if handled (including ignored).
    fn handle_wrmsr(&self, msr_index: u32, value: u64) -> bool {
        match msr_index {
            // IA32_EFER
            0xC0000080 => {
                let mut ctx = self.guest_context().lock();
                ctx.sregs.efer = value;
            }
            // IA32_APICBASE
            0x0000001B => {
                let mut ctx = self.guest_context().lock();
                ctx.sregs.apic_base = value;
            }
            // IA32_STAR, IA32_LSTAR, IA32_CSTAR, IA32_FMASK,
            // IA32_KERNEL_GS_BASE, IA32_FS_BASE, IA32_GS_BASE,
            // IA32_SYSENTER_CS/ESP/EIP, IA32_TSC_AUX
            0xC0000081 | 0xC0000082 | 0xC0000083 | 0xC0000084
            | 0xC0000100 | 0xC0000101 | 0xC0000102 | 0xC0000103
            | 0x00000174 | 0x00000175 | 0x00000176 => {
                // Silently ignore these MSR writes
            }
            // IA32_MISC_ENABLE, IA32_BIOS_UPDT_TRIG, IA32_BIOS_SIGN_ID
            0x000001A0 | 0x00000079 | 0x0000008B => {
                // Silently ignore
            }
            // IA32_TSC - writeable but we just ignore for now
            0x00000010 => {}
            // Unknown MSR
            _ => {
                debug!(
                    "KVM: WRMSR unknown MSR {:#x} = {:#x}, ignoring",
                    msr_index,
                    value
                );
            }
        }
        // RIP is advanced by VMX past the WRMSR instruction

        true
    }
}
