// SPDX-License-Identifier: MPL-2.0

//! Guest mode (virtualization) abstractions.
//!
//! This module provides safe abstractions for hardware-assisted virtualization,
//! following the same pattern as the existing `user` module:
//!
//! - [`GuestMode`] — safe guest execution (analog of `UserMode`)
//! - [`GuestContext`] — guest CPU state (analog of `UserContext`)
//! - [`GuestPhysMemSpace`] — guest physical address space (analog of `VmSpace`)
//!
//! All hardware interaction (Intel VT-x/EPT or AMD SVM/NPT) is encapsulated
//! within OSTD behind safe APIs. The kernel services layer implements the
//! KVM-compatible user-space interface using exclusively safe Rust.
//!
//! CPU vendor is detected automatically at runtime.

#[cfg(target_arch = "x86_64")]
pub use crate::arch::guest::{
    CpuidAccess, EptPageFlags, EptPageProperty, GuestContext, GuestControlBlock, GuestExitReason,
    GuestGprSaveArea, GuestPageFlags, GuestPageProperty, GuestPhysMemSpace, GuestSregs, IoPortAccess,
    MmioAccess, MsrAccess,
};

#[cfg(target_arch = "x86_64")]
mod x86_impl {
    use crate::arch::guest::vmexit::GuestExitReason;
    use crate::arch::guest::{GuestContext, GuestControlBlock};
    use crate::arch::guest::intel::vmcs::Vmcs;
    use crate::arch::guest::amd::vmcb::Vmcb;
    use crate::prelude::*;
    use crate::task::disable_preempt;
    use core::sync::atomic::{AtomicBool, Ordering};

    /// Safe abstraction for guest-mode execution (analog of `UserMode`).
    ///
    /// An ephemeral object created per `KVM_RUN` invocation. It holds the
    /// vendor-specific VMCS/VMCB and manages the VM lifecycle on the current CPU.
    /// When dropped, it releases the hypervisor reference.
    ///
    /// `GuestMode` is `!Send` because it is bound to the current CPU.
    #[allow(missing_docs)]
    pub enum GuestMode {
        Intel(IntelGuestMode),
        Amd(AmdGuestMode),
    }

    impl !Send for GuestMode {}

    impl GuestMode {
        /// Creates a new `GuestMode` for executing a guest.
        ///
        /// This performs VMXON/SVM enable on the current CPU if not already active,
        /// and loads the VMCS/VMCB for the given vCPU.
        ///
        /// # Errors
        ///
        /// Returns an error if the hardware setup fails.
        pub fn new(cb: GuestControlBlock, context: GuestContext) -> Result<Self> {
            match cb {
                GuestControlBlock::Intel(vmcs) => {
                    IntelGuestMode::new(vmcs, context).map(IntelGuestMode::into_inner)
                }
                GuestControlBlock::Amd(vmcb) => {
                    AmdGuestMode::new(vmcb, context).map(AmdGuestMode::into_inner)
                }
            }
        }

        /// Creates a new `GuestMode` and initializes VMCS/VMCB fields for guest execution.
        ///
        /// This performs hardware setup and then initializes the control structures
        /// with the provided page table pointer (EPTP for Intel, nCR3 for AMD).
        ///
        /// This should be called on the first run of a vCPU.
        ///
        /// # Errors
        ///
        /// Returns an error if hardware setup or initialization fails.
        pub fn new_initialized(
            cb: GuestControlBlock,
            context: GuestContext,
            eptp: u64,
        ) -> Result<Self> {
            match cb {
                GuestControlBlock::Intel(vmcs) => {
                    IntelGuestMode::new_initialized(vmcs, context, eptp)
                        .map(IntelGuestMode::into_inner)
                }
                GuestControlBlock::Amd(vmcb) => {
                    AmdGuestMode::new_initialized(vmcb, context, eptp)
                        .map(AmdGuestMode::into_inner)
                }
            }
        }

        /// Executes the guest until an exit occurs.
        pub fn execute<F>(&mut self, has_kernel_event: F) -> GuestExitReason
        where
            F: FnMut() -> bool,
        {
            match self {
                GuestMode::Intel(m) => m.execute(has_kernel_event),
                GuestMode::Amd(m) => m.execute(has_kernel_event),
            }
        }

        /// Returns a reference to the guest CPU context.
        pub fn context(&self) -> &GuestContext {
            match self {
                GuestMode::Intel(m) => m.context(),
                GuestMode::Amd(m) => m.context(),
            }
        }

        /// Returns a mutable reference to the guest CPU context.
        pub fn context_mut(&mut self) -> &mut GuestContext {
            match self {
                GuestMode::Intel(m) => m.context_mut(),
                GuestMode::Amd(m) => m.context_mut(),
            }
        }
    }

    /// Intel VMX-based GuestMode.
    pub struct IntelGuestMode {
        context: GuestContext,
        vmcs: Arc<Vmcs>,
    }

    impl IntelGuestMode {
        fn new(vmcs: Arc<Vmcs>, context: GuestContext) -> Result<Self> {
            let _vmxon_frame = crate::arch::guest::intel::vmx::vmx_enter()?;

            // SAFETY: We just entered VMX root mode, so VMPTRLD is valid.
            unsafe {
                vmcs.load_on_current_cpu()?;
            }

            Ok(Self { context, vmcs })
        }

        fn new_initialized(vmcs: Arc<Vmcs>, context: GuestContext, eptp: u64) -> Result<Self> {
            let _vmxon_frame = crate::arch::guest::intel::vmx::vmx_enter()?;

            // SAFETY: We are in VMX root mode.
            unsafe {
                vmcs.load_on_current_cpu()?;
                vmcs.initialize(eptp)?;
            }

            Ok(Self { context, vmcs })
        }

        fn into_inner(self) -> GuestMode {
            GuestMode::Intel(self)
        }

        fn execute<F>(&mut self, _has_kernel_event: F) -> GuestExitReason
        where
            F: FnMut() -> bool,
        {
            use crate::arch::guest::intel::vmexit::VmxExitInfo;
            use crate::arch::guest::intel::vmx::{vmcs_field, vmwrite};

            let _preempt_guard = disable_preempt();

            // SAFETY: VMX root mode is active.
            unsafe {
                if let Err(e) = self.vmcs.load_on_current_cpu() {
                    crate::error!("Failed to load VMCS: {:?}", e);
                    return GuestExitReason::InternalError;
                }
            }

            // SAFETY: VMCS is loaded on current CPU.
            unsafe {
                self.context.load_into_vmcs();
            }

            unsafe {
                unsafe extern "C" {
                    fn asm_vmx_host_rip();
                }
                vmwrite(
                    vmcs_field::HOST_RIP,
                    asm_vmx_host_rip as *const () as u64,
                );
            }

            let mut gpr_save = self.context.gprs;
            let mut exit_info = VmxExitInfo::default();
            let launch_flag: u64 = if self.vmcs.is_launched() { 1 } else { 0 };

            let entry_result = unsafe {
                crate::arch::guest::intel::asm::__vmx_enter_guest_v2(
                    &mut gpr_save,
                    &mut exit_info as *mut _ as *mut u8,
                    launch_flag,
                )
            };

            if entry_result != 0 {
                return GuestExitReason::FailEntry(crate::arch::guest::FailEntryInfo {
                    entry_reason: exit_info.exit_reason,
                });
            }

            if !self.vmcs.is_launched() {
                self.vmcs.mark_launched();
            }

            self.context.gprs = gpr_save;

            unsafe {
                self.context.save_from_vmcs();
            }

            unsafe {
                crate::arch::guest::intel::vmexit::decode_exit(
                    &exit_info,
                    self.context.gprs.rax,
                    self.context.gprs.rcx,
                    self.context.gprs.rdx,
                )
            }
        }

        fn context(&self) -> &GuestContext {
            &self.context
        }

        fn context_mut(&mut self) -> &mut GuestContext {
            &mut self.context
        }
    }

    impl Drop for IntelGuestMode {
        fn drop(&mut self) {
            // SAFETY: We are in VMX root mode (entered in GuestMode::new).
            unsafe {
                self.vmcs.clear();
            }
            crate::arch::guest::intel::vmx::vmx_exit();
        }
    }

    /// AMD SVM-based GuestMode.
    pub struct AmdGuestMode {
        context: GuestContext,
        vmcb: Arc<Vmcb>,
        /// Whether this VMCB has been initialized for guest execution.
        initialized: AtomicBool,
    }

    impl AmdGuestMode {
        fn new(vmcb: Arc<Vmcb>, context: GuestContext) -> Result<Self> {
            crate::arch::guest::amd::svm::svm_enter()?;
            vmcb.prepare_for_run()?;

            Ok(Self {
                context,
                vmcb,
                initialized: AtomicBool::new(false),
            })
        }

        fn new_initialized(vmcb: Arc<Vmcb>, context: GuestContext, nptp: u64) -> Result<Self> {
            crate::arch::guest::amd::svm::svm_enter()?;
            vmcb.prepare_for_run()?;

            // SAFETY: VMCB is valid and ready for initialization.
            unsafe {
                vmcb.initialize(nptp)?;
            }

            Ok(Self {
                context,
                vmcb,
                initialized: AtomicBool::new(true),
            })
        }

        fn into_inner(self) -> GuestMode {
            GuestMode::Amd(self)
        }

        fn execute<F>(&mut self, _has_kernel_event: F) -> GuestExitReason
        where
            F: FnMut() -> bool,
        {
            use crate::arch::guest::amd::vmcb::vmcb_offset;
            use crate::arch::guest::amd::vmexit::SvmExitInfo;

            let _preempt_guard = disable_preempt();

            // Load guest state into VMCB before VMRUN.
            // SAFETY: VMCB is valid.
            unsafe {
                self.load_into_vmcb();
            }

            let mut gpr_save = self.context.gprs;

            // Write guest RAX to VMCB[RAX] for VMRUN to load.
            // SAFETY: VMCB is valid.
            unsafe {
                self.vmcb.write_u64(vmcb_offset::RAX, gpr_save.rax);
            }

            let vmcb_paddr = self.vmcb.paddr();
            let mut exit_info = SvmExitInfo::default();

            // SAFETY: SVM is entered, VMCB is prepared, GPR save area is correct.
            let entry_result = unsafe {
                crate::arch::guest::amd::asm::__svm_vmrun(
                    &mut gpr_save as *mut _ as *mut u8,
                    &mut exit_info as *mut _ as *mut u8,
                    vmcb_paddr as u64,
                )
            };

            if entry_result != 0 {
                return GuestExitReason::FailEntry(crate::arch::guest::FailEntryInfo {
                    entry_reason: exit_info.exit_reason,
                });
            }

            // Read guest RAX from VMCB after #VMEXIT.
            // SAFETY: VMCB is valid and a VM exit just occurred.
            let guest_rax = unsafe { self.vmcb.read_u64(vmcb_offset::RAX) };
            gpr_save.rax = guest_rax;

            // Read VMCB exit info.
            unsafe {
                exit_info.exit_reason = self.vmcb.read_u32(vmcb_offset::EXITCODE);
                exit_info.exit_info1 = self.vmcb.read_u64(vmcb_offset::EXITINFO1);
                exit_info.exit_info2 = self.vmcb.read_u64(vmcb_offset::EXITINFO2);
                exit_info.exit_int_info = self.vmcb.read_u32(vmcb_offset::EXITINTINFO);
            }

            if !self.initialized.load(Ordering::Acquire) {
                self.initialized.store(true, Ordering::Release);
            }

            self.context.gprs = gpr_save;

            // Save guest state from VMCB after #VMEXIT.
            unsafe {
                self.save_from_vmcb();
            }

            unsafe {
                crate::arch::guest::amd::vmexit::decode_exit(
                    &exit_info,
                    self.context.gprs.rax,
                    self.context.gprs.rcx,
                    self.context.gprs.rdx,
                )
            }
        }

        unsafe fn load_into_vmcb(&self) {
            use crate::arch::guest::amd::vmcb::vmcb_offset;

            // SAFETY: VMCB is valid.
            unsafe {
                self.vmcb
                    .write_u64(vmcb_offset::RIP, self.context.rip);
                self.vmcb
                    .write_u64(vmcb_offset::RFLAGS, self.context.rflags);
                self.vmcb
                    .write_u64(vmcb_offset::RSP, self.context.sregs.rsp);
                self.vmcb
                    .write_u64(vmcb_offset::CR0, self.context.sregs.cr0);
                self.vmcb
                    .write_u64(vmcb_offset::CR3, self.context.sregs.cr3);
                self.vmcb
                    .write_u64(vmcb_offset::CR4, self.context.sregs.cr4);
                self.vmcb
                    .write_u64(vmcb_offset::EFER, self.context.sregs.efer);
            }
        }

        unsafe fn save_from_vmcb(&mut self) {
            use crate::arch::guest::amd::vmcb::vmcb_offset;

            // SAFETY: VMCB is valid.
            unsafe {
                self.context.rip = self.vmcb.read_u64(vmcb_offset::RIP);
                self.context.rflags = self.vmcb.read_u64(vmcb_offset::RFLAGS);
                self.context.sregs.rsp = self.vmcb.read_u64(vmcb_offset::RSP);
                self.context.sregs.cr0 = self.vmcb.read_u64(vmcb_offset::CR0);
                self.context.sregs.cr3 = self.vmcb.read_u64(vmcb_offset::CR3);
                self.context.sregs.cr4 = self.vmcb.read_u64(vmcb_offset::CR4);
                self.context.sregs.efer = self.vmcb.read_u64(vmcb_offset::EFER);
            }
        }

        fn context(&self) -> &GuestContext {
            &self.context
        }

        fn context_mut(&mut self) -> &mut GuestContext {
            &mut self.context
        }
    }

    impl Drop for AmdGuestMode {
        fn drop(&mut self) {
            crate::arch::guest::amd::svm::svm_exit();
        }
    }
}

#[cfg(target_arch = "x86_64")]
pub use x86_impl::GuestMode;
