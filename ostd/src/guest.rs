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
//! All VMX hardware interaction is encapsulated within OSTD behind safe APIs.
//! The kernel services layer implements the KVM-compatible user-space interface
//! using exclusively safe Rust.
//!
//! Currently only available on x86_64 with Intel VT-x support.

#[cfg(target_arch = "x86_64")]
pub use crate::arch::guest::{
    CpuidAccess, EptPageFlags, EptPageProperty, EptViolationInfo, FailEntryInfo, GuestContext,
    GuestExitReason, GuestGprSaveArea, GuestPhysMemSpace, GuestSregs, IoPortAccess, MmioAccess,
    MsrAccess,
};

#[cfg(target_arch = "x86_64")]
mod x86_impl {
    use crate::arch::guest::vmcs::Vmcs;
    use crate::arch::guest::vmexit::VmxExitInfo;
    use crate::prelude::*;
    use crate::task::disable_preempt;
    use super::*;

    /// Safe abstraction for guest-mode execution (analog of `UserMode`).
    ///
    /// An ephemeral object created per `KVM_RUN` invocation. It holds the VMCS
    /// and manages the VMX lifecycle on the current CPU. When dropped, it releases
    /// the VMX reference and clears the VMCS.
    ///
    /// `GuestMode` is `!Send` because it is bound to the current CPU.
    pub struct GuestMode {
        context: GuestContext,
        vmcs: Arc<Vmcs>,
    }

    impl !Send for GuestMode {}

    impl GuestMode {
        /// Creates a new `GuestMode` for executing a guest.
        ///
        /// This performs VMXON on the current CPU if not already active,
        /// and VMPTRLD on the given VMCS.
        ///
        /// # Arguments
        ///
        /// * `vmcs` - The VMCS for this virtual CPU.
        /// * `context` - The initial guest CPU context.
        ///
        /// # Errors
        ///
        /// Returns an error if VMXON or VMPTRLD fails.
        pub fn new(vmcs: Arc<Vmcs>, context: GuestContext) -> Result<Self> {
            // Enter VMX root operation on this CPU
            let _vmxon_frame = crate::arch::guest::vmx::vmx_enter()?;

            // Load VMCS on current CPU
            // SAFETY: We just entered VMX root mode, so VMPTRLD is valid.
            unsafe {
                vmcs.load_on_current_cpu()?;
            }

            Ok(Self { context, vmcs })
        }

        /// Creates a new `GuestMode` and initializes the VMCS fields for guest execution.
        ///
        /// This performs VMXON on the current CPU if not already active,
        /// VMPTRLD on the given VMCS, and then initializes all VMCS fields
        /// using the provided EPTP for EPT-based address translation.
        ///
        /// This should be called on the first run of a vCPU (before the VMCS
        /// has been launched). Subsequent runs should use [`new`] instead.
        ///
        /// # Errors
        ///
        /// Returns an error if VMXON, VMPTRLD, or VMCS initialization fails.
        pub fn new_initialized(
            vmcs: Arc<Vmcs>,
            context: GuestContext,
            eptp: u64,
        ) -> Result<Self> {
            let _vmxon_frame = crate::arch::guest::vmx::vmx_enter()?;

            // SAFETY: We are in VMX root mode. Load VMCS and initialize it.
            unsafe {
                vmcs.load_on_current_cpu()?;
                vmcs.initialize(eptp)?;
            }

            Ok(Self { context, vmcs })
        }

        /// Executes the guest until an exit occurs.
        ///
        /// Disables preemption for the duration. Handles CPU migration
        /// transparently (VMCLEAR on old CPU, VMPTRLD on new CPU).
        ///
        /// The method returns when an exit requires kernel attention.
        /// External interrupts are handled internally and do not cause returns
        /// to the caller.
        pub fn execute<F>(&mut self, _has_kernel_event: F) -> GuestExitReason
        where
            F: FnMut() -> bool,
        {
            let _preempt_guard = disable_preempt();

            // Ensure VMCS is loaded on current CPU (handles migration)
            // SAFETY: We are in VMX root mode and preemption is disabled.
            unsafe {
                if let Err(e) = self.vmcs.load_on_current_cpu() {
                    crate::error!("Failed to load VMCS: {:?}", e);
                    return GuestExitReason::InternalError;
                }
            }

            // Load guest context into VMCS (RIP, RSP, RFLAGS, CRs, segments)
            // SAFETY: VMCS is loaded on current CPU.
            unsafe {
                self.context.load_into_vmcs();
            }

            // Set host RIP in VMCS to the VM exit handler
            // SAFETY: VMCS is loaded. Writing HOST_RIP is safe.
            unsafe {
                unsafe extern "C" {
                    fn asm_vmx_host_rip();
                }
                crate::arch::guest::vmx::vmwrite(
                    crate::arch::guest::vmx::vmcs_field::HOST_RIP,
                    asm_vmx_host_rip as *const () as u64,
                );
            }

            // Prepare GPR save area and exit info structures
            let mut gpr_save = self.context.gprs;
            let mut exit_info = VmxExitInfo::default();

            // Determine launch flag: 0 for VMLAUNCH, nonzero for VMRESUME
            let launch_flag: u64 = if self.vmcs.is_launched() { 1 } else { 0 };

            // Enter the guest via assembly trampoline
            // SAFETY: VMCS is loaded, guest context is loaded, host state is set,
            // GPR save area is provided for the trampoline to save/restore GPRs,
            // and the guest runs in VMX non-root mode with EPT isolation.
            let entry_result = unsafe {
                __vmx_enter_guest_v2(&mut gpr_save, &mut exit_info, launch_flag)
            };

            if entry_result != 0 {
                // VM entry failed
                return GuestExitReason::FailEntry(FailEntryInfo {
                    entry_reason: exit_info.exit_reason,
                });
            }

            // Mark VMCS as launched after first successful VMLAUNCH
            if !self.vmcs.is_launched() {
                self.vmcs.mark_launched();
            }

            // Copy saved GPRs back to guest context
            self.context.gprs = gpr_save;

            // Save VMCS-accessible guest context (RIP, RSP, RFLAGS, CRs)
            // SAFETY: VMCS is loaded, VM exit just occurred.
            unsafe {
                self.context.save_from_vmcs();
            }

            // Decode the exit reason
            // SAFETY: VMCS is loaded, VM exit just occurred.
            let exit_reason = unsafe {
                crate::arch::guest::vmexit::decode_exit(
                    &exit_info,
                    self.context.gprs.rax,
                    self.context.gprs.rcx,
                    self.context.gprs.rdx,
                )
            };

            exit_reason
        }

        /// Returns a reference to the guest CPU context.
        pub fn context(&self) -> &GuestContext {
            &self.context
        }

        /// Returns a mutable reference to the guest CPU context.
        pub fn context_mut(&mut self) -> &mut GuestContext {
            &mut self.context
        }
    }

    impl Drop for GuestMode {
        fn drop(&mut self) {
            // Clear VMCS from current CPU.
            // SAFETY: We are in VMX root mode (entered in GuestMode::new).
            unsafe {
                self.vmcs.clear();
            }

            // Release VMX reference on this CPU
            crate::arch::guest::vmx::vmx_exit();
        }
    }

    unsafe extern "C" {
        /// VM entry/exit trampoline defined in asm.S.
        /// Takes: GuestGprSaveArea ptr, VmxExitInfo ptr, launch_flag (0=vmlaunch, nonzero=vmresume)
        fn __vmx_enter_guest_v2(
            gpr_save: *mut GuestGprSaveArea,
            exit_info: *mut VmxExitInfo,
            launch_flag: u64,
        ) -> i32;
    }
}

#[cfg(target_arch = "x86_64")]
pub use x86_impl::GuestMode;
