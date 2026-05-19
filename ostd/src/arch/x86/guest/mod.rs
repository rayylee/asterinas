// SPDX-License-Identifier: MPL-2.0

//! Architecture-specific guest (virtualization) module for x86_64.
//!
//! Provides VMX-based virtualization abstractions: GuestMode, GuestContext,
//! GuestPhysMemSpace, and related types.

pub(crate) mod asm;
pub(crate) mod context;
pub(crate) mod ept;
pub mod vmcs;
pub(crate) mod vmexit;
pub(crate) mod vmx;

// Re-export public types
pub use context::{GuestContext, GuestGprSaveArea, GuestSregs};
pub use ept::{EptPageFlags, EptPageProperty, GuestPhysMemSpace};
pub use vmexit::{
    CpuidAccess, EptViolationInfo, FailEntryInfo, GuestExitReason, IoPortAccess, MmioAccess,
    MsrAccess,
};
