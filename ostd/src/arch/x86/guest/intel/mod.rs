// SPDX-License-Identifier: MPL-2.0

//! Intel VT-x / VMX + EPT virtualization implementation.

pub(crate) mod asm;
pub(crate) mod ept;
pub mod vmcs;
pub(crate) mod vmexit;
pub(crate) mod vmx;

// Re-export Intel-specific public types
pub use ept::{EptPageFlags, EptPageProperty};
