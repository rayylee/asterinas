// SPDX-License-Identifier: MPL-2.0

//! AMD SVM / NPT virtualization implementation.

pub(crate) mod asm;
pub(crate) mod npt;
pub(crate) mod svm;
pub mod vmcb;
pub(crate) mod vmexit;

// Re-export public types
#[allow(unused_imports)]
pub use npt::{NptPageFlags, NptPageProperty};
#[allow(unused_imports)]
pub use svm::detect_svm_capabilities;
