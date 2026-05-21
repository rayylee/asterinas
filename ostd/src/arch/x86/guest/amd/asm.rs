// SPDX-License-Identifier: MPL-2.0

//! SVM assembly routines for AMD SVM virtualization.
//!
//! Provides low-level assembly wrappers for SVM instructions:
//! VMRUN, VMMCALL, VMLOAD, VMSAVE, CLGI, STGI, INVLPGA,
//! and the VM entry/exit trampoline.
#![allow(dead_code)]

use core::arch::global_asm;

unsafe extern "C" {
    /// VMRUN trampoline.
    pub fn __svm_vmrun(gpr_save: *mut u8, exit_info: *mut u8, vmcb_paddr: u64) -> i32;
    /// VMMCALL.
    pub(super) fn asm_vmmcall();
    /// CLGI.
    pub(super) fn asm_clgi();
    /// STGI.
    pub(super) fn asm_stgi();
    /// INVLPGA.
    pub(super) fn asm_invlpga(addr: u64, asid: u32);
}

/// Invalidates all NPT TLB entries for all ASIDs.
///
/// # Safety
///
/// The caller must ensure NPT is active and SVM is enabled.
pub(crate) unsafe fn invlpga_all() {
    // INVLPGA with addr=0, ASID=0 flushes all TLB entries for all ASIDs.
    // SAFETY: Caller ensures SVM/NPT is active.
    unsafe {
        asm_invlpga(0, 0);
    }
}

// VMRUN trampoline for entering/exiting the guest.
//
// Input:
//   rdi = &GuestGprSaveArea
//   rsi = &SvmExitInfo (written by Rust code after return)
//   rdx = VMCB physical address
//
// The Rust code must:
//   1. Write guest RAX to VMCB offset 0x1F8 before calling
//   2. Read guest RAX from VMCB offset 0x1F8 after return
//   3. Read EXITCODE, EXITINFO1, EXITINFO2, EXITINTINFO from VMCB after return
//
// On #VMEXIT, all GPRs except RAX have guest values (saved by this trampoline).
// RAX after #VMEXIT is loaded from HSA (not guest value).
// Guest RAX is in VMCB[0x1F8] and must be read by Rust code.
global_asm!(
    ".balign 16",
    ".global __svm_vmrun",
    ".type __svm_vmrun, @function",
    "__svm_vmrun:",
    "    push rbp",
    "    push rbx",
    "    push r12",
    "    push r13",
    "    push r14",
    "    push r15",
    "    push rdi",             // [rsp+16] GuestGprSaveArea ptr
    "    push rsi",             // [rsp+8]  ExitInfo ptr (not used in asm)
    "    push rdx",             // [rsp]    VMCB paddr
    "    mov rbx, [rdi + 8]",   // guest rbx
    "    mov rcx, [rdi + 16]",  // guest rcx
    "    mov rdx, [rdi + 24]",  // guest rdx
    "    mov rsi, [rdi + 32]",  // guest rsi
    "    mov rbp, [rdi + 48]",  // guest rbp
    "    mov r8,  [rdi + 56]",  // guest r8
    "    mov r9,  [rdi + 64]",  // guest r9
    "    mov r10, [rdi + 72]",  // guest r10
    "    mov r11, [rdi + 80]",  // guest r11
    "    mov r12, [rdi + 88]",  // guest r12
    "    mov r13, [rdi + 96]",  // guest r13
    "    mov r14, [rdi + 104]", // guest r14
    "    mov r15, [rdi + 112]", // guest r15
    "    mov rdi, [rdi + 40]",  // guest rdi
    "    mov rax, [rsp]",       // VMCB paddr
    // Disable global interrupts before vmrun.
    // VMRUN automatically restores GIF on #VMEXIT.
    // vmload/vmsave are omitted: guest MSRs (LSTAR, SF_MASK, etc.)
    // are not modified, avoiding corruption from zero-initialized VMCB fields.
    "    clgi",
    "    vmrun",
    // #VMEXIT lands here. GIF=0 (cleared by hardware on #VMEXIT).
    // RAX has been restored from HSA (host RAX value).
    "    stgi",
    "    mov rax, [rsp + 16]", // rax = GuestGprSaveArea ptr
    "    mov [rax + 8], rbx",
    "    mov [rax + 16], rcx",
    "    mov [rax + 24], rdx",
    "    mov [rax + 32], rsi",
    "    mov [rax + 40], rdi",
    "    mov [rax + 48], rbp",
    "    mov [rax + 56], r8",
    "    mov [rax + 64], r9",
    "    mov [rax + 72], r10",
    "    mov [rax + 80], r11",
    "    mov [rax + 88], r12",
    "    mov [rax + 96], r13",
    "    mov [rax + 104], r14",
    "    mov [rax + 112], r15",
    "    xor eax, eax",
    "    add rsp, 3*8",
    "    pop r15",
    "    pop r14",
    "    pop r13",
    "    pop r12",
    "    pop rbx",
    "    pop rbp",
    "    ret",
    ".size __svm_vmrun, . - __svm_vmrun",
);

global_asm!(
    ".balign 16",
    ".global asm_vmmcall",
    ".type asm_vmmcall, @function",
    "asm_vmmcall:",
    "    vmmcall",
    "    ret",
    ".size asm_vmmcall, . - asm_vmmcall",
);

global_asm!(
    ".balign 16",
    ".global asm_clgi",
    ".type asm_clgi, @function",
    "asm_clgi:",
    "    clgi",
    "    ret",
    ".size asm_clgi, . - asm_clgi",
);

global_asm!(
    ".balign 16",
    ".global asm_stgi",
    ".type asm_stgi, @function",
    "asm_stgi:",
    "    stgi",
    "    ret",
    ".size asm_stgi, . - asm_stgi",
);

global_asm!(
    ".balign 16",
    ".global asm_invlpga",
    ".type asm_invlpga, @function",
    "asm_invlpga:",
    "    mov rax, rdi",
    "    mov ecx, esi",
    "    invlpga",
    "    ret",
    ".size asm_invlpga, . - asm_invlpga",
);
