// SPDX-License-Identifier: MPL-2.0

//! VMX assembly routines for Intel VT-x virtualization.
//!
//! Provides low-level assembly wrappers for VMX instructions:
//! VMXON, VMXOFF, VMPTRLD, VMCLEAR, VMREAD, VMWRITE,
//! and the VM entry/exit trampoline.

use core::arch::global_asm;

// VMX basic instructions
global_asm!(
    ".balign 16",
    ".global asm_vmxon",
    ".type asm_vmxon, @function",
    "asm_vmxon:",
    "    vmxon [rdi]",
    "    setb al",          // CF=1 -> error
    "    setz cl",          // ZF=1 -> failed
    "    shl cl, 1",
    "    or al, cl",
    "    movzx eax, al",
    "    ret",
    ".size asm_vmxon, . - asm_vmxon",
);

global_asm!(
    ".balign 16",
    ".global asm_vmxoff",
    ".type asm_vmxoff, @function",
    "asm_vmxoff:",
    "    vmxoff",
    "    setb al",
    "    setz cl",
    "    shl cl, 1",
    "    or al, cl",
    "    movzx eax, al",
    "    ret",
    ".size asm_vmxoff, . - asm_vmxoff",
);

global_asm!(
    ".balign 16",
    ".global asm_vmptrld",
    ".type asm_vmptrld, @function",
    "asm_vmptrld:",
    "    vmptrld [rdi]",
    "    setb al",
    "    setz cl",
    "    shl cl, 1",
    "    or al, cl",
    "    movzx eax, al",
    "    ret",
    ".size asm_vmptrld, . - asm_vmptrld",
);

global_asm!(
    ".balign 16",
    ".global asm_vmclear",
    ".type asm_vmclear, @function",
    "asm_vmclear:",
    "    vmclear [rdi]",
    "    setb al",
    "    setz cl",
    "    shl cl, 1",
    "    or al, cl",
    "    movzx eax, al",
    "    ret",
    ".size asm_vmclear, . - asm_vmclear",
);

global_asm!(
    ".balign 16",
    ".global asm_vmread",
    ".type asm_vmread, @function",
    "asm_vmread:",
    "    vmread rax, rdi",
    "    ret",
    ".size asm_vmread, . - asm_vmread",
);

global_asm!(
    ".balign 16",
    ".global asm_vmwrite",
    ".type asm_vmwrite, @function",
    "asm_vmwrite:",
    "    vmwrite rdi, rsi",
    "    setb al",
    "    setz cl",
    "    shl cl, 1",
    "    or al, cl",
    "    movzx eax, al",
    "    ret",
    ".size asm_vmwrite, . - asm_vmwrite",
);

global_asm!(
    ".balign 16",
    ".global asm_invept",
    ".type asm_invept, @function",
    "asm_invept:",
    "    invept rdi, [rsi]",
    "    setb al",
    "    setz cl",
    "    shl cl, 1",
    "    or al, cl",
    "    movzx eax, al",
    "    ret",
    ".size asm_invept, . - asm_invept",
);

// Final clean implementation
global_asm!(
    ".balign 16",
    // Remove the broken __vmx_enter_guest symbol
    // We only use __vmx_enter_guest_v2

    ".global __vmx_enter_guest_v2",
    ".type __vmx_enter_guest_v2, @function",
    "__vmx_enter_guest_v2:",

    // Input: rdi = &GuestGprSaveArea, rsi = &VmxExitInfo, edx = launch_flag
    //   launch_flag: 0 = VMLAUNCH (first entry), nonzero = VMRESUME

    // Save host callee-saved registers
    "    push rbp",
    "    push rbx",
    "    push r12",
    "    push r13",
    "    push r14",
    "    push r15",

    // Save host pointers and launch flag on the stack
    "    push rdi",               // [rsp+48] GuestGprSaveArea ptr
    "    push rsi",               // [rsp+40] VmxExitInfo ptr
    "    push rdx",               // [rsp+32] launch flag

    // Set HOST_RSP in VMCS (RSP after pushes = current RSP)
    "    mov rdi, 0x6C14",        // HOST_RSP encoding
    "    mov rsi, rsp",
    "    vmwrite rdi, rsi",

    // Load guest GPRs from save area
    // rdi was just clobbered (used for vmwrite), but we have the save area ptr
    // on the stack at [rsp+48]
    "    mov rdi, [rsp + 48]",    // Reload GuestGprSaveArea ptr
    "    mov rax, [rdi + 0]",    // guest rax
    "    mov rbx, [rdi + 8]",    // guest rbx
    "    mov rcx, [rdi + 16]",   // guest rcx
    "    mov rdx, [rdi + 24]",   // guest rdx
    "    mov rbp, [rdi + 48]",   // guest rbp
    "    mov r8,  [rdi + 56]",   // guest r8
    "    mov r9,  [rdi + 64]",   // guest r9
    "    mov r10, [rdi + 72]",   // guest r10
    "    mov r11, [rdi + 80]",   // guest r11
    "    mov r12, [rdi + 88]",   // guest r12
    "    mov r13, [rdi + 96]",   // guest r13
    "    mov r14, [rdi + 104]",  // guest r14
    "    mov r15, [rdi + 112]",  // guest r15
    "    mov rsi, [rdi + 32]",   // guest rsi
    "    mov rdi, [rdi + 40]",   // guest rdi (last, since we needed it as base ptr)

    // VMLAUNCH or VMRESUME based on launch flag
    "    cmp qword ptr [rsp + 32], 0",
    "    jne .Lvmx_do_vmresume",
    "    vmlaunch",
    "    jmp .Lvmx_check_entry_result",
    ".Lvmx_do_vmresume:",
    "    vmresume",

    ".Lvmx_check_entry_result:",
    // If VM entry failed (CF=1 or ZF=1 after vmresume/vmlaunch), we land here
    // because the instruction failed -- no VM exit occurred.
    // But if VM entry succeeded, we never reach here.
    // If VM entry fails, RSP is still valid.

    // Recover our pointers from stack (guest GPRs are in regs but entry failed)
    "    mov rdi, [rsp + 48]",    // GuestGprSaveArea ptr
    "    mov rsi, [rsp + 40]",    // VmxExitInfo ptr

    // Save the guest GPRs back to save area
    "    mov [rdi + 0], rax",
    "    mov [rdi + 8], rbx",
    "    mov [rdi + 16], rcx",
    "    mov [rdi + 24], rdx",
    "    mov [rdi + 32], rsi",
    "    mov [rdi + 48], rbp",
    "    mov [rdi + 56], r8",
    "    mov [rdi + 64], r9",
    "    mov [rdi + 72], r10",
    "    mov [rdi + 80], r11",
    "    mov [rdi + 88], r12",
    "    mov [rdi + 96], r13",
    "    mov [rdi + 104], r14",
    "    mov [rdi + 112], r15",
    // guest rdi is gone (we overwrote it), but on failed entry that's OK.

    // Write entry failure info
    "    mov eax, 0x4400",       // VM_INSTRUCTION_ERROR
    "    vmread rax, rax",
    "    mov [rsi], eax",         // exit_reason

    // Return failure (1)
    "    mov eax, 1",
    // Clean up stack (3 pushes for ptrs + 6 callee-saves)
    "    add rsp, 3*8",           // remove ptrs + launch flag
    "    pop r15",
    "    pop r14",
    "    pop r13",
    "    pop r12",
    "    pop rbx",
    "    pop rbp",
    "    ret",

    // ---- VM exit handler ----
    ".balign 16",
    ".global asm_vmx_host_rip",
    ".type asm_vmx_host_rip, @function",
    "asm_vmx_host_rip:",
    ".Lvmx_exit_handler_v2:",
    // VM exit lands here. CPU has restored HOST_RIP and HOST_RSP from VMCS.
    // HOST_RSP points to the stack with: launch_flag, VmxExitInfo ptr, GuestGprSaveArea ptr,
    // then callee-saves.
    // Guest GPRs are in the physical registers.

    // Save all guest GPRs to the save area.
    // We need the save area pointer, which is on the stack at [rsp+48].
    // Use RSP-relative addressing to avoid clobbering any register.
    // But we can't use rdi as the base without losing guest rdi.
    //
    // Standard approach: save everything using rsp-relative addressing.
    // This is verbose but correct.

    // Save guest rax first (we need a register to hold the save area ptr)
    "    mov [rsp + 32], rax",    // Overwrite launch flag slot with guest rax
                                   // (launch flag is no longer needed)

    // Now rax is free. Load save area ptr into rax.
    "    mov rax, [rsp + 48]",    // rax = GuestGprSaveArea ptr

    // Save guest GPRs to save area
    "    mov [rax + 8], rbx",
    "    mov [rax + 16], rcx",
    "    mov [rax + 24], rdx",
    "    mov [rax + 32], rsi",
    // Skip rdi for now (we need it)
    "    mov [rax + 48], rbp",
    "    mov [rax + 56], r8",
    "    mov [rax + 64], r9",
    "    mov [rax + 72], r10",
    "    mov [rax + 80], r11",
    "    mov [rax + 88], r12",
    "    mov [rax + 96], r13",
    "    mov [rax + 104], r14",
    "    mov [rax + 112], r15",

    // Save guest rdi
    "    mov [rax + 40], rdi",

    // Now restore guest rax from the stack slot we used as temp storage
    "    mov rdx, [rsp + 32]",    // rdx = guest rax (temp)
    "    mov [rax + 0], rdx",     // save guest rax to save area

    // Now we can use rdi for VmxExitInfo
    "    mov rdi, [rsp + 40]",    // rdi = VmxExitInfo ptr

    // Read exit info from VMCS
    "    mov rsi, 0x4402",        // VM_EXIT_REASON
    "    vmread rax, rsi",
    "    mov [rdi], eax",          // Store exit_reason

    "    mov rsi, 0x4404",        // VM_EXIT_INTR_INFO
    "    vmread rax, rsi",
    "    mov [rdi + 4], eax",     // Store exit_intr_info

    "    mov rsi, 0x6400",        // EXIT_QUALIFICATION (actually at encoding 0x6400 for natural width)
    "    vmread rax, rsi",
    "    mov [rdi + 8], rax",     // Store exit_qualification

    "    mov rsi, 0x2400",        // GUEST_PHYSICAL_ADDRESS
    "    vmread rax, rsi",
    "    mov [rdi + 16], rax",    // Store guest_physical_address

    // Return success (0)
    "    xor eax, eax",

    // Clean up stack
    "    add rsp, 3*8",           // remove ptrs + launch flag
    "    pop r15",
    "    pop r14",
    "    pop r13",
    "    pop r12",
    "    pop rbx",
    "    pop rbp",
    "    ret",
    ".size __vmx_enter_guest_v2, . - __vmx_enter_guest_v2",
);
