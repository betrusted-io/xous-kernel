#if __riscv_xlen == 64
# define STORE    sd
# define LOAD     ld
# define LOG_REGBYTES 3
#else
# define STORE    sw
# define LOAD     lw
# define LOG_REGBYTES 2
#endif
#define REGBYTES (1 << LOG_REGBYTES)

/*
    Entry point of all programs (_start).

    It initializes DWARF call frame information, the stack pointer, the
    frame pointer (needed for closures to work in start_rust) and the global
    pointer. Then it calls _start_rust.
*/


/* Make sure there is an abort when linking */
.section .text.init, "ax"
.globl abort
abort:
    j abort

.section .text.init, "ax"

.global _start

_start:
    .cfi_startproc
    .cfi_undefined ra

    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop

    // Set frame pointer
    add s0, sp, zero

    // Set trap handler
    la t0, _start_trap
    csrw stvec, t0

    jal zero, _start_rust

    .cfi_endproc


/*
    Trap entry point (_start_trap)

    Saves caller saved registers ra, t0..6, a0..7, calls _start_trap_rust,
    restores caller saved registers and then returns.
*/
.section .trap, "ax"
.global _start_trap

_start_trap:
    csrw        sscratch, sp
    li          sp, 0x00801000

    STORE       x1, 0*REGBYTES(sp)
    // Skip SP for now
    STORE       x3, 2*REGBYTES(sp)
    STORE       x4, 3*REGBYTES(sp)
    STORE       x5, 4*REGBYTES(sp)
    STORE       x6, 5*REGBYTES(sp)
    STORE       x7, 6*REGBYTES(sp)
    STORE       x8, 7*REGBYTES(sp)
    STORE       x9, 8*REGBYTES(sp)
    STORE       x10, 9*REGBYTES(sp)
    STORE       x11, 10*REGBYTES(sp)
    STORE       x12, 11*REGBYTES(sp)
    STORE       x13, 12*REGBYTES(sp)
    STORE       x14, 13*REGBYTES(sp)
    STORE       x15, 14*REGBYTES(sp)
    STORE       x16, 15*REGBYTES(sp)
    STORE       x17, 16*REGBYTES(sp)
    STORE       x18, 17*REGBYTES(sp)
    STORE       x19, 18*REGBYTES(sp)
    STORE       x20, 19*REGBYTES(sp)
    STORE       x21, 20*REGBYTES(sp)
    STORE       x22, 21*REGBYTES(sp)
    STORE       x23, 22*REGBYTES(sp)
    STORE       x24, 23*REGBYTES(sp)
    STORE       x25, 24*REGBYTES(sp)
    STORE       x26, 25*REGBYTES(sp)
    STORE       x27, 26*REGBYTES(sp)
    STORE       x28, 27*REGBYTES(sp)
    STORE       x29, 28*REGBYTES(sp)
    STORE       x30, 29*REGBYTES(sp)
    STORE       x31, 30*REGBYTES(sp)

    // Save SATP as well
    csrr        t0, satp
    STORE       t0, 31*REGBYTES(sp)

    // Save SSTATUS as well
    csrr        t0, sstatus
    STORE       t0, 32*REGBYTES(sp)

    // Save SEPC as well
    csrr        t0, sepc
    STORE       t0, 33*REGBYTES(sp)

    // Save SP
    csrr        t0, sscratch
    STORE       t0, 1*REGBYTES(sp)

    // Restore a default SATP
    li          sp, 0x003ffffc
    j           _start_trap_rust

.global return_to_user
return_to_user:
    move        sp, a0

    LOAD        x1, 0*REGBYTES(sp)
    // Skip SP for now
    LOAD        x3, 2*REGBYTES(sp)
    LOAD        x4, 3*REGBYTES(sp)
    LOAD        x5, 4*REGBYTES(sp)
    LOAD        x6, 5*REGBYTES(sp)
    LOAD        x7, 6*REGBYTES(sp)
    LOAD        x8, 7*REGBYTES(sp)
    LOAD        x9, 8*REGBYTES(sp)
    LOAD        x10, 9*REGBYTES(sp)
    LOAD        x11, 10*REGBYTES(sp)
    LOAD        x12, 11*REGBYTES(sp)
    LOAD        x13, 12*REGBYTES(sp)
    LOAD        x14, 13*REGBYTES(sp)
    LOAD        x15, 14*REGBYTES(sp)
    LOAD        x16, 15*REGBYTES(sp)
    LOAD        x17, 16*REGBYTES(sp)
    LOAD        x18, 17*REGBYTES(sp)
    LOAD        x19, 18*REGBYTES(sp)
    LOAD        x20, 19*REGBYTES(sp)
    LOAD        x21, 20*REGBYTES(sp)
    LOAD        x22, 21*REGBYTES(sp)
    LOAD        x23, 22*REGBYTES(sp)
    LOAD        x24, 23*REGBYTES(sp)
    LOAD        x25, 24*REGBYTES(sp)
    LOAD        x26, 25*REGBYTES(sp)
    LOAD        x27, 26*REGBYTES(sp)
    LOAD        x28, 27*REGBYTES(sp)
    LOAD        x29, 28*REGBYTES(sp)
    LOAD        x30, 29*REGBYTES(sp)
    LOAD        x31, 30*REGBYTES(sp)

    // Restore SP
    LOAD        x2, 1*REGBYTES(sp)
    sret

.global xous_syscall_return_rust
xous_syscall_return_rust:

    LOAD        a7, 7*REGBYTES(a0)
    LOAD        a6, 6*REGBYTES(a0)
    LOAD        a5, 5*REGBYTES(a0)
    LOAD        a4, 4*REGBYTES(a0)
    LOAD        a3, 3*REGBYTES(a0)
    LOAD        a2, 2*REGBYTES(a0)
    LOAD        a1, 1*REGBYTES(a0)
    LOAD        a0, 0*REGBYTES(a0)

    li          sp, 0x00801000
    LOAD        t0, 1*REGBYTES(sp)
    csrw        sscratch, t0

    LOAD        x1, 0*REGBYTES(sp)
    // Skip SP for now
    LOAD        x3, 2*REGBYTES(sp)
    LOAD        x4, 3*REGBYTES(sp)
    LOAD        x5, 4*REGBYTES(sp)
    LOAD        x6, 5*REGBYTES(sp)
    LOAD        x7, 6*REGBYTES(sp)
    LOAD        x8, 7*REGBYTES(sp)
    LOAD        x9, 8*REGBYTES(sp)
    // Skip argument registers
    LOAD        x18, 17*REGBYTES(sp)
    LOAD        x19, 18*REGBYTES(sp)
    LOAD        x20, 19*REGBYTES(sp)
    LOAD        x21, 20*REGBYTES(sp)
    LOAD        x22, 21*REGBYTES(sp)
    LOAD        x23, 22*REGBYTES(sp)
    LOAD        x24, 23*REGBYTES(sp)
    LOAD        x25, 24*REGBYTES(sp)
    LOAD        x26, 25*REGBYTES(sp)
    LOAD        x27, 26*REGBYTES(sp)
    LOAD        x28, 27*REGBYTES(sp)
    LOAD        x29, 28*REGBYTES(sp)
    LOAD        x30, 29*REGBYTES(sp)
    LOAD        x31, 30*REGBYTES(sp)

    // Save SP
    csrr        t0, sscratch
    LOAD        x2, 1*REGBYTES(sp)
    sret

.global xous_syscall_resume_context
xous_syscall_resume_context:

    move        sp, a0
    LOAD        t0, 1*REGBYTES(sp)
    csrw        sscratch, t0

    // Save SATP as well
    LOAD        t0, 31*REGBYTES(sp)
    csrw        satp, t0
    sfence.vma

    // Save SSTATUS as well
    LOAD        t0, 32*REGBYTES(sp)
    csrw        sstatus, t0

    // Save SEPC as well
    LOAD        t0, 33*REGBYTES(sp)
    csrw        sepc, t0

    LOAD        x1, 0*REGBYTES(sp)
    // Skip SP for now
    LOAD        x3, 2*REGBYTES(sp)
    LOAD        x4, 3*REGBYTES(sp)
    LOAD        x5, 4*REGBYTES(sp)
    LOAD        x6, 5*REGBYTES(sp)
    LOAD        x7, 6*REGBYTES(sp)
    LOAD        x8, 7*REGBYTES(sp)
    LOAD        x9, 8*REGBYTES(sp)
    LOAD        x10, 9*REGBYTES(sp)
    LOAD        x11, 10*REGBYTES(sp)
    LOAD        x12, 11*REGBYTES(sp)
    LOAD        x13, 12*REGBYTES(sp)
    LOAD        x14, 13*REGBYTES(sp)
    LOAD        x15, 14*REGBYTES(sp)
    LOAD        x16, 15*REGBYTES(sp)
    LOAD        x17, 16*REGBYTES(sp)
    LOAD        x18, 17*REGBYTES(sp)
    LOAD        x19, 18*REGBYTES(sp)
    LOAD        x20, 19*REGBYTES(sp)
    LOAD        x21, 20*REGBYTES(sp)
    LOAD        x22, 21*REGBYTES(sp)
    LOAD        x23, 22*REGBYTES(sp)
    LOAD        x24, 23*REGBYTES(sp)
    LOAD        x25, 24*REGBYTES(sp)
    LOAD        x26, 25*REGBYTES(sp)
    LOAD        x27, 26*REGBYTES(sp)
    LOAD        x28, 27*REGBYTES(sp)
    LOAD        x29, 28*REGBYTES(sp)
    LOAD        x30, 29*REGBYTES(sp)
    LOAD        x31, 30*REGBYTES(sp)

    // Save SP
    csrr        t0, sscratch
    LOAD        x2, 1*REGBYTES(sp)
    sret

.global flush_mmu
flush_mmu:
    sfence.vma
    ret
