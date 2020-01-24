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

.global enable_mmu
.global return_from_interrupt
.text
enable_mmu:
    la      sp, _estack // Trash the stack and start over
return_from_interrupt:
	mret    // Return to kmain

.global flush_mmu
flush_mmu:
    sfence.vma
    ret

.global my_fence
.global read_satp
.text
read_satp:
    csrr    a0, satp
    ret
