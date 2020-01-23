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

.global return_from_interrupt
.text
return_from_interrupt:
    la      sp, _estack
	mret    // Return to kmain

.global read_satp
.text
read_satp:
    csrr    a0, satp
    ret
