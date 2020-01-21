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

.global start_kmain
.text
start_kmain:
    li		t0, (1 << 11) | (1 << 5)
	csrw	mstatus, t0
	csrw	mepc, a0
    add     a0, a1, zero
    add     a1, a2, zero
    add     a2, a3, zero
    add     a3, a4, zero
    add     a4, a5, zero
    add     a5, a6, zero
    add     a6, a7, zero
    add     a7, zero, zero
	mret    // Return to kmain
