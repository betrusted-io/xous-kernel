#define STORE    sw
#define LOAD     lw
#define LOG_REGBYTES 2
#define REGBYTES (1 << LOG_REGBYTES)+16

.global _xous_syscall
_xous_syscall:
    ecall
    sw          a0, 0*REGBYTES(sp)
    sw          a1, 1*REGBYTES(sp)
    sw          a2, 2*REGBYTES(sp)
    sw          a3, 3*REGBYTES(sp)
    sw          a4, 4*REGBYTES(sp)
    sw          a5, 5*REGBYTES(sp)
    sw          a6, 6*REGBYTES(sp)
    sw          a7, 7*REGBYTES(sp)
    ret
