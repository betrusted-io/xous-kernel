//! uscratch register

read_csr_as_usize!(0xCC0, __read_vdci);
write_csr_as_usize!(0xCC0, __write_vdci);
