//! uscratch register

read_csr_as_usize!(0xFC0, __read_vmip);
write_csr_as_usize!(0xFC0, __write_vmip);
