//! uscratch register

read_csr_as_usize!(0xDC0, __read_vsip);
write_csr_as_usize!(0xDC0, __write_vsip);
