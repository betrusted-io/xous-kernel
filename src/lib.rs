#![no_std]

extern crate xous_riscv;

// use core::panic::PanicInfo;
// #[panic_handler]
// fn handle_panic(_arg: &PanicInfo) -> ! {
//     loop {}
// }

// Allow consumers of this library to make syscalls
pub mod syscalls;
