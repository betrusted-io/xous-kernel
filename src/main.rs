#![no_std]
#![no_main]

extern crate xous_riscv;

use core::panic::PanicInfo;
#[panic_handler]
fn handle_panic(arg: &PanicInfo) -> ! {
    loop {}
}

use xous_riscv_rt::entry;
#[entry]
fn xous_main() -> ! {
    loop {
        unsafe { xous_riscv::asm::wfi() };
    }
}
