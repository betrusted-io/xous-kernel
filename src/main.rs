#![no_std]
#![no_main]

extern crate xous_riscv;
mod syscalls;
mod irq;
mod macros;
mod mem;

pub use irq::sys_interrupt_claim;

use core::panic::PanicInfo;
use xous_kernel_riscv_rt::xous_kernel_entry;
use xous_riscv::register::{mcause, mstatus, mie, vmim, vmip};
use mem::MemoryManager;


#[panic_handler]
fn handle_panic(_arg: &PanicInfo) -> ! {
    loop {}
}

fn print_str(uart: *mut usize, s: &str) {
    for c in s.bytes() {
        unsafe { uart.write_volatile(c as usize) };
    }
}

#[xous_kernel_entry]
fn xous_main() -> ! {
    unsafe {
        vmim::write(0); // Disable all machine interrupts
        mie::set_msoft();
        mie::set_mtimer();
        mie::set_mext();
        mstatus::set_mie(); // Enable CPU interrupts
    }
    let mm = MemoryManager::new();
    sys_interrupt_claim(2, |_| {
        let uart_ptr = 0xE000_1800 as *mut usize;
        print_str(uart_ptr, "hello, world!\r\n");
        // Acknowledge the IRQ
        unsafe {
            uart_ptr.add(0).read_volatile();

            // Acknowledge the event
            uart_ptr.add(4).write_volatile(3);
        };
    })
    .unwrap();

    // Enable interrupts
    let uart_ptr = 0xE000_1800 as *mut usize;
    unsafe { uart_ptr.add(4).write_volatile(3) };
    unsafe { uart_ptr.add(5).write_volatile(3) };
    print_str(uart_ptr, "greetings!\r\n");

    loop {
        unsafe { xous_riscv::asm::wfi() };
    }
}

#[no_mangle]
pub fn trap_handler() {
    let mc = mcause::read();
    let irqs_pending = vmip::read();

    if mc.is_exception() {}

    if irqs_pending != 0 {
        irq::handle(irqs_pending);
    }
}
