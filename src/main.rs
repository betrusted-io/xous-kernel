#![no_std]
#![no_main]

extern crate vexriscv;

mod debug;
mod definitions;
mod irq;
mod macros;
mod mem;
mod processtable;
mod syscalls;

pub use irq::sys_interrupt_claim;

use core::panic::PanicInfo;
use mem::MemoryManager;
use processtable::ProcessTable;
use vexriscv::register::{mcause, mie, mstatus, vmim, vmip};
use xous_kernel_riscv_rt::xous_kernel_entry;

#[panic_handler]
fn handle_panic(_arg: &PanicInfo) -> ! {
    loop {}
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

    let uart = debug::DEFAULT_UART;

    // Enable "RX_EMPTY" interrupt
    uart.enable_rx();

    println!("Starting up...");
    sys_interrupt_claim(2, debug::irq).unwrap();

    let mut mm = MemoryManager::new();
    let mut _pt = ProcessTable::new(&mut mm);


    loop {
        // unsafe { vexriscv::asm::wfi() };
    }
}

#[no_mangle]
pub fn trap_handler() {
    let mc = mcause::read();
    let irqs_pending = vmip::read();

    if mc.is_exception() {
        unsafe { vexriscv::asm::ebreak() };
        loop {}
    }

    if irqs_pending != 0 {
        irq::handle(irqs_pending);
    }
}
