#![no_std]
#![no_main]

extern crate vexriscv;

#[macro_use]
mod debug;

mod definitions;
mod exception;
mod irq;
mod macros;
mod mem;
mod processtable;
mod syscalls;
mod timer;

pub use irq::sys_interrupt_claim;

use core::panic::PanicInfo;
use mem::MemoryManager;
use processtable::ProcessTable;
use vexriscv::register::{mcause, mepc, mie, mstatus, mtval, satp, vmim, vmip};
use xous_kernel_riscv_rt::xous_kernel_entry;

#[panic_handler]
fn handle_panic(arg: &PanicInfo) -> ! {
    println!("PANIC!");
    println!("Details: {:?}", arg);
    loop {}
}

extern "Rust" {
    fn enable_mmu() -> !;
}
extern "C" {
    /// Debug function to read the current SATP.  Useful since Renode
    /// doesn't support reading it any other way.
    fn read_satp() -> usize;
}

#[xous_kernel_entry]
fn mmu_init() -> ! {
    let mut mm = MemoryManager::new().expect("Couldn't create memory manager");
    mm.init().expect("Couldn't initialize memory manager");

    let mut pt = ProcessTable::new().expect("Couldn't create process table");

    // Allocate a page to PID 1 to use as the root page table, then create
    // an identity mapping in preparation for enabling the MMU.
    let process1 = pt
        .create_process(&mut mm)
        .expect("Couldn't create process for PID1");
    let pid1_satp = pt.satp_for(process1).expect("Couldn't find SATP for PID1");
    mm.create_identity(pid1_satp)
        .expect("Couldn't create identity mapping for PID1");

    println!("MMU enabled, jumping to kmain");
    pt.switch_to(process1, kmain as usize)
        .expect("Couldn't switch to PID1");
    println!("SATP: {:08x}", unsafe { read_satp() });

    unsafe {

        // Additionally, enable CPU interrupts
        mstatus::set_mie();

        // When we do an "mret", return to supervisor mode.
        mstatus::set_mpp(mstatus::MPP::User);

        println!("loader: MSTATUS: {:?}", mstatus::read());
        enable_mmu()
    }
}

/// This function runs with the MMU enabled, as part of PID 1
#[no_mangle]
fn kmain() -> ! {
    // unsafe {
    //     vmim::write(0); // Disable all machine interrupts
    //     mie::set_msoft();
    //     mie::set_mtimer();
    //     mie::set_mext();
    //     // mstatus::set_spie();
    // }

    sprintln!("KMAIN: In User mode");
    let uart = debug::SUPERVISOR_UART;
    // uart.init();

    sprintln!("kmain: SATP: {:08x}", satp::read().bits());
    sprintln!("kmain: MSTATUS: {:?}", mstatus::read());

    // sys_interrupt_claim(0, timer::irq).unwrap();
    // timer::time_init();

    // Enable "RX_EMPTY" interrupt
    uart.enable_rx();

    sys_interrupt_claim(2, debug::irq).expect("Couldn't claim interrupt 2");

    sprintln!("Entering main loop");
    sprintln!("Attempting to disable the MMU ({:08x}):", satp::read().bits());
    satp::write(0);
    println!("Done!  Now: {:08x}", satp::read().bits());
    // let mut last_time = timer::get_time();
    loop {
        // let new_time = timer::get_time();
        // if new_time >= last_time + 1000 {
        //     last_time = new_time;
        //     println!("Uptime: {} ms", new_time);
        // }
        // unsafe { vexriscv::asm::wfi() };
    }
}

#[no_mangle]
pub fn trap_handler() {
    let mc = mcause::read();
    let irqs_pending = vmip::read();

    if mc.is_exception() {
        let ex = exception::RiscvException::from_regs(mc.bits(), mepc::read(), mtval::read());
        let _old_satp = satp::read().bits();

        // Disable the MMU if we get into this exception state,
        // to prevent double-faulting.
        satp::write(0);
        print!("CPU Exception: ");
        println!("{}", ex);
        unsafe { vexriscv::asm::ebreak() };
        loop {}
    }

    if irqs_pending != 0 {
        irq::handle(irqs_pending);
    }
}
