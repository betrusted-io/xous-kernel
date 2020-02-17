#![no_std]
#![no_main]

extern crate vexriscv;

#[macro_use]
extern crate bitflags;

#[macro_use]
mod debug;

mod start;

#[macro_use]
mod args;
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
use mem::{MemoryManager, MMUFlags};
use processtable::SystemServices;
use vexriscv::register::{
    mepc, mie, satp, scause, sepc, sie, sstatus, stval, vmim, vmip, vsim, vsip,
};

#[panic_handler]
fn handle_panic(arg: &PanicInfo) -> ! {
    sprintln!("PANIC!");
    sprintln!("Details: {:?}", arg);
    loop {}
}

#[no_mangle]
fn xous_kernel_main(arg_offset: *const u32, ss_offset: *mut u32, rpt_offset: *mut u32) -> ! {
    let args = args::KernelArguments::new(arg_offset);
    let system_services = SystemServices::new(ss_offset);
    let mut memory_manager = MemoryManager::new(rpt_offset, &args).expect("couldn't create memory manager");

    // As a test, map the default UART into our memory space
    memory_manager.map_page(0xE0001000, debug::DEFAULT_UART.base as u32, MMUFlags::R | MMUFlags::W).expect("unable to map serial port");
    println!("Map success!");

    debug::SUPERVISOR_UART.enable_rx();
    sprintln!("KMAIN: Supervisor mode started...");
    unsafe {
        sstatus::set_sie();
        sie::set_ssoft();
        sie::set_sext();
        vsim::write(0xffffffff); // Enable all machine interrupts
    }
    sprintln!("KMAIN: Interrupts enabled...");
    sprintln!("System Services offset: {:08x}", ss_offset as u32);
    sprintln!(
        "Runtime Pagetable Tracker offset: {:08x}",
        rpt_offset as u32
    );
    sprintln!("Kernel arguments:");
    for arg in args.iter() {
        sprintln!("    {}", arg);
    }

    sprintln!("Processes:");
    for (pid, process) in system_services.processes.iter().enumerate() {
        if process.satp != 0 {
            sprintln!("   {}: @ {:08x} PC:{:08x}", pid, process.satp, process.pc);
        }
    }

    sprint!("}} ");
    loop {}
    // let mut mm = MemoryManager::new().expect("Couldn't create memory manager");
    // mm.init().expect("Couldn't initialize memory manager");

    // let mut pt = ProcessTable::new().expect("Couldn't create process table");

    // // Allocate a page to PID 1 to use as the root page table, then create
    // // an identity mapping in preparation for enabling the MMU.
    // let process1 = pt
    //     .create_process(&mut mm)
    //     .expect("Couldn't create process for PID1");
    // let pid1_satp = pt.satp_for(process1).expect("Couldn't find SATP for PID1");
    // mm.create_identity(pid1_satp)
    //     .expect("Couldn't create identity mapping for PID1");

    // println!("MMU enabled, jumping to kmain");
    // pt.switch_to(process1, kmain as usize)
    //     .expect("Couldn't switch to PID1");

    // unsafe {

    //     // Additionally, enable CPU interrupts
    //     mstatus::set_mie();

    //     // When we do an "mret", return to supervisor mode.
    //     mstatus::set_mpp(mstatus::MPP::User);

    //     println!("loader: MSTATUS: {:?}", mstatus::read());
    //     enable_mmu()
    // }
}

// /// This function runs with the MMU enabled, as part of PID 1
// #[no_mangle]
// fn kmain() -> ! {
//     // unsafe {
//     //     vmim::write(0); // Disable all machine interrupts
//     //     mie::set_msoft();
//     //     mie::set_mtimer();
//     //     mie::set_mext();
//     //     // mstatus::set_spie();
//     // }

//     sprintln!("KMAIN: In User mode");
//     let uart = debug::SUPERVISOR_UART;
//     // uart.init();

//     sprintln!("kmain: SATP: {:08x}", satp::read().bits());
//     sprintln!("kmain: MSTATUS: {:?}", mstatus::read());

//     // sys_interrupt_claim(0, timer::irq).unwrap();
//     // timer::time_init();

//     // Enable "RX_EMPTY" interrupt
//     uart.enable_rx();

//     sys_interrupt_claim(2, debug::irq).expect("Couldn't claim interrupt 2");

//     sprintln!("Entering main loop");
//     sprintln!("Attempting to disable the MMU ({:08x}):", satp::read().bits());
//     satp::write(0);
//     println!("Done!  Now: {:08x}", satp::read().bits());
//     // let mut last_time = timer::get_time();
//     loop {
//         // let new_time = timer::get_time();
//         // if new_time >= last_time + 1000 {
//         //     last_time = new_time;
//         //     println!("Uptime: {} ms", new_time);
//         // }
//         // unsafe { vexriscv::asm::wfi() };
//     }
// }

#[no_mangle]
pub fn trap_handler() {
    let mc = scause::read();
    // let irqs_pending = vmip::read();

    let ex = exception::RiscvException::from_regs(mc.bits(), sepc::read(), stval::read());
    if mc.is_exception() {
        sprintln!("CPU Exception: {}", ex);
        unsafe { vexriscv::asm::ebreak() };
        loop {}
    } else {
        sprintln!("Other exception: {}", ex);
    }
}
