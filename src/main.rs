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
use core::slice;
use mem::{MMUFlags, MemoryManager};
use processtable::{InitialProcess, SystemServices};
use vexriscv::register::{scause, sepc, sie, sstatus, stval, vsip};

#[panic_handler]
fn handle_panic(arg: &PanicInfo) -> ! {
    sprintln!("PANIC!");
    sprintln!("Details: {:?}", arg);
    loop {}
}

#[no_mangle]
fn xous_kernel_main(arg_offset: *const u32, init_offset: *const u32, rpt_offset: *mut u32) -> ! {
    let args = args::KernelArguments::new(arg_offset);
    let mut memory_manager =
        MemoryManager::new(rpt_offset, &args).expect("couldn't create memory manager");
    memory_manager
        .map_page(
            0xF0002000,
            (debug::SUPERVISOR_UART.base as u32) & !4095,
            MMUFlags::R | MMUFlags::W,
        )
        .expect("unable to map serial port");
    let system_services = SystemServices::new(init_offset, &args);

    // As a test, map the default UART into our memory space
    // memory_manager.print();

    debug::SUPERVISOR_UART.enable_rx();
    sprintln!("KMAIN: Supervisor mode started...");
    unsafe {
        sstatus::set_sie();
        sie::set_ssoft();
        sie::set_sext();
    }
    sprintln!("KMAIN: Interrupts enabled...");
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
            sprintln!("   {}: {:?}", (pid as u32) + 1, process);
        }
    }

    sys_interrupt_claim(3, debug::irq).expect("Couldn't claim interrupt 3");
    // sprintln!(
    //     "Switching to PID2 @ {:08x}",
    //     system_services.processes[1].pc
    // );
    // system_services
    //     .switch_to_pid(2)
    //     .expect("Couldn't switch to PID2");
    sprint!("}} ");
    loop {}
    //     unsafe { vexriscv::asm::wfi() };
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
    let irqs_pending = vsip::read();

    let ex = exception::RiscvException::from_regs(mc.bits(), sepc::read(), stval::read());
    if mc.is_exception() {
        sprintln!("CPU Exception: {}", ex);
        unsafe { vexriscv::asm::ebreak() };
        loop {}
    } else {
        irq::handle(irqs_pending);
        // sprintln!("Other exception: {}  (irqs_pending: {:08x})", ex, irqs_pending);
    }
}
