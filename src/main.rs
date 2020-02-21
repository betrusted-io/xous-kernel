#![no_std]
#![no_main]

extern crate vexriscv;

#[macro_use]
extern crate bitflags;

extern crate xous;

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

use core::mem as core_mem;
use core::panic::PanicInfo;
use mem::{MMUFlags, MemoryManager};
use processtable::SystemServices;
use vexriscv::register::{satp, scause, sepc, sie, sstatus, stval, vsip};

extern "C" {
    fn xous_syscall_return_fast(
        a0: u32,
        a1: u32,
        a2: u32,
        a3: u32,
        a4: u32,
        a5: u32,
        a6: u32,
        a7: u32,
    ) -> !;
}
extern "Rust" {
    #[allow(unused)]
    fn xous_syscall_return_rust(result: &xous::XousResult) -> !;
    #[allow(unused)]
    fn xous_syscall_return(result: xous::XousResult) -> !;
}

#[panic_handler]
fn handle_panic(arg: &PanicInfo) -> ! {
    sprintln!("PANIC!");
    sprintln!("Details: {:?}", arg);
    loop {}
}

#[no_mangle]
fn xous_kernel_main(arg_offset: *const u32, init_offset: *const u32, rpt_offset: *mut u32) -> ! {
    let args = args::KernelArguments::new(arg_offset);
    let _memory_manager =
        MemoryManager::new(rpt_offset, &args).expect("couldn't create memory manager");
    xous::rsyscall(xous::SysCall::MapMemory(
        0xF0002000 as *mut usize,
        debug::SUPERVISOR_UART.base,
        4096,
        xous::MemoryFlags::R | xous::MemoryFlags::W,
    ))
    .unwrap();
    // memory_manager
    //     .map_page(
    //         0xF0002000 as *mut usize,
    //         ((debug::SUPERVISOR_UART.base as u32) & !4095) as *mut usize,
    //         MMUFlags::R | MMUFlags::W,
    //     )
    //     .expect("unable to map serial port");
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

    sprintln!("Calling Yield: {:?}", xous::rsyscall(xous::SysCall::Yield));
    sys_interrupt_claim(3, debug::irq).expect("Couldn't claim interrupt 3");
    sprintln!(
        "Switching to PID2 @ {:08x}",
        system_services.processes[1].pc
    );
    xous::rsyscall(xous::SysCall::Resume(2)).expect("Couldn't switch to PID2");
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
pub fn trap_handler(
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
) -> ! {
    use xous::{SysCall, XousResult};
    let call = SysCall::from_args(a0, a1, a2, a3, a4, a5, a6, a7);
    let sc = scause::read();
    // sprintln!("Entered trap handler");
    if (sc.bits() == 9) || (sc.bits() == 8) {
        let is_user = sc.bits() == 8;
        sepc::write(sepc::read() + 4);
        // sprintln!(
        //     "Syscall {:08x}: {:08x}, {:08x}, {:08x}, {:08x}, {:08x}, {:08x}, {:08x}",
        //     a0,
        //     a1,
        //     a2,
        //     a3,
        //     a4,
        //     a5,
        //     a6,
        //     a7
        // );
        // sprintln!("   Syscall: {:?}", call);
        let call = call.unwrap_or_else(|_| {
            unsafe { xous_syscall_return_fast(9, 3, 1, 7, 5, 3, 0, 9) };
        });

        let response = match &call {
            SysCall::MapMemory(phys, virt, size, flags) => unsafe {
                let mm = MemoryManager::get();
                mm.map_page(*phys, *virt, MMUFlags::R | MMUFlags::W | (if is_user { MMUFlags::USER } else { MMUFlags::NONE }))
                    .map(|x| XousResult::MemoryAddress(x.get() as *mut usize))
                    .unwrap_or(XousResult::XousError(2))
            },
            SysCall::SwitchTo(pid, pc, sp) => unsafe {
                let ss = SystemServices::get();
                ss.switch_to_pid_at(*pid, *pc, *sp);
                XousResult::XousError(1)
            },
            SysCall::Resume(pid) => unsafe {
                let ss = SystemServices::get();
                ss.resume_pid(*pid);
                XousResult::XousError(1)
            },
            c => XousResult::XousError(1),
        };
        sprintln!("Call: {:?}  Result: {:?}", call, response);
        unsafe { xous_syscall_return_rust(&response) };
        // unsafe { xous_syscall_return_fast(9, 3, 1, 7, 5, 3, 0, 9) };
        // unsafe { xous_syscall_return_rust(&xous::XousResult::MaxResult6(a1+100, a2+100, a3+100, a4+100, a5+100, a6+100, a7+100)) };
        // unsafe { xous_syscall_return(&xous::XousResult::XousError(8675309)) };
        // unsafe { xous_syscall_return_fast(xous::XousResult::MaxResult5(1, 2, 3, 4, 5, 6, 7)) };
        // unsafe { fast_return_from_syscall_8(1, 2, 3, 4, 5, 6, 7, 8) };
    }

    let ex = exception::RiscvException::from_regs(sc.bits(), sepc::read(), stval::read());
    if sc.is_exception() {
        let pid = satp::read().asid();
        sprintln!("CPU Exception on PID {}: {}", pid, ex);
        unsafe {
            let mm = MemoryManager::get();
            mm.print();
        }
        loop {}
    } else {
        let irqs_pending = vsip::read();
        irq::handle(irqs_pending);
        // sprintln!("Other exception: {}  (irqs_pending: {:08x})", ex, irqs_pending);
    }
    loop {}
}
