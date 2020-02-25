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
    fn xous_syscall_resume_context(context: irq::ProcessContext) -> !;
}

#[panic_handler]
fn handle_panic(arg: &PanicInfo) -> ! {
    println!("PANIC!");
    println!("Details: {:?}", arg);
    loop {}
}

#[no_mangle]
fn xous_kernel_main(arg_offset: *const u32, init_offset: *const u32, rpt_offset: *mut u32) -> ! {
    let args = args::KernelArguments::new(arg_offset);
    let _memory_manager =
        MemoryManager::new(rpt_offset, &args).expect("couldn't create memory manager");
    // xous::rsyscall(xous::SysCall::MapMemory(
    //     0xF0002000 as *mut usize,
    //     debug::SUPERVISOR_UART.base,
    //     4096,
    //     xous::MemoryFlags::R | xous::MemoryFlags::W,
    // ))
    // .unwrap();
    _memory_manager
        .map_page(
            0xF0002000 as *mut usize,
            ((debug::SUPERVISOR_UART.base as u32) & !4095) as *mut usize,
            MMUFlags::R | MMUFlags::W,
        )
        .expect("unable to map serial port");
    let system_services = SystemServices::new(init_offset, &args);

    // As a test, map the default UART into our memory space
    // memory_manager.print();

    debug::SUPERVISOR_UART.enable_rx();
    println!("KMAIN: Supervisor mode started...");
    unsafe {
        sstatus::set_sie();
        sie::set_ssoft();
        sie::set_sext();
    }
    println!("KMAIN: Interrupts enabled...");
    println!(
        "Runtime Pagetable Tracker offset: {:08x}",
        rpt_offset as u32
    );
    println!("Kernel arguments:");
    for arg in args.iter() {
        println!("    {}", arg);
    }

    println!("Processes:");
    for (pid, process) in system_services.processes.iter().enumerate() {
        if process.satp != 0 {
            println!("   {}: {:?}", (pid as u32) + 1, process);
        }
    }

    println!("Calling Yield: {:?}", xous::rsyscall(xous::SysCall::Yield));
    xous::rsyscall(xous::SysCall::ClaimInterrupt(
        3,
        debug::irq as *mut usize,
        0 as *mut usize,
    ))
    .expect("Couldn't claim interrupt 3");
    println!(
        "Switching to PID2 @ {:08x}",
        system_services.processes[1].pc
    );
    xous::rsyscall(xous::SysCall::Resume(2)).expect("Couldn't switch to PID2");
    // system_services
    //     .switch_to_pid(2)
    //     .expect("Couldn't switch to PID2");
    print!("}} ");
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

//     println!("KMAIN: In User mode");
//     let uart = debug::SUPERVISOR_UART;
//     // uart.init();

//     println!("kmain: SATP: {:08x}", satp::read().bits());
//     println!("kmain: MSTATUS: {:?}", mstatus::read());

//     // sys_interrupt_claim(0, timer::irq).unwrap();
//     // timer::time_init();

//     // Enable "RX_EMPTY" interrupt
//     uart.enable_rx();

//     println!("Entering main loop");
//     println!("Attempting to disable the MMU ({:08x}):", satp::read().bits());
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

static mut PREVIOUS_CONTEXT: Option<irq::ProcessContext> = None;

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
    let pid = satp::read().asid();
    let ref current_context = unsafe { &*(0x00801000 as *const irq::ProcessContext)};
    println!("Entered trap handler");
    if (sc.bits() == 9) || (sc.bits() == 8) {
        let is_user = sc.bits() == 8;
        sepc::write(sepc::read() + 4);
        println!(
            "    Syscall {:08x}: {:08x}, {:08x}, {:08x}, {:08x}, {:08x}, {:08x}, {:08x}",
            a0, a1, a2, a3, a4, a5, a6, a7
        );
        println!("   Decoded Syscall: {:?}", call);
        let call = call.unwrap_or_else(|_| {
            unsafe { xous_syscall_return_fast(9, 3, 1, 7, 5, 3, 0, 9) };
        });

        let response = match &call {
            SysCall::MapMemory(phys, virt, size, flags) => unsafe {
                let mm = MemoryManager::get();
                mm.map_page(
                    *phys,
                    *virt,
                    MMUFlags::R
                        | MMUFlags::W
                        | (if is_user {
                            MMUFlags::USER
                        } else {
                            MMUFlags::NONE
                        }),
                )
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
            SysCall::ClaimInterrupt(no, callback, arg) => {
                irq::interrupt_claim(*no, pid as definitions::XousPid, *callback, *arg)
                    .map(|_| XousResult::Ok)
                    .unwrap_or(XousResult::XousError(3))
            }
            c => XousResult::XousError(1),
        };
        println!("Call: {:?}  Result: {:?}", call, response);
        unsafe { xous_syscall_return_rust(&response) };
    }

    let ex = exception::RiscvException::from_regs(sc.bits(), sepc::read(), stval::read());
    if sc.is_exception() {
        match ex {
            exception::RiscvException::InstructionPageFault(0x00802000, _) => {
                println!("Return from interrupt");
                unsafe {
                    if let Some(previous) = PREVIOUS_CONTEXT.take() {
                        sie::set_sext();
                        xous_syscall_resume_context(previous);
                    }
                }
            }
            ex => {
                println!("CPU Exception on PID {}: {}", pid, ex);
                unsafe {
                    let mm = MemoryManager::get();
                    mm.print();
                }
            }
        }
        loop {}
    } else {
        let irqs_pending = vsip::read();
        println!(
            "Other exception: {}  (irqs_pending: {:08x})",
            ex, irqs_pending
        );
        unsafe {
            if PREVIOUS_CONTEXT.is_none() {
                PREVIOUS_CONTEXT = Some(**current_context);
            }
        }
        irq::handle(irqs_pending);
    }
    loop {}
}
