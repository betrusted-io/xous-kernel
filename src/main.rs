#![cfg_attr(not(test), no_main)]
#![cfg_attr(not(test), no_std)]

extern crate vexriscv;

#[macro_use]
extern crate bitflags;

extern crate xous;

#[macro_use]
mod debug;

#[cfg(test)]
mod test;

mod arch;

#[macro_use]
mod args;
mod irq;
mod mem;
mod processtable;
mod syscall;

use mem::MemoryManager;
use processtable::SystemServices;
use xous::*;

#[cfg(not(test))]
use core::panic::PanicInfo;
#[cfg(not(test))]
#[panic_handler]
fn handle_panic(_arg: &PanicInfo) -> ! {
    println!("PANIC in PID {}!", crate::arch::current_pid());
    println!("Details: {:?}", _arg);
    loop {}
}

#[no_mangle]
fn xous_kernel_main(arg_offset: *const u32, init_offset: *const u32, rpt_offset: *mut u32) -> ! {
    let args = args::KernelArguments::new(arg_offset);
    let _memory_manager =
        MemoryManager::new(rpt_offset, &args).expect("couldn't create memory manager");
    let system_services = SystemServices::new(init_offset, &args);
    arch::init();

    // Either map memory using a syscall, or if we're debugging the syscall
    // handler then directly map it.
    // xous::rsyscall(xous::SysCall::MapMemory(
    //     0xF0002000 as *mut usize,
    //     debug::SUPERVISOR_UART.base,
    //     4096,
    //     xous::MemoryFlags::R | xous::MemoryFlags::W,
    // ))
    // .unwrap();
    #[cfg(feature = "debug-print")]
    {
        _memory_manager
            .map_range(
                0xF0002000 as *mut usize,
                ((debug::SUPERVISOR_UART.base as u32) & !4095) as *mut usize,
                4096,
                MemoryFlags::R | MemoryFlags::W,
            )
            .expect("unable to map serial port");
        println!("KMAIN: Supervisor mode started...");
        debug::SUPERVISOR_UART.enable_rx();
    }
    println!("Kernel arguments:");
    for _arg in args.iter() {
        println!("    {}", _arg);
    }

    #[cfg(feature = "debug-print")]
    xous::rsyscall(xous::SysCall::ClaimInterrupt(
        3,
        debug::irq as *mut usize,
        0 as *mut usize,
    ))
    .expect("Couldn't claim interrupt 3");
    print!("}} ");

    loop {
        let mut runnable = false;
        for (pid_idx, process) in system_services.processes.iter().enumerate() {
            // If this process is owned by the kernel, and if it can be run, run it.
            if process.ppid == 1 && process.runnable() {
                runnable = true;
                xous::rsyscall(xous::SysCall::SwitchTo((pid_idx + 1) as XousPid, 0 as *const usize))
                    .expect("couldn't switch to pid");
            }
        }
        if !runnable {
            println!("No runnable tasks found.  Zzz...");
            unsafe { vexriscv::asm::wfi() };
        }
    }
}
