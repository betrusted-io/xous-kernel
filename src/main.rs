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
mod exception;
mod irq;
mod mem;
mod processtable;
mod syscalls;

use core::panic::PanicInfo;
use mem::{MMUFlags, MemoryManager};
use processtable::{SystemServices, ProcessContext};
use vexriscv::register::{satp, scause, sepc, sie, sstatus, stval, vsip};
use xous::*;

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
    fn xous_syscall_return_rust(result: &XousResult) -> !;
    #[allow(unused)]
    fn xous_syscall_return(result: XousResult) -> !;
    fn xous_syscall_resume_context(context: ProcessContext) -> !;
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

    // Either map memory using a syscall, or if we're debugging the syscall
    // handler then directly map it.
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
        system_services.processes[1].satp
    );
    xous::rsyscall(xous::SysCall::Resume(2)).expect("Couldn't switch to PID2");
    print!("}} ");
    loop {}
}

static mut PREVIOUS_CONTEXT: Option<ProcessContext> = None;

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
    let call = SysCall::from_args(a0, a1, a2, a3, a4, a5, a6, a7);
    let sc = scause::read();
    // If we were previously in Supervisor mode and we've just tried to write
    // to invalid memory, then we likely blew out the stack.
    if sstatus::read().spp() == sstatus::SPP::Supervisor && sc.bits() == 0xf {
        panic!("Ran out of kernel stack");
    }

    let pid = satp::read().asid() as XousPid;
    let ref current_context = ProcessContext::current();
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
            SysCall::MapMemory(phys, virt, size, req_flags) => unsafe {
                if size & 4095 != 0 {
                    println!("map: bad alignment of size {:08x}", size);
                    XousResult::Error(XousError::BadAlignment)
                } else {
                    println!(
                        "Mapping {:08x} -> {:08x} ({} bytes, flags: {:?})",
                        *phys as u32, *virt as u32, size, req_flags
                    );
                    let mm = MemoryManager::get();
                    let mut flags = MMUFlags::NONE;
                    if *req_flags & xous::MemoryFlags::R == xous::MemoryFlags::R {
                        flags |= MMUFlags::R;
                    }
                    if *req_flags & xous::MemoryFlags::W == xous::MemoryFlags::W {
                        flags |= MMUFlags::W;
                    }
                    if *req_flags & xous::MemoryFlags::X == xous::MemoryFlags::X {
                        flags |= MMUFlags::X;
                    }
                    if is_user {
                        flags |= MMUFlags::USER;
                    }
                    let mut last_mapped = 0;
                    let mut result = XousResult::Ok;
                    for offset in (0..*size).step_by(4096) {
                        if let XousResult::Error(e) = mm
                            .map_page(
                                ((*phys as usize) + offset) as *mut usize,
                                ((*virt as usize) + offset) as *mut usize,
                                flags,
                            )
                            .map(|x| XousResult::MemoryAddress(x.get() as *mut usize))
                            .unwrap_or_else(|e| XousResult::Error(e))
                        {
                            result = XousResult::Error(e);
                            break;
                        }
                        last_mapped = offset;
                    }
                    if result != XousResult::Ok {
                        for offset in (0..last_mapped).step_by(4096) {
                            mm.unmap_page(
                                ((*phys as usize) + offset) as *mut usize,
                                ((*virt as usize) + offset) as *mut usize,
                                flags,
                            )
                            .expect("couldn't unmap page");
                        }
                    }
                    mm.print_ownership();
                    result
                }
            },
            SysCall::SwitchTo(pid, pc, sp) => unsafe {
                unimplemented!();
                // let ss = SystemServices::get();
                // XousResult::Error(
                //     ss.switch_to_pid_at(*pid, *pc, *sp)
                //         .expect_err("context switch failed"),
                // )
            },
            SysCall::Resume(pid) => unsafe {
                let ss = SystemServices::get();
                XousResult::Error(ss.resume_pid(*pid).expect_err("resume pid failed"))
            },
            SysCall::ClaimInterrupt(no, callback, arg) => {
                irq::interrupt_claim(*no, pid as definitions::XousPid, *callback, *arg)
                    .map(|_| XousResult::Ok)
                    .unwrap_or_else(|e| XousResult::Error(e))
            }
            _ => XousResult::Error(XousError::UnhandledSyscall),
        };
        println!("Call: {:?}  Result: {:?}", call, response);
        unsafe { xous_syscall_return_rust(&response) };
    }

    use exception::RiscvException;
    let ex = RiscvException::from_regs(sc.bits(), sepc::read(), stval::read());
    if sc.is_exception() {
        if let RiscvException::InstructionPageFault(0x00802000, _offset) = ex {
            println!("Return from interrupt");
            unsafe {
                if let Some(previous) = PREVIOUS_CONTEXT.take() {
                    sie::set_sext();
                    xous_syscall_resume_context(previous);
                }
            }
        }
        // If the CPU tries to store, assume it's blown out its stack and
        // allocate a new page there.
        if let RiscvException::StorePageFault(pc, sp) = ex {
            assert!(
                pid > 1,
                "kernel store page fault (pc: {:08x}  target: {:08x})",
                pc,
                sp
            );
            // If the stack seems sane, simply give the user more stack.
            if sp < mem::USER_STACK_OFFSET && mem::USER_STACK_OFFSET - sp <= 262144 {
                let mm = unsafe { MemoryManager::get() };
                let new_page = mm.alloc_page(pid).expect("Couldn't allocate new page");
                println!(
                    "Allocating new physical page {:08x} @ {:08x}",
                    new_page,
                    (sp & !4095)
                );
                mm.map_page(
                    new_page as *mut usize,
                    (sp & !4095) as *mut usize,
                    MMUFlags::W | MMUFlags::R | MMUFlags::USER,
                )
                .expect("Couldn't map new stack");
                println!("Resuming context");
                unsafe { xous_syscall_resume_context(**current_context) };
            }
        }
        println!("CPU Exception on PID {}: {}", pid, ex);
        unsafe {
            let mm = MemoryManager::get();
            mm.print_map();
        }
        loop {}
    } else {
        let irqs_pending = vsip::read();
        // println!(
        //     "Other exception: {}  (irqs_pending: {:08x})",
        //     ex, irqs_pending
        // );
        println!("Handling IRQ");
        unsafe {
            if PREVIOUS_CONTEXT.is_none() {
                PREVIOUS_CONTEXT = Some(**current_context);
            }
        }
        irq::handle(irqs_pending).expect("Couldn't handle IRQ");
    }
    loop {}
}
