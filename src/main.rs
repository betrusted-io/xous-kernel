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
use processtable::{SystemServices, ProcessContext, ProcessState};
use vexriscv::register::{satp, scause, sepc, sie, sstatus, stval, vsip};
use xous::*;

extern "Rust" {
    #[allow(unused)]
    fn xous_syscall_return_rust(result: &XousResult) -> !;
    #[allow(unused)]
    fn xous_syscall_return(result: XousResult) -> !;
    fn xous_syscall_resume_context(context: ProcessContext) -> !;
}

#[panic_handler]
fn handle_panic(arg: &PanicInfo) -> ! {
    println!("PANIC in PID {}!", satp::read().asid());
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
    println!("Kernel arguments:");
    for arg in args.iter() {
        println!("    {}", arg);
    }

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
                xous::rsyscall(xous::SysCall::Resume((pid_idx + 1) as XousPid)).expect("couldn't switch to pid");
            }
        }
        if ! runnable {
            println!("No runnable tasks found.  Zzz...");
            unsafe { vexriscv::asm::wfi() };
        }
    }
}

static mut PREVIOUS_PID: Option<XousPid> = None;

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
    let sc = scause::read();

    // If we were previously in Supervisor mode and we've just tried to write
    // to invalid memory, then we likely blew out the stack.
    if sstatus::read().spp() == sstatus::SPP::Supervisor && sc.bits() == 0xf {
        panic!("Ran out of kernel stack");
    }

    let pid = satp::read().asid() as XousPid;
    let ref mut current_context = ProcessContext::current();
    let mm = unsafe { MemoryManager::get() };
    let ss = unsafe { SystemServices::get() };

    if (sc.bits() == 9) || (sc.bits() == 8) {
        // We got here because of an `ecall` instruction.  When we return, skip
        // past this instruction.
        current_context.sepc += 4;

        let is_user = sc.bits() == 8;
        let call = SysCall::from_args(a0, a1, a2, a3, a4, a5, a6, a7).unwrap_or_else(|_|
            unsafe { xous_syscall_return_rust(&XousResult::Error(XousError::UnhandledSyscall)) }
        );
        // println!(
        //     "    Syscall {:08x}: {:08x}, {:08x}, {:08x}, {:08x}, {:08x}, {:08x}, {:08x}",
        //     a0, a1, a2, a3, a4, a5, a6, a7
        // );
        // println!("   Decoded Syscall: {:?}", call);

        let response = match &call {
            SysCall::MapMemory(phys, virt, size, req_flags) => {
                if (*virt as usize) < mem::USER_AREA_START {
                    XousResult::Error(XousError::BadAddress)
                } else if size & 4095 != 0 {
                    // println!("map: bad alignment of size {:08x}", size);
                    XousResult::Error(XousError::BadAlignment)
                } else {
                    println!(
                        "Mapping {:08x} -> {:08x} ({} bytes, flags: {:?})",
                        *phys as u32, *virt as u32, size, req_flags
                    );
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
                    result
                }
            },
            // SysCall::SwitchTo(pid, pc, sp) => unsafe {
            //     unimplemented!();
            //     // let ss = SystemServices::get();
            //     // XousResult::Error(
            //     //     ss.switch_to_pid_at(*pid, *pc, *sp)
            //     //         .expect_err("context switch failed"),
            //     // )
            // },
            SysCall::Resume(pid) => {
                XousResult::Error(ss.resume_pid(*pid, ProcessState::Ready).expect_err("resume pid failed"))
            },
            SysCall::ClaimInterrupt(no, callback, arg) => {
                irq::interrupt_claim(*no, pid as definitions::XousPid, *callback, *arg)
                    .map(|_| XousResult::Ok)
                    .unwrap_or_else(|e| XousResult::Error(e))
            },
            SysCall::Yield => {
                let ppid = ss.get_process(pid).expect("Can't get current process").ppid;
                assert_ne!(ppid, 0, "no parent process id");
                current_context.registers[10] = 0;
                ss.resume_pid(ppid, ProcessState::Ready).expect("couldn't resume parent process");
                XousResult::Error(XousError::ProcessNotFound)
            }
            SysCall::WaitEvent => {
                let process = ss.get_process(pid).expect("Can't get current process");
                let ppid = process.ppid;
                assert_ne!(ppid, 0, "no parent process id");
                current_context.registers[10] = 0;
                ss.resume_pid(ppid, ProcessState::Sleeping).expect("couldn't resume parent process");
                XousResult::Error(XousError::ProcessNotFound)
            }
            _ => XousResult::Error(XousError::UnhandledSyscall),
        };
        // println!("Call: {:?}  Result: {:?}", call, response);

        // When we return, skip past the `ecall` instruction
        sepc::write(sepc::read() + 4);
        unsafe { xous_syscall_return_rust(&response) };
    }

    use exception::RiscvException;
    let ex = RiscvException::from_regs(sc.bits(), sepc::read(), stval::read());
    if sc.is_exception() {
        if let RiscvException::InstructionPageFault(processtable::RETURN_FROM_ISR, _offset) = ex {
            // Re-enable interrupts now that they're handled
            unsafe { sie::set_sext() };
            unsafe {
                if let Some(previous_pid) = PREVIOUS_PID.take() {
                    // println!("Resuming previous pid {}", previous_pid);
                    ss.resume_pid(previous_pid, ProcessState::Ready).expect_err("resume pid failed");
                    panic!("dunno what happened");
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
                let new_page = mm.alloc_page(pid).expect("Couldn't allocate new page");
                // println!(
                //     "Allocating new physical page {:08x} @ {:08x}",
                //     new_page,
                //     (sp & !4095)
                // );
                mm.map_page(
                    new_page as *mut usize,
                    (sp & !4095) as *mut usize,
                    MMUFlags::W | MMUFlags::R | MMUFlags::USER,
                )
                .expect("Couldn't map new stack");
                // println!("Resuming context");
                unsafe { xous_syscall_resume_context(**current_context) };
            }
        }
        println!("CPU Exception on PID {}: {}", pid, ex);
        loop {}
    } else {
        let irqs_pending = vsip::read();
        // Safe to access globals since interrupts are disabled
        // when this function runs.
        unsafe {
            if PREVIOUS_PID.is_none() {
                PREVIOUS_PID = Some(pid);
            }
        }
        irq::handle(irqs_pending).expect("Couldn't handle IRQ");
    }
    loop {}
}
