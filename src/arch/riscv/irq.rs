use crate::arch::current_pid;
use crate::arch::mem::MemoryMapping;
use crate::mem::MemoryManagerHandle;
use crate::processtable::{ProcessContext, ProcessState, SystemServicesHandle, RETURN_FROM_ISR};
use vexriscv::register::{scause, sepc, sie, sstatus, stval, vsim, vsip};
use xous::{MemoryFlags, SysCall, XousError, XousPid, XousResult};

extern "Rust" {
    fn xous_syscall_return_rust(result: &XousResult) -> !;
}

/// Disable external interrupts
pub fn disable_all_irqs() {
    unsafe { sie::clear_sext() };
}

/// Enable external interrupts
pub fn enable_all_irqs() {
    unsafe { sie::set_sext() };
}

pub fn enable_irq(irq_no: usize) {
    // Note that the vexriscv "IRQ Mask" register is inverse-logic --
    // that is, setting a bit in the "mask" register unmasks (i.e. enables) it.
    vsim::write(vsim::read() | (1 << irq_no));
}

pub fn disable_irq(irq_no: usize) {
    vsim::write(vsim::read() & !(1 << irq_no));
}

static mut PREVIOUS_PID: Option<XousPid> = None;

fn map_page_and_return(pc: usize, addr: usize, pid: XousPid, flags: MemoryFlags) {
    assert!(
        pid > 1,
        "kernel store page fault (pc: {:08x}  target: {:08x})",
        pc,
        addr
    );

    {
        let mut mm = MemoryManagerHandle::get();
        let new_page = mm.alloc_page(pid).expect("Couldn't allocate new page");
        println!(
            "Allocating new physical page {:08x} @ {:08x}",
            new_page,
            (addr & !4095)
        );
        mm.map_range(
            new_page as *mut usize,
            (addr & !4095) as *mut usize,
            4096,
            flags,
        )
        .expect("Couldn't map new stack");
    }
    crate::arch::syscall::resume(current_pid() == 1, ProcessContext::current());
}

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
    if cfg!(target_arch = "riscv32")
        && sstatus::read().spp() == sstatus::SPP::Supervisor
        && sc.bits() == 0xf
    {
        panic!("Ran out of kernel stack");
    }

    if (sc.bits() == 9) || (sc.bits() == 8) {
        // We got here because of an `ecall` instruction.  When we return, skip
        // past this instruction.
        crate::arch::ProcessContext::current().sepc += 4;
        let call = SysCall::from_args(a0, a1, a2, a3, a4, a5, a6, a7).unwrap_or_else(|_| unsafe {
            xous_syscall_return_rust(&XousResult::Error(XousError::UnhandledSyscall))
        });
        // println!(
        //     "    Syscall {:08x}: {:08x}, {:08x}, {:08x}, {:08x}, {:08x}, {:08x}, {:08x}",
        //     a0, a1, a2, a3, a4, a5, a6, a7
        // );

        let response = crate::syscall::handle(call);

        println!("Result: {:?}", response);

        // If we're resuming a process that was previously sleeping, restore the context.
        // Otherwise, keep the context the same but pass the return values in 8 return
        // registers.
        if response == XousResult::ResumeProcess {
            crate::arch::syscall::resume(current_pid() == 1, ProcessContext::current());
        } else {
            // When we return, skip past the `ecall` instruction
            sepc::write(sepc::read() + 4);
            unsafe { xous_syscall_return_rust(&response) };
        }
    }

    let pid = crate::arch::current_pid();
    use crate::arch::exception::RiscvException;
    let ex = RiscvException::from_regs(sc.bits(), sepc::read(), stval::read());
    if sc.is_exception() {
        // If the CPU tries to store, lok for a "reserved page" and provide
        // it with one if necessary.
        match ex {
            RiscvException::StorePageFault(pc, sp) | RiscvException::LoadPageFault(pc, sp) => {
                let mapping = MemoryMapping::current();
                let flags = mapping.flags_for_address(sp) & 7;
                if flags & 1 == 0 && flags != 0 {
                    let flags = MemoryFlags::from_bits(flags).expect("couldn't return flags");
                    map_page_and_return(pc, sp, pid, flags);
                }
            }
            RiscvException::InstructionPageFault(RETURN_FROM_ISR, _offset) => {
                unsafe {
                    if let Some(previous_pid) = PREVIOUS_PID.take() {
                        // println!("Resuming previous pid {}", previous_pid);
                        SystemServicesHandle::get()
                            .resume_pid(previous_pid, ProcessState::Ready)
                            .expect("unable to resume previous PID");
                    }
                    // Re-enable interrupts now that they're handled
                    enable_all_irqs();
                    crate::arch::syscall::resume(current_pid() == 1, ProcessContext::current());
                }
            }
            _ => (),
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
        crate::irq::handle(irqs_pending).expect("Couldn't handle IRQ");
        crate::arch::syscall::resume(current_pid() == 1, ProcessContext::current());
    }
}
