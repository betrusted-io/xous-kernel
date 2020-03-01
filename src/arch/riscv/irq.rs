use crate::mem::MemoryManager;
use crate::arch::mem::MemoryMapping;
use crate::processtable::{ProcessContext, ProcessState, SystemServices, RETURN_FROM_ISR};
use vexriscv::register::{scause, sepc, sie, sstatus, stval, vsim, vsip};
use xous::{SysCall, XousError, XousPid, XousResult, MemoryFlags};

extern "Rust" {
    fn xous_syscall_return_rust(result: &XousResult) -> !;
    fn xous_syscall_resume_context(context: ProcessContext) -> !;
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

        // When we return, skip past the `ecall` instruction
        sepc::write(sepc::read() + 4);
        unsafe { xous_syscall_return_rust(&response) };
    }

    let pid = crate::arch::current_pid();
    use crate::arch::exception::RiscvException;
    let ex = RiscvException::from_regs(sc.bits(), sepc::read(), stval::read());
    if sc.is_exception() {
        if let RiscvException::InstructionPageFault(RETURN_FROM_ISR, _offset) = ex {
            // Re-enable interrupts now that they're handled
            unsafe {
                sie::set_sext();
                if let Some(previous_pid) = PREVIOUS_PID.take() {
                    // println!("Resuming previous pid {}", previous_pid);
                    SystemServices::get()
                        .resume_pid(previous_pid, ProcessState::Ready)
                        .expect_err("resume pid failed");
                    panic!("dunno what happened");
                }
            }
        }
        // If the CPU tries to store, lok for a "reserved page" and provide
        // it with one if necessary.
        if let RiscvException::StorePageFault(pc, sp) = ex {
            assert!(
                pid > 1,
                "kernel store page fault (pc: {:08x}  target: {:08x})",
                pc,
                sp
            );
            let mapping = MemoryMapping::current();
            if mapping.current_mapping(sp) & 3 == 2 {
                let mm = unsafe { MemoryManager::get() };
                let new_page = mm.alloc_page(pid).expect("Couldn't allocate new page");
                println!(
                    "Allocating new physical page {:08x} @ {:08x}",
                    new_page,
                    (sp & !4095)
                );
                mm.map_range(
                    new_page as *mut usize,
                    (sp & !4095) as *mut usize,
                    4096,
                    MemoryFlags::W | MemoryFlags::R,
                )
                .expect("Couldn't map new stack");
                // println!("Resuming context");
                let cc = crate::arch::ProcessContext::current();
                unsafe { xous_syscall_resume_context(*cc) };
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
        crate::irq::handle(irqs_pending).expect("Couldn't handle IRQ");
    }
    loop {}
}
