use crate::definitions::{XousError, XousPid};
use crate::processtable::SystemServices;
use vexriscv::register::{sstatus, vsim};

static mut IRQ_HANDLERS: [Option<(XousPid, *mut usize, *mut usize)>; 32] = [None; 32];

pub fn handle(irqs_pending: usize) -> Result<(), XousError> {
    // Unsafe is required here because we're accessing a static
    // mutable value, and it could be modified from various threads.
    // However, this is fine because this is run from an IRQ context
    // with interrupts disabled.
    // NOTE: This will become an issue when running with multiple cores,
    // so this should be protected by a mutex.
    unsafe {
        for irq_no in 0..IRQ_HANDLERS.len() {
            if irqs_pending & (1 << irq_no) != 0 {
                if let Some((pid, f, arg)) = IRQ_HANDLERS[irq_no] {
                    let ss = SystemServices::get();
                    // Mask the IRQ and call the function
                    vsim::write(vsim::read() | (1 << irq_no));
                    ss.make_callback_to(pid, f, arg)?;
                    // Call the IRQ handler
                    // println!("Calling handler");
                } else {
                    // If there is no handler, mask this interrupt
                    // to prevent an IRQ storm.  This is considered
                    // an error.
                    // println!("Shutting it up");
                    vsim::write(vsim::read() | (1 << irq_no));
                }
            }
        }
    }
    Ok(())
}

pub fn interrupt_claim(irq: usize, pid: XousPid, f: *mut usize, arg: *mut usize) -> Result<(), XousError> {
    // Unsafe is required since we're accessing a static mut array.
    // However, we disable interrupts to prevent contention on this array.
    unsafe {
        sstatus::clear_sie();
        let result = if irq > IRQ_HANDLERS.len() {
            Err(XousError::InterruptNotFound)
        } else if IRQ_HANDLERS[irq].is_some() {
            Err(XousError::InterruptInUse)
        } else {
            IRQ_HANDLERS[irq] = Some((pid, f, arg));
            // Note that the vexriscv "IRQ Mask" register is inverse-logic --
            // that is, setting a bit in the "mask" register unmasks (i.e. enables) it.
            vsim::write(vsim::read() | (1 << irq));
            Ok(())
        };
        sstatus::set_sie();
        result
    }
}
