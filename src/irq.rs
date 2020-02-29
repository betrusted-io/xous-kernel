use crate::definitions::{XousError, XousPid};
use crate::processtable::SystemServices;
use crate::arch;

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
                    // Disable all other IRQs and redirect into userspace
                    arch::irq::disable_all_irqs();
                    ss.make_callback_to(pid, f, irq_no, arg)?;
                } else {
                    // If there is no handler, mask this interrupt
                    // to prevent an IRQ storm.  This is considered
                    // an error.
                    // println!("Shutting it up");
                    arch::irq::disable_irq(irq_no);
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
        arch::irq::enable_all_irqs();
        let result = if irq > IRQ_HANDLERS.len() {
            Err(XousError::InterruptNotFound)
        } else if IRQ_HANDLERS[irq].is_some() {
            Err(XousError::InterruptInUse)
        } else {
            IRQ_HANDLERS[irq] = Some((pid, f, arg));
            arch::irq::enable_irq(irq);
            Ok(())
        };
        arch::irq::enable_all_irqs();
        result
    }
}
