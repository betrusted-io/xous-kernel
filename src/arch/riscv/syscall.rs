use crate::processtable::ProcessContext;
use vexriscv::register::{sepc, sstatus};

extern "C" {
    fn return_to_user(regs: *const usize) -> !;
}

pub fn invoke(supervisor: bool, pc: usize, sp: usize, ret_addr: usize, args: &[usize]) -> ! {
    let mut regs = [0; 31];
    regs[0] = ret_addr;
    regs[1] = sp;
    regs[9] = args[0];
    regs[10] = args[1];
    set_supervisor(supervisor);
    sepc::write(pc as usize);
    unsafe { return_to_user(regs.as_ptr()) };
}

fn set_supervisor(supervisor: bool) {
    if supervisor {
        unsafe { sstatus::set_spp(sstatus::SPP::Supervisor) };
    } else {
        unsafe { sstatus::set_spp(sstatus::SPP::User) };
    }
}

pub fn resume(supervisor: bool, context: &ProcessContext) -> ! {
    sepc::write(context.sepc);

    // Return to user mode
    set_supervisor(supervisor);

    println!(
        "Switching to PID {}, SP: {:08x}, PC: {:08x}, SATP: {:08x}",
        (context.satp >> 22) & ((1 << 9) - 1),
        context.registers[1],
        context.sepc,
        context.satp
    );
    unsafe { return_to_user(context.registers.as_ptr()) };
}
