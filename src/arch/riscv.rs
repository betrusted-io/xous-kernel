use core::mem;
use vexriscv::register::{satp, sepc, sie, sstatus, vsim};
use xous::definitions::XousPid;

extern "C" {
    fn return_to_user(regs: *const usize) -> !;
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

pub fn current_pid() -> XousPid {
    satp::read().asid() as XousPid
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
        "Switching to PID {}, SP: {:08x}, PC: {:08x}",
        (context.satp >> 22) & ((1 << 9) - 1),
        context.registers[1],
        context.sepc
    );
    unsafe { return_to_user(context.registers.as_ptr()) };
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct ProcessContext {
    pub registers: [usize; 31],
    pub satp: usize,
    pub sstatus: usize,
    pub sepc: usize,
}

impl ProcessContext {
    pub fn current() -> &'static mut ProcessContext {
        unsafe { &mut *(0x00801000 as *mut ProcessContext) }
    }
    pub fn saved() -> &'static mut ProcessContext {
        unsafe { &mut *((0x00801000 + mem::size_of::<ProcessContext>()) as *mut ProcessContext) }
    }

    /// Determine whether a process context is valid.
    /// Contexts are valid when the `SATP.VALID` bit is `1`.
    pub fn valid(&self) -> bool {
        (self.satp & 0x80000000) == 0x80000000
    }

    /// Invalidate a context by setting its `SATP.VALID` bit to 0.
    pub fn invalidate(&mut self) {
        self.satp = 0;
    }
}

#[derive(Copy, Clone, Default, PartialEq)]
pub struct MemoryMapping {
    satp: usize,
}

impl core::fmt::Debug for MemoryMapping {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::result::Result<(), core::fmt::Error> {
        write!(
            fmt,
            "(satp: 0x{:08x}, mode: {}, ASID: {}, PPN: {:08x})",
            self.satp,
            self.satp >> 31,
            self.satp >> 22 & ((1 << 9) - 1),
            (self.satp >> 0 & ((1 << 22) - 1)) << 12,
        )
    }
}

impl MemoryMapping {
    pub fn set(&mut self, new: usize) {
        self.satp = new;
    }
    pub fn get_pid(&self) -> XousPid {
        (self.satp >> 22 & ((1 << 9) - 1)) as XousPid
    }
    pub fn current() -> MemoryMapping {
        MemoryMapping {
            satp: satp::read().bits(),
        }
    }
    pub fn activate(&self) {
        satp::write(self.satp);
    }
}

pub const DEFAULT_MEMORY_MAPPING: MemoryMapping = MemoryMapping { satp: 0 };
