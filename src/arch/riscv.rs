use vexriscv::register::{satp, sie, sstatus};
use xous::XousPid;

pub mod irq;
pub mod mem;
mod start;
pub mod syscall;
pub mod exception;

pub fn current_pid() -> XousPid {
    satp::read().asid() as XousPid
}

pub fn init() {
    unsafe {
        sstatus::set_sie();
        sie::set_ssoft();
        sie::set_sext();
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
/// Everything required to keep track of a single thread of execution.
pub struct ProcessContext {
    /// Storage for all RISC-V registers, minus $zero
    pub registers: [usize; 31],

    /// The return address.  Note that if this context was created
    /// because of an `ecall` instruction, you will need to add `4`
    /// to this before returning, to prevent that instruction from
    /// getting executed again.
    pub sepc: usize,
}

impl ProcessContext {
    /// Returns the current process context, which is stored at the same address
    /// in every process.
    pub fn current() -> &'static mut ProcessContext {
        unsafe { &mut *(0x00801000 as *mut ProcessContext) }
    }

    /// Returns the saved process context, which is stored just above the
    /// current context.
    pub fn saved() -> &'static mut ProcessContext {
        unsafe {
            &mut *((0x00801000 + core::mem::size_of::<ProcessContext>()) as *mut ProcessContext)
        }
    }

    /// Determine whether a process context is valid.
    /// Contexts are valid when they have a place to return to --
    /// i.e. `SEPC` is nonzero
    pub fn valid(&self) -> bool {
        self.sepc != 0
    }

    /// Invalidate a context by removing its return address
    pub fn invalidate(&mut self) {
        self.sepc = 0;
    }

    pub fn get_stack(&self) -> usize {
        self.registers[1]
    }

    /// Initialize this process context with the given entrypoint and stack
    /// addresses.
    pub fn init(&mut self, entrypoint: usize, stack: usize) {
        self.sepc = entrypoint;
        self.registers[1] = stack;
    }
}
