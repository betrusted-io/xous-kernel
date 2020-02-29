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
        unsafe {
            &mut *((0x00801000 + core::mem::size_of::<ProcessContext>()) as *mut ProcessContext)
        }
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

    pub fn get_stack(&self) -> usize {
        self.registers[1]
    }

    pub fn init(&mut self, entrypoint: usize, stack: usize) {
        self.sepc = entrypoint;
        self.registers[1] = stack;
    }
}
