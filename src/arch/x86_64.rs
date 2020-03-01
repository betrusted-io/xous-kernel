use xous::{XousPid, XousResult};

pub mod irq {
    /// Disable external interrupts
    pub fn disable_all_irqs() {
        unimplemented!();
    }

    /// Enable external interrupts
    pub fn enable_all_irqs() {
        unimplemented!();
    }

    pub fn enable_irq(irq_no: usize) {
        unimplemented!();
    }

    pub fn disable_irq(irq_no: usize) {
        unimplemented!();
    }
}

pub fn current_pid() -> XousPid {
    unimplemented!();
}

pub fn init() {
}

pub mod syscall {
    use crate::arch::ProcessContext;
    pub fn invoke(supervisor: bool, pc: usize, sp: usize, ret_addr: usize, args: &[usize]) -> ! {
        unimplemented!();
    }

    fn set_supervisor(supervisor: bool) {
        unimplemented!();
    }

    pub fn resume(supervisor: bool, context: &ProcessContext) -> ! {
        unimplemented!();
    }
}

pub mod mem {
    use xous::{XousError, XousPid, MemoryFlags};
    use crate::mem::MemoryManager;
    #[derive(Copy, Clone, Default, PartialEq)]
    pub struct MemoryMapping {}
    impl MemoryMapping {
        pub fn set_raw(&mut self, new: usize) {
            unimplemented!();
        }
        pub fn get_pid(&self) -> XousPid {
            unimplemented!();
        }
        pub fn current() -> MemoryMapping {
            unimplemented!();
        }
        pub fn activate(&self) {
            unimplemented!();
        }
    }

    impl core::fmt::Debug for MemoryMapping {
        fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::result::Result<(), core::fmt::Error> {
            write!(fmt, "unimplemented",)
        }
    }

    pub fn map_page_inner(
        mm: &mut MemoryManager,
        pid: XousPid,
        phys: usize,
        virt: usize,
        req_flags: MemoryFlags,
    ) -> Result<(), XousError> {
        unimplemented!();
    }

    pub fn unmap_page_inner(
        mm: &mut MemoryManager,
        pid: XousPid,
        phys: usize,
        virt: usize,
        req_flags: MemoryFlags,
    ) -> Result<(), XousError> {
        unimplemented!();
    }

    pub const DEFAULT_MEMORY_MAPPING: MemoryMapping = MemoryMapping {};

    pub const DEFAULT_STACK_TOP: usize = 0xffff_0000;
    pub const DEFAULT_HEAP_BASE: usize = 0x4000_0000;
    pub const DEFAULT_MESSAGE_BASE: usize = 0x8000_0000;
    pub const DEFAULT_BASE: usize = 0xc000_0000;

    pub const USER_AREA_START: usize = 0x00c0_0000;
    pub const PAGE_SIZE: usize = 4096;
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct ProcessContext {}

impl ProcessContext {
    pub fn current() -> &'static mut ProcessContext {
        unimplemented!();
    }
    pub fn saved() -> &'static mut ProcessContext {
        unimplemented!();
    }

    /// Determine whether a process context is valid.
    /// Contexts are valid when the `SATP.VALID` bit is `1`.
    pub fn valid(&self) -> bool {
        unimplemented!();
    }

    /// Invalidate a context by setting its `SATP.VALID` bit to 0.
    pub fn invalidate(&mut self) {
        unimplemented!();
    }

    pub fn get_stack(&self) -> usize {
        unimplemented!();
    }
    pub fn init(&mut self, entrypoint: usize, stack: usize) {
    }
}

#[cfg(test)]
#[no_mangle]
pub extern "Rust" fn _xous_syscall_rust(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize, ret: &mut XousResult) {
    unimplemented!();
}

#[cfg(test)]
#[no_mangle]
fn _xous_syscall(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize, ret: &mut XousResult) {
    unimplemented!();
}
