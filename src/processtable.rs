use crate::definitions::{MemoryAddress, XousError, XousPid};
use crate::mem::MemoryManager;
use crate::{filled_array, print, println};
use vexriscv::register::{mstatus, satp};

const MAX_PROCESS_COUNT: usize = 256;

pub struct Process {
    pub satp: usize,
}

impl core::fmt::Debug for Process {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::result::Result<(), core::fmt::Error> {
        write!(
            fmt,
            "Process (satp: 0x{:08x}, mode: {}, ASID: {}, PPN: {:08x})",
            self.satp,
            self.satp >> 31,
            self.satp >> 22 & ((1 << 9) - 1),
            (self.satp >> 0 & ((1 << 22) - 1)) << 9,
        )
    }
}

pub struct ProcessTable {
    processes: [Process; MAX_PROCESS_COUNT],
}

extern "Rust" {
    fn start_kmain(
        kmain: extern "Rust" fn(MemoryManager, ProcessTable) -> !,
        mm: MemoryManager,
        pt: ProcessTable,
    ) -> !;
}

impl ProcessTable {
    pub fn new(mut mm: MemoryManager, kmain: fn(MemoryManager, ProcessTable) -> !) -> ! {
        let mut pt = ProcessTable {
            processes: filled_array![Process { satp: 0 }; 256],
        };

        // Allocate a root page table for PID 1.  Also mark the "ASID" as "1"
        // for "PID 1"
        let root_page = mm.alloc_page(1).unwrap().get();
        pt.processes[1].satp = (root_page >> 9) | (1 << 22);
        mm.create_identity(&pt.processes[1])
            .expect("Unable to create identity mapping");
        println!("PID 1: {:?} root page @ {:08x}", pt.processes[1], root_page);
        println!("Enabling MMU...");
        unsafe {
            // Set the MMU pointer to our identity mapping
            satp::set(
                satp::Mode::Sv32,
                (pt.processes[1].satp >> 22) & ((1 << 9) - 1),
                (pt.processes[1].satp >> 0) & ((1 << 22) - 1),
            );

            // Switch to Supervisor mode
            mstatus::set_mpp(mstatus::MPP::Supervisor);
        };
        println!("MMU enabled, jumping to kmain");
        unsafe { start_kmain(kmain, mm, pt) }
    }
}
