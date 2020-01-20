use crate::definitions::{XousError, XousPid, MemoryAddress};
use crate::mem::MemoryManager;
use crate::{filled_array, println, print};

const MAX_PROCESS_COUNT: usize = 256;

struct Process {
    satp: Option<MemoryAddress>,
}

impl core::fmt::Debug for Process {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::result::Result<(), core::fmt::Error> {
        write!(fmt, "Process (satp: 0x{:08x})", match self.satp { Some(s) => s.get(), None => 0 })
    }
}

pub struct ProcessTable {
    processes: [Process; MAX_PROCESS_COUNT],
}

impl ProcessTable {
    pub fn new(mm: &mut MemoryManager) -> Self {
        let mut pt = ProcessTable {
            processes: filled_array![Process { satp: None }; 256],
        };

        // Allocate a root page table for PID 1
        // mm.create_identity(1).expect("Unable to create identity mapping");
        pt.processes[1].satp = Some(mm.alloc_page(1).unwrap());
        println!("PID 1: {:?}", pt.processes[1]);
        pt
    }
}
