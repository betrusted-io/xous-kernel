use crate::definitions::{XousError, XousPid, MemoryAddress};
use crate::mem::MemoryManager;
use crate::filled_array;

const MAX_PROCESS_COUNT: usize = 256;

struct Process {
    satp: Option<MemoryAddress>,
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
        pt.processes[1].satp = Some(mm.alloc_page(1).unwrap());
        mm.create_identity(pt.processes[1].satp.unwrap(), 1).expect("Unable to create identity mapping");
        pt
    }
}
