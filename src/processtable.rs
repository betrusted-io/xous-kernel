use crate::definitions::{MemoryAddress, MemorySize, XousError, XousPid};
use crate::mem::MemoryManager;
use crate::{filled_array, print, println};
use vexriscv::register::{mepc, mstatus, satp};
use vexriscv::asm::sfence_vma;

const MAX_PROCESS_COUNT: usize = 256;
static mut CURRENT_SATP: usize = 0;

pub struct Process {
    pub satp: usize,
}

pub struct ProcessTableInner {
    processes: [Process; MAX_PROCESS_COUNT],
}

pub struct ProcessTable {}

static mut PT: ProcessTableInner = ProcessTableInner {
    processes: filled_array![Process { satp: 0 }; 256],
};

extern "Rust" {
    fn kmain(mm: MemoryManager, pt: ProcessTable) -> !;
    fn flush_mmu(r1: usize, r2: usize);
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

impl ProcessTableInner {
    /// Switch to the new PID when we return to supervisor mode
    pub fn switch_to(&self, pid: XousPid, pc: usize) -> Result<(), XousError> {
        if pid == 0 {
            return Err(XousError::ProcessNotFound);
        }
        if pid >= 255 {
            return Err(XousError::ProcessNotFound);
        }

        let pid = pid as usize;
        let new_satp = self.processes[pid].satp;
        if new_satp & (1 << 31) == 0 {
            return Err(XousError::ProcessNotFound);
        }

        unsafe {
            CURRENT_SATP = new_satp;
        }
        satp::write(new_satp);
        mepc::write(pc);
        unsafe { flush_mmu(0, 0) };
        Ok(())
    }

    pub fn alloc_pid(&mut self) -> Result<XousPid, XousError> {
        for (idx, process) in self.processes.iter().enumerate() {
            if process.satp == 0 {
                return Ok((idx + 1) as XousPid);
            }
        }
        Err(XousError::ProcessNotChild)
    }
}

impl ProcessTable {
    pub fn new() -> Result<ProcessTable, XousError> {
        Ok(ProcessTable {})
    }

    pub fn create_process(&mut self, mm: &mut MemoryManager) -> Result<XousPid, XousError> {
        let mut pt = unsafe { &mut PT };
        let pid = pt.alloc_pid()?;
        let root_page = mm.alloc_page(pid).expect("Couldn't allocate memory for new process page tables");
        let root_page = root_page.get();
        pt.processes[pid as usize].satp = (root_page >> 12) | ((pid as usize) << 22) | (1 << 31);
        Ok(pid)
    }

    pub fn satp_for(&self, pid: XousPid) -> Result<MemoryAddress, XousError> {
        let pt = unsafe { &PT };
        match MemoryAddress::new(pt.processes[pid as usize].satp) {
            Some(addr) => Ok(addr),
            None => Err(XousError::ProcessNotFound)
        }
    }

    pub fn switch_to(&self, pid: XousPid, pc: usize) -> Result<(), XousError> {
        let pt = unsafe { &PT };
        pt.switch_to(pid, pc)
    }
}

pub fn sys_memory_allocate(
    phys: Option<MemoryAddress>,
    virt: Option<MemoryAddress>,
    size: MemorySize,
) -> Result<MemoryAddress, XousError> {
    let mut mm = MemoryManager::new()?;
    match phys {
        Some(paddr) => match virt {
            Some(vaddr) => return mm.map_page(unsafe { CURRENT_SATP }, paddr.get(), vaddr.get()),
            None => {},
        }
        None => match virt {
            Some(vaddr) => {},
            None => {},
        }
    }

    Ok(MemoryAddress::new(4096).unwrap())
}
