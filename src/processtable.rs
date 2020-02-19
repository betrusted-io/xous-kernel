use crate::args::KernelArguments;
use crate::definitions::{XousError, XousPid};
use core::slice;
use vexriscv::register::{satp, sepc};

const MAX_PROCESS_COUNT: usize = 255;

extern "C" {
    fn return_to_user(satp: usize, pc: usize, sp: usize) -> !;
}

#[derive(Default)]
pub struct Process {
    /// The absolute MMU address.  If 0, then this process is free.
    pub satp: u32,

    /// Where this process is in terms of lifecycle
    pub state: u32,

    /// The last address of the program counter
    pub pc: u32,

    /// Address of the stack pointer
    pub sp: u32,
}

#[repr(C)]
/// The stage1 bootloader sets up some initial processes.  These are reported
/// to us as (satp, entrypoint, sp) tuples, which can be turned into a structure.
/// The first element is always the kernel.
pub struct InitialProcess {
    /// The RISC-V SATP value, which includes the offset of the root page
    /// table plus the process ID.
    satp: u32,

    /// Where execution begins
    entrypoint: u32,

    /// Address of the top of the stack
    sp: u32,
}

/// A big unifying struct containing all of the system state.
/// This is inherited from the stage 1 bootloader.
#[repr(C)]
pub struct SystemServices {
    /// A table of all processes on the system
    pub processes: [Process; MAX_PROCESS_COUNT],
}

impl core::fmt::Debug for Process {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::result::Result<(), core::fmt::Error> {
        write!(
            fmt,
            "Process (satp: 0x{:08x}, mode: {}, ASID: {}, PPN: {:08x}), state: {}, PC: {:08x}, SP: {:08x}",
            self.satp,
            self.satp >> 31,
            self.satp >> 22 & ((1 << 9) - 1),
            (self.satp >> 0 & ((1 << 22) - 1)) << 12,
            self.state,
            self.pc,
            self.sp,
        )
    }
}

impl SystemServices {
    pub fn new(base: *const u32, args: &KernelArguments) -> SystemServices {
        let init_offsets = {
            let mut init_count = 1;
            for arg in args.iter() {
                if arg.name == make_type!("Init") {
                    init_count += 1;
                }
            }
            unsafe { slice::from_raw_parts(base as *const InitialProcess, init_count) }
        };

        use core::mem::MaybeUninit;

        // Rust doesn't have a good way to initialize large arrays.
        let mut array: [MaybeUninit<Process>; MAX_PROCESS_COUNT] =
            unsafe { MaybeUninit::uninit().assume_init() };

        for element in array.iter_mut() {
            let new_process = Process {
                ..Default::default()
            };
            *element = MaybeUninit::new(new_process);
        }
        let mut processes =
            unsafe { core::mem::transmute::<_, [Process; MAX_PROCESS_COUNT]>(array) };
        sprintln!("Iterating over {} processes...", init_offsets.len());
        // Copy over the initial process list
        for init in init_offsets.iter() {
            let pid = ((init.satp >> 22) & ((1 << 9) - 1));
            let ref mut process = processes[pid as usize];
            sprintln!("Process: SATP: {:08x}  PID: {}  Memory: {:08x}  PC: {:08x}  SP: {:08x}",
            init.satp, pid, init.satp << 10, init.entrypoint, init.sp);
            process.satp = init.satp;
            process.pc = init.entrypoint;
            process.sp = init.sp;
        }

        SystemServices { processes }
    }

    pub fn switch_to_pid(&self, pid: XousPid) -> Result<(), XousError> {
        if pid == 0 {
            return Err(XousError::ProcessNotFound);
        }
        // PID0 doesn't exist -- process IDs are offset by 1.
        let pid = pid as usize - 1;
        if self.processes[pid].satp == 0 {
            return Err(XousError::ProcessNotFound);
        }

        let satp = self.processes[pid].satp as usize;
        let pc = self.processes[pid].pc as usize;
        let sp = self.processes[pid].sp as usize;
        let new_satp = (satp >> 12) | ((pid) << 22) | (1 << 31);
        unsafe { return_to_user(new_satp, pc, sp) };
    }
    // /// Switch to the new PID when we return to supervisor mode
    // pub fn switch_to(&self, pid: XousPid, pc: usize) -> Result<(), XousError> {
    //     if pid == 0 {
    //         return Err(XousError::ProcessNotFound);
    //     }
    //     if pid >= 255 {
    //         return Err(XousError::ProcessNotFound);
    //     }

    //     let pid = pid as usize;
    //     let new_satp = self.processes[pid].satp;
    //     if new_satp & (1 << 31) == 0 {
    //         return Err(XousError::ProcessNotFound);
    //     }

    //     unsafe {
    //         CURRENT_SATP = new_satp;
    //     }
    //     satp::write(new_satp & 0x803fffff);
    //     mepc::write(pc);
    //     Ok(())
    // }

    // pub fn alloc_pid(&mut self) -> Result<XousPid, XousError> {
    //     for (idx, process) in self.processes.iter().enumerate() {
    //         if process.satp == 0 {
    //             return Ok((idx + 1) as XousPid);
    //         }
    //     }
    //     Err(XousError::ProcessNotChild)
    // }
}

// impl ProcessTable {
//     pub fn new() -> Result<ProcessTable, XousError> {
//         Ok(ProcessTable {})
//     }

//     pub fn create_process(&mut self, mm: &mut MemoryManager) -> Result<XousPid, XousError> {
//         let mut pt = unsafe { &mut PT };
//         let pid = pt.alloc_pid()?;
//         let root_page = mm.alloc_page(pid).expect("Couldn't allocate memory for new process page tables");
//         let root_page = root_page.get();
//         pt.processes[pid as usize].satp = (root_page >> 12) | ((pid as usize) << 22) | (1 << 31);
//         Ok(pid)
//     }

//     pub fn satp_for(&self, pid: XousPid) -> Result<MemoryAddress, XousError> {
//         let pt = unsafe { &PT };
//         match MemoryAddress::new(pt.processes[pid as usize].satp) {
//             Some(addr) => Ok(addr),
//             None => Err(XousError::ProcessNotFound)
//         }
//     }

//     pub fn switch_to(&self, pid: XousPid, pc: usize) -> Result<(), XousError> {
//         let pt = unsafe { &PT };
//         pt.switch_to(pid, pc)
//     }
// }

// pub fn sys_memory_allocate(
//     phys: Option<MemoryAddress>,
//     virt: Option<MemoryAddress>,
//     size: MemorySize,
// ) -> Result<MemoryAddress, XousError> {
//     // let mut mm = MemoryManager::new()?;
//     // match phys {
//     //     Some(paddr) => match virt {
//     //         Some(vaddr) => return mm.map_page(unsafe { CURRENT_SATP }, paddr.get(), vaddr.get()),
//     //         None => {},
//     //     }
//     //     None => match virt {
//     //         Some(vaddr) => {},
//     //         None => {},
//     //     }
//     // }

//     Ok(MemoryAddress::new(4096).unwrap())
// }
