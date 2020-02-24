use crate::args::KernelArguments;
use crate::definitions::{XousError, XousPid};
use core::slice;
use vexriscv::register::{satp, sepc, sstatus};

const MAX_PROCESS_COUNT: usize = 32;

extern "C" {
    fn return_to_user(sp: usize, regs: *const usize) -> !;
    fn flush_mmu();
}

#[derive(Default, Copy, Clone)]
pub struct Process {
    /// The absolute MMU address.  If 0, then this process is free.
    pub satp: usize,

    /// All registers (except $zero, $sp, and $pc)
    pub regs: [usize; 29],

    /// Where this process is in terms of lifecycle
    pub state: u32,

    /// Address of the stack pointer
    pub sp: usize,

    /// The last address of the program counter
    pub pc: usize,
}

#[repr(C)]
/// The stage1 bootloader sets up some initial processes.  These are reported
/// to us as (satp, entrypoint, sp) tuples, which can be turned into a structure.
/// The first element is always the kernel.
pub struct InitialProcess {
    /// The RISC-V SATP value, which includes the offset of the root page
    /// table plus the process ID.
    satp: usize,

    /// Where execution begins
    entrypoint: usize,

    /// Address of the top of the stack
    sp: usize,
}

/// A big unifying struct containing all of the system state.
/// This is inherited from the stage 1 bootloader.
#[repr(C)]
pub struct SystemServices {
    /// A table of all processes on the system
    pub processes: [Process; MAX_PROCESS_COUNT],
}

static mut SYSTEM_SERVICES: SystemServices = SystemServices {
    processes: [Process { satp: 0, state: 0, pc: 0, sp: 0, regs: [0; 29]}; MAX_PROCESS_COUNT],
};

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
    pub fn new(base: *const u32, args: &KernelArguments) -> &'static mut SystemServices {
        let init_offsets = {
            let mut init_count = 1;
            for arg in args.iter() {
                if arg.name == make_type!("Init") {
                    init_count += 1;
                }
            }
            unsafe { slice::from_raw_parts(base as *const InitialProcess, init_count) }
        };

        let ref mut ss = unsafe { &mut SYSTEM_SERVICES };
        // println!("Iterating over {} processes...", init_offsets.len());
        // Copy over the initial process list
        for init in init_offsets.iter() {
            let pid = (init.satp >> 22) & ((1 << 9) - 1);
            let ref mut process = ss.processes[(pid - 1) as usize];
            // println!("Process: SATP: {:08x}  PID: {}  Memory: {:08x}  PC: {:08x}  SP: {:08x}",
            // init.satp, pid, init.satp << 10, init.entrypoint, init.sp);
            process.satp = init.satp;
            process.pc = init.entrypoint;
            process.sp = init.sp;
        }

        unsafe { &mut SYSTEM_SERVICES }
    }

    pub unsafe fn get() -> &'static mut SystemServices {
        &mut SYSTEM_SERVICES
    }

    fn get_process(&self, pid: XousPid) -> Result<&Process, XousError> {
        if pid == 0 {
            println!("Process not found -- PID is 0");
            return Err(XousError::ProcessNotFound);
        }
        // PID0 doesn't exist -- process IDs are offset by 1.
        let pid = pid as usize - 1;
        if self.processes[pid].satp == 0 {
            println!("Process not found -- SATP is 0");
            return Err(XousError::ProcessNotFound);
        }
        if (self.processes[pid].satp >> 22 & ((1 << 9) - 1)) != (pid+1) as usize {
            println!("Process doesn't match ({} vs {})",
            self.processes[pid].satp >> 22 & ((1 << 9) - 1), (pid+1));
            return Err(XousError::ProcessNotFound);
        }
        println!("Found PID");
        Ok(&self.processes[pid])
    }

    pub fn make_callback_to(&self, pid: XousPid, pc: *const usize, arg: *mut usize) -> Result<(), XousError> {
        let process = self.get_process(pid)?;
        satp::write(process.satp);
        sepc::write(pc as usize);
        let mut regs = [0; 29];
        regs[9] = arg as usize;
        regs[0] = 0x50105017;
        unsafe { sstatus::set_spp(sstatus::SPP::Supervisor) };
        unsafe { return_to_user(process.sp, regs.as_ptr()) };
    }

    pub fn switch_to_pid_at(&self, pid: XousPid, pc: *const usize, sp: *mut usize) -> Result<(), XousError> {
        let process = self.get_process(pid)?;
        satp::write(process.satp);
        sepc::write(pc as usize);
        unsafe { return_to_user(sp as usize, process.regs.as_ptr()) };
    }

    pub fn resume_pid(&self, pid: XousPid) -> Result<(), XousError> {
        let process = self.get_process(pid)?;

        let pc = process.pc;
        let sp = process.sp;
        println!("Changing SATP: {:08x}", process.satp);
        satp::write(process.satp);
        println!("Setting SEPC");
        sepc::write(pc);

        // Return to user mode
        unsafe { sstatus::set_spp(sstatus::SPP::User) };
        println!(">>>>>> PID {}, SP: {:08x}, PC: {:08x}", (pid+1), sp as usize, pc as usize);
        unsafe {
            use crate::mem::MemoryManager;
            let mm = MemoryManager::get();
            mm.print();
        }
        unsafe { return_to_user(sp, process.regs.as_ptr()) };
    }
}
