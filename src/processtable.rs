use crate::args::KernelArguments;
use crate::definitions::{XousError, XousPid};
use core::slice;
use vexriscv::register::{satp, sepc, sstatus};

const MAX_PROCESS_COUNT: usize = 32;

#[repr(C)]
#[derive(Copy, Clone)]
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
}

#[derive(Debug, Copy, Clone)]
enum ProcessState {
    Free,
    Setup(usize /* entrypoint */, usize /* stack */),
    Ready,
    Running,
}

extern "C" {
    fn return_to_user(regs: *const usize) -> !;
}

#[derive(Copy, Clone)]
pub struct Process {
    /// The absolute MMU address.  If 0, then this process is free.
    pub satp: usize,

    /// Where this process is in terms of lifecycle
    state: ProcessState,
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
    processes: [Process {
        satp: 0,
        state: ProcessState::Free,
    }; MAX_PROCESS_COUNT],
};

impl core::fmt::Debug for Process {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::result::Result<(), core::fmt::Error> {
        write!(
            fmt,
            "Process (satp: 0x{:08x}, mode: {}, ASID: {}, PPN: {:08x}), state: {:?}",
            self.satp,
            self.satp >> 31,
            self.satp >> 22 & ((1 << 9) - 1),
            (self.satp >> 0 & ((1 << 22) - 1)) << 12,
            self.state,
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
            process.state = ProcessState::Setup(init.entrypoint, init.sp);
        }

        unsafe { &mut SYSTEM_SERVICES }
    }

    pub unsafe fn get() -> &'static mut SystemServices {
        &mut SYSTEM_SERVICES
    }

    fn get_process(&mut self, pid: XousPid) -> Result<&mut Process, XousError> {
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
        if (self.processes[pid].satp >> 22 & ((1 << 9) - 1)) != (pid + 1) as usize {
            println!(
                "Process doesn't match ({} vs {})",
                self.processes[pid].satp >> 22 & ((1 << 9) - 1),
                (pid + 1)
            );
            return Err(XousError::ProcessNotFound);
        }
        println!("Found PID");
        Ok(&mut self.processes[pid])
    }

    fn current_process(&mut self) -> Result<&mut Process, XousError> {
        let pid = satp::read().asid() as XousPid;
        if pid == 0 {
            panic!("No current process!");
        }
        // PID0 doesn't exist -- process IDs are offset by 1.
        let pid = pid as usize - 1;
        if self.processes[pid].satp == 0 {
            panic!("Current process not found -- SATP is 0");
        }
        if self.processes[pid].satp != satp::read().bits() {
            panic!("Process SATP doesn't match!");
        }
        println!("Found PID");
        Ok(&mut self.processes[pid])
    }

    pub fn make_callback_to(
        &mut self,
        pid: XousPid,
        pc: *const usize,
        irq_no: usize,
        arg: *mut usize,
    ) -> Result<(), XousError> {
        let process = self.get_process(pid)?;
        satp::write(process.satp);
        let context = ProcessContext::current();
        sepc::write(pc as usize);
        let mut regs = [0; 31];
        regs[9] = irq_no as usize;
        regs[10] = arg as usize;
        regs[0] = 0x00802000;
        regs[1] = context.registers[1];
        let mode = if pid == 1 {
            sstatus::SPP::Supervisor
        } else {
            sstatus::SPP::User
        };
        unsafe { sstatus::set_spp(mode) };
        unsafe { return_to_user(regs.as_ptr()) };
    }

    // pub fn switch_to_pid_at(
    //     &self,
    //     pid: XousPid,
    //     pc: *const usize,
    //     sp: *mut usize,
    // ) -> Result<(), XousError> {
    //     let process = self.get_process(pid)?;
    //     satp::write(process.satp);
    //     sepc::write(pc as usize);
    //     unsafe { return_to_user(sp as usize, process.regs.as_ptr()) };
    // }

    /// Resume the given process, picking up exactly where it left off.
    /// If the process is in the Setup state, set it up and then resume.
    pub fn resume_pid(&mut self, pid: XousPid) -> Result<(), XousError> {
        let current = self.current_process().expect("couldn't get current process");
        // XXX This should go back to "Running" upon failure!
        current.state = ProcessState::Ready;

        let process = self.get_process(pid)?;
        match process.state {
            ProcessState::Free => return Err(XousError::ProcessNotFound),
            _ => ()
        }

        println!("Changing SATP: {:08x}", process.satp);
        satp::write(process.satp);

        let context = ProcessContext::current();

        if let ProcessState::Setup(entrypoint, stack) = process.state {
            println!("Process State is `setup`: {:08x} SP: {:08x}", entrypoint, stack);
            context.sepc = entrypoint;
            context.registers[1] = stack;
        }
        else {
            println!("Process is already set up");
        }
        process.state = ProcessState::Running;
        println!("Setting SEPC");
        sepc::write(context.sepc);

        // Return to user mode
        if pid == 1 {
            unsafe { sstatus::set_spp(sstatus::SPP::Supervisor) };
        } else {
            unsafe { sstatus::set_spp(sstatus::SPP::User) };
        }

        println!(
            ">>>>>> PID {}, SP: {:08x}, PC: {:08x}",
            pid,
            context.registers[1],
            context.sepc
        );
        unsafe {
            use crate::mem::MemoryManager;
            let mm = MemoryManager::get();
            mm.print_map();
        }
        unsafe { return_to_user(context.registers.as_ptr()) };
    }
}
