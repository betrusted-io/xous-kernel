use crate::args::KernelArguments;
use crate::definitions::{XousError, XousPid};
use core::mem;
use core::slice;
use vexriscv::register::{satp, sepc, sstatus};

const MAX_PROCESS_COUNT: usize = 254;
pub const RETURN_FROM_ISR: usize = 0x0080_2000;

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
        unsafe { &mut *((0x00801000 + mem::size_of::<ProcessContext>()) as *mut ProcessContext) }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
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

    /// The process that created this process, which tells
    /// who is allowed to manipulate this process.
    pub ppid: XousPid,
}

impl Process {
    pub fn runnable(&self) -> bool {
        match self.state {
            ProcessState::Setup(_, _) | ProcessState::Ready => true,
            _ => false,
        }
    }
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
        ppid: 0,
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
            process.ppid = if pid == 1 { 0 } else { 1 };
            process.state = ProcessState::Setup(init.entrypoint, init.sp);
        }

        unsafe { &mut SYSTEM_SERVICES }
    }

    pub unsafe fn get() -> &'static mut SystemServices {
        &mut SYSTEM_SERVICES
    }

    pub fn get_process(&mut self, pid: XousPid) -> Result<&mut Process, XousError> {
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
        Ok(&mut self.processes[pid])
    }

    fn current_pid(&mut self) -> XousPid {
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
        pid as XousPid + 1
    }

    pub fn make_callback_to(
        &mut self,
        pid: XousPid,
        pc: *const usize,
        irq_no: usize,
        arg: *mut usize,
    ) -> Result<(), XousError> {
        {
            let current_pid = self.current_pid();
            let mut current = self.get_process(current_pid).expect("couldn't get current PID");
            assert_eq!(current.state, ProcessState::Running, "current process was not running");
            current.state = ProcessState::Ready;
        }

        let mut process = self.get_process(pid)?;
        assert_eq!(process.state, ProcessState::Ready, "target process was not ready");
        process.state = ProcessState::Running;

        // Switch to new process memory space
        satp::write(process.satp);

        let context = ProcessContext::current();

        // Save previous context (if it's not already saved)
        let saved = ProcessContext::saved();
        if saved.satp == 0 {
            println!("Saving SATP for PID {}", pid);
            *saved = *context;
        }

        sepc::write(pc as usize);
        let mut regs = [0; 31];
        regs[9] = irq_no as usize;
        regs[10] = arg as usize;
        regs[0] = RETURN_FROM_ISR;
        regs[1] = context.registers[1];
        let mode = if pid == 1 {
            sstatus::SPP::Supervisor
        } else {
            sstatus::SPP::User
        };
        println!("Callback to PID {}, SP: {:08x}, PC: {:08x}", pid, context.registers[1], pc as usize);
        unsafe { sstatus::set_spp(mode) };
        unsafe { return_to_user(regs.as_ptr()) };
    }

    /// Resume the given process, picking up exactly where it left off.
    /// If the process is in the Setup state, set it up and then resume.
    pub fn resume_pid(&mut self, pid: XousPid) -> Result<(), XousError> {
        let previous_pid = self.current_pid();

        // Save state if the PID has changed
        let context = if pid != previous_pid {
            let context = {
                let new = self.get_process(pid)?;
                match new.state {
                    ProcessState::Free => return Err(XousError::ProcessNotFound),
                    _ => (),
                }

                satp::write(new.satp);

                let context = ProcessContext::current();

                match new.state {
                    ProcessState::Setup(entrypoint, stack) => {
                        context.sepc = entrypoint;
                        context.registers[1] = stack;
                    }
                    ProcessState::Free => panic!("process was suddenly Free"),
                    ProcessState::Ready => (),
                    ProcessState::Running => panic!("process was already running"),
                }
                new.state = ProcessState::Running;
                context
            };

            // Mark the previous process as ready to run, since we just switched away
            {
                self.get_process(previous_pid)
                    .expect("couldn't get previous pid")
                    .state = ProcessState::Ready;
            }
            context
        } else {
            ProcessContext::current()
        };

        // Restore the previous context, if one exists.
        let previous = ProcessContext::saved();
        if previous.satp != 0 {
            println!("Restoring previous context (current PC: {:08x}, new PC: {:08x})", context.sepc, previous.sepc);
            *context = *previous;
            previous.satp = 0;
        }

        sepc::write(context.sepc);

        // Return to user mode
        if pid == 1 {
            unsafe { sstatus::set_spp(sstatus::SPP::Supervisor) };
        } else {
            unsafe { sstatus::set_spp(sstatus::SPP::User) };
        }

        println!(
            "Switching to PID {}, SP: {:08x}, PC: {:08x}",
            pid, context.registers[1], context.sepc
        );
        unsafe { return_to_user(context.registers.as_ptr()) };
    }
}
