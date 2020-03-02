use crate::arch;
use crate::args::KernelArguments;
use crate::definitions::{XousError, XousPid};
use core::slice;
// use vexriscv::register::{satp, sepc, sstatus};
use crate::arch::mem::MemoryMapping;
pub use crate::arch::ProcessContext;

const MAX_PROCESS_COUNT: usize = 254;
pub const RETURN_FROM_ISR: usize = 0x0080_2000;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ProcessState {
    /// This is an unallocated, free process
    Free,

    /// This is a brand-new process that hasn't been run
    /// yet, and needs its stack and entrypoint set up.
    Setup(usize /* entrypoint */, usize /* stack */),

    /// This process is able to be run
    Ready,

    /// This is the current active process
    Running,

    /// This process is waiting for an event, such as
    /// as message or an interrupt
    Sleeping,
}

impl Default for ProcessState {
    fn default() -> ProcessState {
        ProcessState::Free
    }
}

#[derive(Copy, Clone, Default)]
pub struct Process {
    /// The absolute MMU address.  If 0, then this process is free.
    pub mapping: MemoryMapping,

    /// Where this process is in terms of lifecycle
    state: ProcessState,

    /// The process that created this process, which tells
    /// who is allowed to manipulate this process.
    pub ppid: XousPid,

    /// Default virtual address when MapMemory is called with no `virt`
    pub mem_default_base: usize,

    /// Address where messages are passed into
    pub mem_message_base: usize,

    /// Base address of the heap
    pub mem_heap_base: usize,

    /// Current size of the heap
    pub mem_heap_size: usize,

    /// Maximum size of the heap
    pub mem_heap_max: usize,
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
        state: ProcessState::Free,
        ppid: 0,
        mapping: arch::mem::DEFAULT_MEMORY_MAPPING,
        mem_default_base: arch::mem::DEFAULT_BASE,
        mem_message_base: arch::mem::DEFAULT_MESSAGE_BASE,
        mem_heap_base: arch::mem::DEFAULT_HEAP_BASE,
        mem_heap_size: 0,
        mem_heap_max: 0,
    }; MAX_PROCESS_COUNT],
};

impl core::fmt::Debug for Process {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::result::Result<(), core::fmt::Error> {
        write!(
            fmt,
            "Process state: {:?}  Memory mapping: {:?}",
            self.state, self.mapping
        )
    }
}

impl SystemServices {
    /// Create a new "System Services" object based on the arguments from the kernel.
    /// These arguments decide where the memory spaces are located, as well as where
    /// the stack and program counter should initially go.
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
            // println!("Process: SATP: {:08x}  PID: {}  Memory: {:08x}  PC: {:08x}  SP: {:08x}  Index: {}",
            // init.satp, pid, init.satp << 10, init.entrypoint, init.sp, pid-1);
            unsafe { process.mapping.from_raw(init.satp) };
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
        let pid_idx = pid as usize - 1;
        if self.processes[pid_idx].mapping.get_pid() != pid {
            println!(
                "Process doesn't match ({} vs {})",
                self.processes[pid_idx].mapping.get_pid(),
                pid
            );
            return Err(XousError::ProcessNotFound);
        }
        Ok(&mut self.processes[pid_idx])
    }

    pub fn current_pid(&self) -> XousPid {
        let pid = arch::current_pid();
        assert_ne!(pid, 0, "no current process");
        // PID0 doesn't exist -- process IDs are offset by 1.
        assert_eq!(
            self.processes[pid as usize - 1].mapping,
            MemoryMapping::current(),
            "process memory map doesn't match -- current_pid: {}",
            pid
        );
        pid as XousPid
    }

    pub fn current_process(&mut self) -> Result<&mut Process, XousError> {
        let pid = self.current_pid();
        self.get_process(pid)
    }

    /// Create a stack frame in the specified process and jump to it.
    /// 1. Pause the current process and switch to the new one
    /// 2. Save the process state, if it hasn't already been saved
    /// 3. Run the new process, returning to an illegal instruction
    pub fn make_callback_to(
        &mut self,
        pid: XousPid,
        pc: *const usize,
        irq_no: usize,
        arg: *mut usize,
    ) -> Result<(), XousError> {
        // Get the current process (which was just interrupted) and mark
        // it as "ready to run".
        {
            let current_pid = self.current_pid();
            let mut current = self
                .get_process(current_pid)
                .expect("couldn't get current PID");
            assert_eq!(
                current.state,
                ProcessState::Running,
                "current process was not running"
            );
            current.state = ProcessState::Ready;
        }

        // Get the new process, and ensure that it is in a state where it's fit to run.
        let mut process = self.get_process(pid)?;
        match process.state {
            ProcessState::Ready | ProcessState::Running | ProcessState::Sleeping => (),
            ProcessState::Free => panic!("process was not allocated"),
            ProcessState::Setup(_, _) => panic!("process hasn't been set up yet"),
        }
        process.state = ProcessState::Running;

        // Switch to new process memory space, allowing us to save the context
        // if necessary.
        process.mapping.activate();

        let context = ProcessContext::current();

        // Save previous context (if it's not already saved)
        let saved = ProcessContext::saved();
        if !saved.valid() {
            *saved = *context;
        }

        arch::syscall::invoke(
            pid == 1,
            pc as usize,
            context.get_stack(),
            RETURN_FROM_ISR,
            &[irq_no, arg as usize],
        );
    }

    /// Resume the given process, picking up exactly where it left off.
    /// If the process is in the Setup state, set it up and then resume.
    pub fn resume_pid(
        &mut self,
        pid: XousPid,
        previous_state: ProcessState,
    ) -> Result<(), XousError> {
        let previous_pid = self.current_pid();

        // Save state if the PID has changed
        let context = if pid != previous_pid {
            let context = {
                let new = self.get_process(pid)?;
                match new.state {
                    ProcessState::Free => return Err(XousError::ProcessNotFound),
                    _ => (),
                }

                new.mapping.activate();

                let context = ProcessContext::current();

                // Set up the new process, if necessary
                match new.state {
                    ProcessState::Setup(entrypoint, stack) => {
                        context.init(entrypoint, stack);
                    }
                    ProcessState::Free => panic!("process was suddenly Free"),
                    ProcessState::Ready | ProcessState::Sleeping => (),
                    ProcessState::Running => panic!("process was already running"),
                }
                new.state = ProcessState::Running;
                context
            };

            // Mark the previous process as ready to run, since we just switched away
            {
                self.get_process(previous_pid)
                    .expect("couldn't get previous pid")
                    .state = previous_state;
            }
            context
        } else {
            ProcessContext::current()
        };

        // Restore the previous context, if one exists.
        let previous = ProcessContext::saved();
        if previous.valid() {
            println!("Previous context was valid -- invalidating current context");
            *context = *previous;
            previous.invalidate();
        }

        arch::syscall::resume(pid == 1, &context);
    }
}
