use crate::arch;
use crate::irq::interrupt_claim;
use crate::mem::MemoryManagerHandle;
use crate::processtable::{ProcessState, SystemServicesHandle};
use xous::*;

// extern "Rust" {
//     /// Allocates kernel structures for a new process, and returns the new PID.
//     /// This removes `page_count` page tables from the calling process at `origin_address`
//     /// and places them at `target_address`.
//     ///
//     /// If the process was created successfully, then the new PID is returned to
//     /// the calling process.  The child is not automatically scheduled for running.
//     ///
//     /// # Errors
//     ///
//     /// * **BadAlignment**: `origin_address` or `target_address` were not page-aligned,
//     ///                   or `address_size` was not a multiple of the page address size.
//     /// * **OutOfMemory**: The kernel couldn't allocate memory for the new process.
//     #[allow(dead_code)]
//     pub fn sys_process_spawn(
//         origin_address: MemoryAddress,
//         target_address: MemoryAddress,
//         address_size: MemorySize,
//     ) -> Result<XousPid, XousError>;

//     /// Interrupts the current process and returns control to the parent process.
//     ///
//     /// # Errors
//     ///
//     /// * **ProcessNotFound**: The provided PID doesn't exist, or is not running on the given CPU.
//     #[allow(dead_code)]
//     pub fn sysi_process_suspend(pid: XousPid, cpu_id: XousCpuId) -> Result<(), XousError>;

//     #[allow(dead_code)]
//     pub fn sys_process_resume(
//         process_id: XousPid,
//         stack_pointer: Option<usize>,
//         additional_contexts: &Option<&[XousContext]>,
//     ) -> Result<
//         (
//             Option<XousContext>,
//             Option<XousContext>,
//             Option<XousContext>,
//         ),
//         XousError,
//     >;

//     /// Causes a process to terminate immediately.
//     ///
//     /// It is recommended that this function only be called on processes that
//     /// have cleaned up after themselves, e.g. shut down any servers and
//     /// flushed any file descriptors.
//     ///
//     /// # Errors
//     ///
//     /// * **ProcessNotFound**: The requested process does not exist
//     /// * **ProcessNotChild**: The requested process is not our child process
//     #[allow(dead_code)]
//     pub fn sys_process_terminate(process_id: XousPid) -> Result<(), XousError>;

//     /// Equivalent to the Unix `sbrk` call.  Adjusts the
//     /// heap size to be equal to the specified value.  Heap
//     /// sizes start out at 0 bytes in new processes.
//     ///
//     /// # Errors
//     ///
//     /// * **OutOfMemory**: The region couldn't be extended.
//     #[allow(dead_code)]
//     pub fn sys_heap_resize(size: MemorySize) -> Result<(), XousError>;

//     ///! Message Passing Functions

//     /// Create a new server with the given name.  This enables other processes to
//     /// connect to this server to send messages.  Only one server name may exist
//     /// on a system at a time.
//     ///
//     /// # Errors
//     ///
//     /// * **ServerExists**: A server has already registered with that name
//     /// * **InvalidString**: The name was not a valid UTF-8 string
//     #[allow(dead_code)]
//     pub fn sys_server_create(server_name: usize) -> Result<XousSid, XousError>;

//     /// Suspend the current process until a message is received.  This thread will
//     /// block until a message is received.
//     ///
//     /// # Errors
//     ///
//     #[allow(dead_code)]
//     pub fn sys_server_receive(server_id: XousSid) -> Result<XousMessageReceived, XousError>;

//     /// Reply to a message received.  The thread will be unblocked, and will be
//     /// scheduled to run sometime in the future.
//     ///
//     /// If the message that we're responding to is a Memory message, then it should be
//     /// passed back directly to the destination without modification -- the actual contents
//     /// will be passed in the `out` address pointed to by the structure.
//     ///
//     /// # Errors
//     ///
//     /// * **ProcessTerminated**: The process we're replying to doesn't exist any more.
//     /// * **BadAddress**: The message didn't pass back all the memory it should have.
//     #[allow(dead_code)]
//     pub fn sys_server_reply(
//         destination: XousMessageSender,
//         message: XousMessage,
//     ) -> Result<(), XousError>;

//     /// Look up a server name and connect to it.
//     ///
//     /// # Errors
//     ///
//     /// * **ServerNotFound**: No server is registered with that name.
//     #[allow(dead_code)]
//     pub fn sys_client_connect(server_name: usize) -> Result<XousConnection, XousError>;

//     /// Send a message to a server.  This thread will block until the message is responded to.
//     /// If the message type is `Memory`, then the memory addresses pointed to will be
//     /// unavailable to this process until this function returns.
//     ///
//     /// # Errors
//     ///
//     /// * **ServerNotFound**: The server does not exist so the connection is now invalid
//     /// * **BadAddress**: The client tried to pass a Memory message using an address it doesn't own
//     /// * **Timeout**: The timeout limit has been reached
//     #[allow(dead_code)]
//     pub fn sys_client_send(
//         server: XousConnection,
//         message: XousMessage,
//     ) -> Result<XousMessage, XousError>;
// }

pub fn handle(call: SysCall) -> XousResult {
    let pid = arch::current_pid();

    println!("PID{} Syscall: {:?}", pid, call);
    match call {
        SysCall::MapPhysical(phys, virt, size, req_flags) => {
            let mut mm = MemoryManagerHandle::get();
            if pid != 1 && (virt as usize) != 0 && (virt as usize) < arch::mem::USER_AREA_START {
                return XousResult::Error(XousError::BadAddress);
            } else if size & 4095 != 0 {
                // println!("map: bad alignment of size {:08x}", size);
                return XousResult::Error(XousError::BadAlignment);
            }
            // println!(
            //     "Mapping {:08x} -> {:08x} ({} bytes, flags: {:?})",
            //     phys as u32, virt as u32, size, req_flags
            // );
            mm.map_range(phys, virt, size, req_flags)
                .map(|_x| XousResult::ReturnResult)
                .unwrap_or_else(|e| XousResult::Error(e))
        }
        SysCall::SwitchTo(pid, context) => {
            if context as usize != 0 {
                panic!("specifying a context page is not yet supported");
            }
            let mut ss = SystemServicesHandle::get();
            ss.resume_pid(pid, ProcessState::Ready)
                .map(|_| XousResult::ResumeProcess)
                .unwrap_or_else(|e| XousResult::Error(e))
        }
        SysCall::ClaimInterrupt(no, callback, arg) => {
            interrupt_claim(no, pid as definitions::XousPid, callback, arg)
                .map(|_| XousResult::ReturnResult)
                .unwrap_or_else(|e| XousResult::Error(e))
        }
        SysCall::Yield => {
            let mut ss = SystemServicesHandle::get();
            let ppid = ss.get_process(pid).expect("Can't get current process").ppid;
            assert_ne!(ppid, 0, "no parent process id");
            ss.resume_pid(ppid, ProcessState::Ready)
                .map(|_| XousResult::ResumeProcess)
                .unwrap_or(XousResult::Error(XousError::ProcessNotFound))
        }
        SysCall::WaitEvent => {
            let mut ss = SystemServicesHandle::get();
            let process = ss.get_process(pid).expect("Can't get current process");
            let ppid = process.ppid;
            assert_ne!(ppid, 0, "no parent process id");
            ss.resume_pid(ppid, ProcessState::Sleeping)
                .map(|_| XousResult::ResumeProcess)
                .unwrap_or(XousResult::Error(XousError::ProcessNotFound))
        }
        _ => XousResult::Error(XousError::UnhandledSyscall),
    }
}
