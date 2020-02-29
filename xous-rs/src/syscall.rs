use crate::{XousPid, XousCpuId, XousError};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

bitflags! {
    /// Flags to be passed to the MapMemory struct.
    /// Note that it is an error to have memory be
    /// writable and not readable.
    pub struct MemoryFlags: usize {
        /// Immediately allocate this memory.  Otherwise it will
        /// be demand-paged.  This is implicitly set when `phys`
        /// is not 0.
        const RESERVE   = 0b00000001;

        /// Allow the CPU to read from this page.
        const R         = 0b00000010;

        /// Allow the CPU to write to this page.
        const W         = 0b00000100;

        /// Allow the CPU to execute from this page.
        const X         = 0b00001000;
    }
}

#[derive(Debug)]
pub enum SysCall {
    /// Allocates pages of memory, equal to a total of `size
    /// bytes.  If a physical address is specified, then this
    /// can be used to allocate regions such as memory-mapped I/O.
    /// If a virtual address is specified, then the returned
    /// pages are located at that address.  Otherwise, they
    /// are located at an unspecified offset.
    ///
    /// You can drop memory privileges by calling `MapMeory` with
    /// the same `virt` parameter, but different `MemoryFlags`.
    /// Note that you can only remove bits by doing this --
    /// you cannot add bits.  For example, you could securely load
    /// a program by mapping its `.text` section, then have it
    /// drop read and write flags in order to make the text section
    /// execute-only.
    ///
    /// # Errors
    ///
    /// * **BadAlignment**: Either the physical or virtual addresses aren't page-aligned,
    ///                     or the size isn't a multiple of the page width.
    /// * **OutOfMemory**: A contiguous chunk of memory couldn't be found, or the system's
    ///                    memory size has been exceeded.
    MapMemory(*mut usize /* phys */, *mut usize /* virt */, usize /* region size */, MemoryFlags /* flags */),

    /// This process wants to give up the remainder of its timeslice.
    Yield,

    /// This process will now wait for an event such as an IRQ or Message.
    WaitEvent,

    /// Stop running the given process.
    Suspend(XousPid, XousCpuId),

    /// Claims an interrupt and unmasks it immediately.  The provided function will
    /// be called from within an interrupt context, but using the ordinary privilege level of
    /// the process.
    ///
    /// # Errors
    ///
    /// * **InterruptNotFound**: The specified interrupt isn't valid on this system
    /// * **InterruptInUse**: The specified interrupt has already been claimed
    ClaimInterrupt(usize /* IRQ number */, *mut usize /* function pointer */, *mut usize /* argument */),

    FreeInterrupt(usize /* IRQ number */),
    Invalid(usize, usize, usize, usize, usize, usize, usize),
    SwitchTo(XousPid, *const usize /* pc */, *mut usize /* sp */),
    Resume(XousPid),
}

#[derive(FromPrimitive)]
enum SysCallNumber {
    MapMemory = 2,
    Yield = 3,
    Suspend = 4,
    ClaimInterrupt = 5,
    FreeInterrupt = 6,
    SwitchTo = 7,
    Resume = 8,
    WaitEvent = 9,
    Invalid,
}

#[derive(Debug)]
pub struct InvalidSyscall {}

impl SysCall {
    pub fn as_args(&self) -> [usize; 8] {
        match *self {
            SysCall::MapMemory(a1, a2, a3, a4) => [SysCallNumber::MapMemory as usize, a1 as usize, a2 as usize, a3, a4.bits(), 0, 0, 0],
            SysCall::Yield => [SysCallNumber::Yield as usize, 0, 0, 0, 0, 0, 0, 0],
            SysCall::WaitEvent => [SysCallNumber::WaitEvent as usize, 0, 0, 0, 0, 0, 0, 0],
            SysCall::Suspend(a1, a2) => [SysCallNumber::Suspend as usize, a1 as usize, a2 as usize, 0, 0, 0, 0, 0],
            SysCall::ClaimInterrupt(a1, a2, a3) => [SysCallNumber::ClaimInterrupt as usize, a1, a2 as usize, a3 as usize, 0, 0, 0, 0],
            SysCall::FreeInterrupt(a1) => [SysCallNumber::FreeInterrupt as usize, a1, 0, 0, 0, 0, 0, 0],
            SysCall::SwitchTo(a1, a2, a3) => [SysCallNumber::SwitchTo as usize, a1 as usize, a2 as usize, a3 as usize, 0, 0, 0, 0],
            SysCall::Resume(a1) => [SysCallNumber::Resume as usize, a1 as usize, 0, 0, 0, 0, 0, 0],
            SysCall::Invalid(a1, a2, a3, a4, a5, a6, a7) => [SysCallNumber::Invalid as usize, a1, a2, a3, a4, a5, a6, a7],
        }
        // match *self {
        //     MaxResult1(a1, a2, a3, a4, a5, a6, a7) => [0, a1, a2, a3, a4, a5, a6, a7],
        //     MaxResult2(a1, a2, a3, a4, a5, a6, a7) => [1, a1, a2, a3, a4, a5, a6, a7],
        //     MapMemory(a1, a2, a3) => [2, a1 as usize, a2 as usize, a3, 0, 0, 0, 0],
        //     call_formatter!(Yield),
        //     Suspend(a1, a2) => [4, a1 as usize, a2, 0, 0, 0, 0, 0],
        //     Invalid(a1, a2, a3, a4, a5, a6, a7) => [!0, a1, a2, a3, a4, a5, a6, a7],
        // }
    }
    pub fn from_args(a0: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize) -> Result<Self, InvalidSyscall> {
        Ok(match FromPrimitive::from_usize(a0) {
            Some(SysCallNumber::MapMemory) => SysCall::MapMemory(a1 as *mut usize, a2 as *mut usize, a3, MemoryFlags::from_bits(a4).ok_or(InvalidSyscall {})?),
            Some(SysCallNumber::Yield) => SysCall::Yield,
            Some(SysCallNumber::WaitEvent) => SysCall::WaitEvent,
            Some(SysCallNumber::Suspend) => SysCall::Suspend(a1 as XousPid, a2),
            Some(SysCallNumber::ClaimInterrupt) => SysCall::ClaimInterrupt(a1, a2 as *mut usize, a3 as *mut usize),
            Some(SysCallNumber::FreeInterrupt) => SysCall::FreeInterrupt(a1),
            Some(SysCallNumber::SwitchTo) => SysCall::SwitchTo(a1 as XousPid, a2 as *const usize, a3 as *mut usize),
            Some(SysCallNumber::Resume) => SysCall::Resume(a1 as XousPid),
            Some(SysCallNumber::Invalid) => SysCall::Invalid(a1, a2, a3, a4, a5, a6, a7),
            None => return Err(InvalidSyscall {}),
        })
    }
}

#[repr(C)]
#[derive(Debug, PartialEq)]
pub enum XousResult {
    Ok,
    MemoryAddress(*mut usize),
    ResumeResult(usize, usize, usize, usize, usize, usize),
    UnknownResult(usize, usize, usize, usize, usize, usize, usize),
    MaxResult4(usize, usize, usize, usize, usize, usize, usize),
    Error(XousError),
}

pub type SyscallResult = Result<XousResult, XousError>;

extern "Rust" {
    fn _xous_syscall_rust(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize, ret: &mut XousResult);
    fn _xous_syscall(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize, ret: &mut XousResult);
}

pub fn rsyscall(call: SysCall) -> SyscallResult {
    use core::mem::{MaybeUninit};
    let mut ret = unsafe { MaybeUninit::uninit().assume_init() };
    let args = call.as_args();
    unsafe { _xous_syscall(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], &mut ret) };
    match ret {
        XousResult::Error(e) => Err(e),
        other => Ok(other)
    }
}

/// This is dangerous, but fast.
pub fn dangerous_syscall(call: SysCall) -> SyscallResult {
    use core::mem::{transmute, MaybeUninit};
    let mut ret = unsafe { MaybeUninit::uninit().assume_init() };
    let presto = unsafe { transmute::<_, (usize, usize, usize, usize, usize, usize, usize, usize)>(call) };
    unsafe { _xous_syscall_rust(presto.0, presto.1, presto.2, presto.3, presto.4, presto.5, presto.6, presto.7, &mut ret) };
    match ret {
        XousResult::Error(e) => Err(e),
        other => Ok(other)
    }
}
