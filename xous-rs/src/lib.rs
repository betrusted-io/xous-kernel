#![no_std]

#[allow(dead_code)] pub type XousPid = u8;
/// Equivalent to a RISC-V Hart ID
#[allow(dead_code)] pub type XousCpuId = usize;

#[macro_use]
extern crate bitflags;
extern crate num_traits;
extern crate num_derive;

use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

bitflags! {
    pub struct MemoryFlags: usize {
        const R         = 0b00000010;
        const W         = 0b00000100;
        const X         = 0b00001000;
    }
}

#[derive(Debug)]
pub enum SysCall {
    // MaxResult1(usize, usize, usize, usize, usize, usize, usize),
    // MaxResult2(usize, usize, usize, usize, usize, usize, usize),
    MapMemory(*mut usize /* phys */, *mut usize /* virt */, usize /* region size */, MemoryFlags /* flags */),
    Yield,
    Suspend(XousPid, XousCpuId),
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
    Invalid,
}

#[derive(Debug)]
pub struct InvalidSyscall {}

impl SysCall {
    pub fn as_args(&self) -> [usize; 8] {
        match *self {
            SysCall::MapMemory(a1, a2, a3, a4) => [SysCallNumber::MapMemory as usize, a1 as usize, a2 as usize, a3, a4.bits(), 0, 0, 0],
            SysCall::Yield => [SysCallNumber::Yield as usize, 0, 0, 0, 0, 0, 0, 0],
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
            Some(SysCallNumber::Suspend) => SysCall::Suspend(a1 as XousPid, a2),
            Some(SysCallNumber::ClaimInterrupt) => SysCall::ClaimInterrupt(a1, a2 as *mut usize, a3 as *mut usize),
            Some(SysCallNumber::FreeInterrupt) => SysCall::FreeInterrupt(a1),
            Some(SysCallNumber::SwitchTo) => SysCall::SwitchTo(a1 as XousPid, a2 as *const usize, a3 as *mut usize),
            Some(SysCallNumber::Resume) => SysCall::Resume(a1 as XousPid),
            Some(SysCallNumber::Invalid) => return Err(InvalidSyscall {}),
            None => return Err(InvalidSyscall {}),
        })
    }
}

#[repr(C)]
pub struct SyscallReturn {
    pub tag: u32,
    pub a1: u32,
    pub a2: u32,
    pub a3: u32,
    pub a4: u32,
    pub a5: u32,
    pub a6: u32,
    pub a7: u32,
}

#[repr(C)]
#[derive(Debug)]
pub enum XousResult {
    MaxResult1(u32, u32, u32, u32, u32, u32, u32),
    MaxResult2(u32, u32, u32, u32, u32, u32, u32),
    MaxResult3(u32, u32, u32, u32, u32, u32, u32),
    MaxResult4(u32, u32, u32, u32, u32, u32, u32),
    MaxResult5(u32, u32, u32, u32, u32, u32, u32),
    MaxResult6(u32, u32, u32, u32, u32, u32, u32),
    MaxResult7(u32, u32, u32, u32, u32, u32, u32),
    MaxResult8(u32, u32, u32, u32, u32, u32, u32),
    XousError(XousError),
    MemoryAddress(*mut usize),
    ResumeResult(u32, u32, u32, u32, u32, u32),
    UnknownResult(u32, u32, u32, u32, u32, u32, u32),
}

pub type XousError = u32;

pub type SyscallResult = Result<XousResult, XousError>;
// type SyscallResult = [u32; 8];

extern "Rust" {
    // fn _xous_syscall(args: CallArgs) -> CallArgs;
    // fn _xous_syscall(args: SyscallArguments) -> Result<XousResult, XousError>;
    // fn _xous_syscall(nr: u32, a1: u32, a2: u32, a3: u32, a4: u32, a5: u32, a6: u32, a7: u32) -> CallArgs;
    // fn _xous_syscall(nr: u32, a1: u32, a2: u32, a3: u32, a4: u32, a5: u32, a6: u32, a7: u32) -> Result<XousResult, XousError>;
    // fn _xous_syscall(args: [u32; 8]) -> [u32; 8];
    fn _xous_syscall_rust(nr: u32, a1: u32, a2: u32, a3: u32, a4: u32, a5: u32, a6: u32, a7: u32, ret: &mut XousResult);
    fn _xous_syscall(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize, ret: &mut XousResult);
    // fn _xous_syscall_rust(params: (u32, u32, u32, u32, u32, u32, u32, u32), ret: &mut XousResult);
}


pub fn rsyscall(call: SysCall) -> SyscallResult {
    use core::mem::{MaybeUninit};
    let mut ret = unsafe { MaybeUninit::uninit().assume_init() };
    let args = call.as_args();
    unsafe { _xous_syscall(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], &mut ret) };
    match ret {
        XousResult::XousError(e) => Err(e),
        other => Ok(other)
    }
    // Ok(ret)
    // unsafe { _xous_syscall(args.nr, args.a1, args.a2, args.a3, args.a4, args.a5, args.a6, args.a7) }
    // unsafe { _xous_syscall([args.nr, args.a1, args.a2, args.a3, args.a4, args.a5, args.a6, args.a7]) }
}

/// This is dangerous, but fast.
pub fn dangerous_syscall(call: SysCall) -> SyscallResult {
    use core::mem::{transmute, MaybeUninit};
    let mut ret = unsafe { MaybeUninit::uninit().assume_init() };
    let presto = unsafe { transmute::<_, (u32, u32, u32, u32, u32, u32, u32, u32)>(call) };
    unsafe { _xous_syscall_rust(presto.0, presto.1, presto.2, presto.3, presto.4, presto.5, presto.6, presto.7, &mut ret) };
    match ret {
        XousResult::XousError(e) => Err(e),
        other => Ok(other)
    }
}
