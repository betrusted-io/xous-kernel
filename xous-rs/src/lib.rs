#![no_std]

#[repr(C)]
pub struct SyscallArguments {
    pub nr: u32,
    pub a1: u32,
    pub a2: u32,
    pub a3: u32,
    pub a4: u32,
    pub a5: u32,
    pub a6: u32,
    pub a7: u32,
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
    fn _xous_syscall(nr: u32, a1: u32, a2: u32, a3: u32, a4: u32, a5: u32, a6: u32, a7: u32, ret: &mut XousResult);
}

use core::mem::MaybeUninit;

pub fn syscall(args: SyscallArguments) -> SyscallResult {
    // let a = CallArgs::Args(args.nr, args.a1, args.a2, args.a3, args.a4, args.a5, args.a6, args.a7);
    // unsafe { _xous_syscall(args) }
    // let mut ret = [0; 8];
    let mut ret = unsafe { MaybeUninit::uninit().assume_init() };

    unsafe { _xous_syscall(args.nr, args.a1, args.a2, args.a3, args.a4, args.a5, args.a6, args.a7, &mut ret) };
    match ret {
        // XousResult::XousError(e) => Err(e),
        other => Ok(other)
    }
    // Ok(ret)
    // unsafe { _xous_syscall(args.nr, args.a1, args.a2, args.a3, args.a4, args.a5, args.a6, args.a7) }
    // unsafe { _xous_syscall([args.nr, args.a1, args.a2, args.a3, args.a4, args.a5, args.a6, args.a7]) }
}
