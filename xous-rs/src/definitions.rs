use core::num::NonZeroUsize;

pub type MemoryAddress = NonZeroUsize;
pub type MemorySize = NonZeroUsize;
pub type StackPointer = usize;
pub type MessageId = usize;

pub type XousPid = u8;
pub type XousMessageSender = usize;
pub type XousConnection = usize;

/// Server ID
pub type XousSid = usize;

/// Equivalent to a RISC-V Hart ID
pub type XousCpuId = usize;

#[derive(Debug)]
#[repr(C)]
pub enum XousError {
    NoError = 0,
    BadAlignment = 1,
    BadAddress = 2,
    OutOfMemory = 3,
    MemoryInUse = 4,
    InterruptNotFound = 5,
    InterruptInUse = 6,
    InvalidString = 7,
    ServerExists = 8,
    ServerNotFound = 9,
    ProcessNotFound = 10,
    ProcessNotChild = 11,
    ProcessTerminated = 12,
    Timeout = 13,
    UnhandledSyscall = 14,
}

#[repr(C)]
pub struct XousContext {
    stack: StackPointer,
    pid: XousPid,
}

#[repr(C)]
pub struct XousMemoryMessage {
    id: MessageId,
    in_buf: Option<MemoryAddress>,
    in_buf_size: Option<MemorySize>,
    out_buf: Option<MemoryAddress>,
    out_buf_size: Option<MemorySize>,
}

#[repr(C)]
pub struct XousScalarMessage {
    id: MessageId,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
}

#[allow(dead_code)]
pub enum XousMessage {
    Memory(XousMemoryMessage),
    Scalar(XousScalarMessage),
}

#[allow(dead_code)]
pub struct XousMessageReceived {
    sender: XousMessageSender,
    message: XousMessage,
}
