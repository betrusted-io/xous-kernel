use core::fmt;

#[derive(PartialEq)]
pub enum RiscvException {
    /// When things are all 0
    NoException,

    /// 1 0
    UserSoftwareInterrupt(usize /* mepc */),

    /// 1 1
    SupervisorSoftwareInterrupt(usize /* mepc */),

    // [reserved]
    /// 1 3
    MachineSoftwareInterrupt(usize /* mepc */),

    /// 1 4
    UserTimerInterrupt(usize /* mepc */),

    /// 1 5
    SupervisorTimerInterrupt(usize /* mepc */),

    // [reserved]
    /// 1 7
    MachineTimerInterrupt(usize /* mepc */),

    /// 1 8
    UserExternalInterrupt(usize /* mepc */),

    /// 1 9
    SupervisorExternalInterrupt(usize /* mepc */),

    // [reserved]
    /// 1 11
    MachineExternalInterrupt(usize /* mepc */),

    ReservedInterrupt(usize /* unknown cause number */, usize /* mepc */),

    /// 0 0
    InstructionAddressMisaligned(usize /* mepc */, usize /* target address */),

    /// 0 1
    InstructionAccessFault(usize /* mepc */, usize /* target address */),

    /// 0 2
    IllegalInstruction(usize /* mepc */, usize /* instruction value */),

    /// 0 3
    Breakpoint(usize /* mepc */),

    /// 0 4
    LoadAddressMisaligned(usize /* mepc */, usize /* target address */),

    /// 0 5
    LoadAccessFault(usize /* mepc */, usize /* target address */),

    /// 0 6
    StoreAddressMisaligned(usize /* mepc */, usize /* target address */),

    /// 0 7
    StoreAccessFault(usize /* mepc */, usize /* target address */),

    /// 0 8
    CallFromUMode(usize /* mepc */),

    /// 0 9
    CallFromSMode(usize /* mepc */),

    // [reserved]
    /// 0 11
    CallFromMMode(usize /* mepc */),

    /// 0 12
    InstructionPageFault(usize /* mepc */, usize /* target address */),

    /// 0 13
    LoadPageFault(usize /* mepc */, usize /* target address */),

    // [reserved]
    /// 0 15
    StorePageFault(usize /* mepc */, usize /* target address */),

    ReservedFault(
        usize, /* unknown cause number */
        usize, /* mepc */
        usize, /* mtval */
    ),
}

impl fmt::Display for RiscvException {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        use RiscvException::*;
        match *self {
            NoException => write!(f, "No trap"),
            UserSoftwareInterrupt(epc) => write!(f, "User swi from 0x{:08x}", epc),
            SupervisorSoftwareInterrupt(epc) => write!(f, "Supervisor swi from 0x{:08x}", epc),
            // --reserved--
            MachineSoftwareInterrupt(epc) => write!(f, "Machine swi at 0x{:08x}", epc),
            UserTimerInterrupt(epc) => write!(f, "User timer interrupt at 0x{:08x}", epc),
            SupervisorTimerInterrupt(epc) => {
                write!(f, "Supervisor timer interrupt at 0x{:08x}", epc)
            }
            // --reserved--
            MachineTimerInterrupt(epc) => write!(f, "Machine timer interrupt at 0x{:08x}", epc),
            UserExternalInterrupt(epc) => write!(f, "User external interrupt at 0x{:08x}", epc),
            SupervisorExternalInterrupt(epc) => {
                write!(f, "Machine external interrupt at 0x{:08x}", epc)
            }
            // --reserved--
            MachineExternalInterrupt(epc) => {
                write!(f, "Supervisor external interrupt at 0x{:08x}", epc)
            }
            ReservedInterrupt(code, epc) => {
                write!(f, "Reserved interrupt 0x{:08x} at 0x{:08x}", code, epc)
            }

            InstructionAddressMisaligned(epc, mtval) => write!(
                f,
                "Misaligned address instruction 0x{:08x} at 0x{:08x}",
                mtval, epc
            ),
            InstructionAccessFault(epc, mtval) => write!(
                f,
                "Instruction access fault to 0x{:08x} at 0x{:08x}",
                mtval, epc
            ),
            IllegalInstruction(epc, mtval) => {
                write!(f, "Illegal instruction 0x{:08x} at 0x{:08x}", mtval, epc)
            }
            Breakpoint(epc) => write!(f, "Breakpoint at 0x{:08x}", epc),
            LoadAddressMisaligned(epc, mtval) => write!(
                f,
                "Misaligned load address of 0x{:08x} at 0x{:08x}",
                mtval, epc
            ),
            LoadAccessFault(epc, mtval) => {
                write!(f, "Load access fault from 0x{:08x} at 0x{:08x}", mtval, epc)
            }
            StoreAddressMisaligned(epc, mtval) => write!(
                f,
                "Misaligned store address of 0x{:08x} at 0x{:08x}",
                mtval, epc
            ),
            StoreAccessFault(epc, mtval) => {
                write!(f, "Store access fault to 0x{:08x} at 0x{:08x}", mtval, epc)
            }
            CallFromUMode(epc) => write!(f, "Call from User mode at 0x{:08x}", epc),
            CallFromSMode(epc) => write!(f, "Call from Supervisor mode at 0x{:08x}", epc),
            // --reserved--
            CallFromMMode(epc) => write!(f, "Call from Machine mode at 0x{:08x}", epc),
            InstructionPageFault(epc, mtval) => write!(
                f,
                "Instruction page fault of 0x{:08x} at 0x{:08x}",
                mtval, epc
            ),
            LoadPageFault(epc, mtval) => {
                write!(f, "Load page fault of 0x{:08x} at 0x{:08x}", mtval, epc)
            }
            // --reserved--
            StorePageFault(epc, mtval) => {
                write!(f, "Store page fault of 0x{:08x} at 0x{:08x}", mtval, epc)
            }
            ReservedFault(code, epc, mtval) => write!(
                f,
                "Reserved interrupt 0x{:08x} with cause 0x{:08x} at 0x{:08x}",
                code, mtval, epc
            ),
        }
    }
}

impl RiscvException {
    pub fn from_regs(mcause: usize, mepc: usize, mtval: usize) -> RiscvException {
        use RiscvException::*;

        if mepc == 0 && mtval == 0 {
            return NoException;
        }

        match mcause {
            0x80000000 => UserSoftwareInterrupt(mepc),
            0x80000001 => SupervisorSoftwareInterrupt(mepc),
            // --reserved--
            0x80000003 => MachineSoftwareInterrupt(mepc),
            0x80000004 => UserTimerInterrupt(mepc),
            0x80000005 => SupervisorTimerInterrupt(mepc),
            // --reserved--
            0x80000007 => MachineTimerInterrupt(mepc),
            0x80000008 => UserExternalInterrupt(mepc),
            0x80000009 => SupervisorExternalInterrupt(mepc),
            // --reserved--
            0x8000000b => MachineExternalInterrupt(mepc),

            0 => InstructionAddressMisaligned(mepc, mtval),
            1 => InstructionAccessFault(mepc, mtval),
            2 => IllegalInstruction(mepc, mtval),
            3 => Breakpoint(mepc),
            4 => LoadAddressMisaligned(mepc, mtval),
            5 => LoadAccessFault(mepc, mtval),
            6 => StoreAddressMisaligned(mepc, mtval),
            7 => StoreAccessFault(mepc, mtval),
            8 => CallFromUMode(mepc),
            9 => CallFromSMode(mepc),
            // --reserved--
            11 => CallFromMMode(mepc),
            12 => InstructionPageFault(mepc, mtval),
            13 => LoadPageFault(mepc, mtval),
            // --reserved--
            15 => StorePageFault(mepc, mtval),
            x @ 10 | x @ 14 | x @ 16..=0x7fffffff => ReservedFault(x, mepc, mtval),

            x => {
                ReservedInterrupt(x & 0x7fffffff, mepc)
            }
        }
    }
}
