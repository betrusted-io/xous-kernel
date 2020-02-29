use crate::mem::MemoryManager;
use core::fmt;
use vexriscv::register::satp;
use xous::{XousError, XousPid, MemoryFlags};

pub const USER_STACK_OFFSET: usize = 0xdfff_fffc;
pub const USER_AREA_START: usize = 0x00c0_0000;
pub const PAGE_SIZE: usize = 4096;
const PAGE_TABLE_OFFSET: usize = 0x0040_0000;
const PAGE_TABLE_ROOT_OFFSET: usize = 0x0080_0000;

extern "C" {
    fn flush_mmu();
}

bitflags! {
    pub struct MMUFlags: usize {
        const NONE      = 0b00000000;
        const VALID     = 0b00000001;
        const R         = 0b00000010;
        const W         = 0b00000100;
        const X         = 0b00001000;
        const USER      = 0b00010000;
        const GLOBAL    = 0b00100000;
        const A         = 0b01000000;
        const D         = 0b10000000;
    }
}

#[derive(Copy, Clone, Default, PartialEq)]
pub struct MemoryMapping {
    satp: usize,
}

impl core::fmt::Debug for MemoryMapping {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::result::Result<(), core::fmt::Error> {
        write!(
            fmt,
            "(satp: 0x{:08x}, mode: {}, ASID: {}, PPN: {:08x})",
            self.satp,
            self.satp >> 31,
            self.satp >> 22 & ((1 << 9) - 1),
            (self.satp >> 0 & ((1 << 22) - 1)) << 12,
        )
    }
}

impl MemoryMapping {
    pub fn set(&mut self, new: usize) {
        self.satp = new;
    }
    pub fn get_pid(&self) -> XousPid {
        (self.satp >> 22 & ((1 << 9) - 1)) as XousPid
    }
    pub fn current() -> MemoryMapping {
        MemoryMapping {
            satp: satp::read().bits(),
        }
    }
    pub fn activate(&self) {
        satp::write(self.satp);
    }
}

pub const DEFAULT_MEMORY_MAPPING: MemoryMapping = MemoryMapping { satp: 0 };

/// A single RISC-V page table entry.  In order to resolve an address,
/// we need two entries: the top level, followed by the lower level.
struct RootPageTable {
    entries: [usize; 1024],
}

struct LeafPageTable {
    entries: [usize; 1024],
}

impl fmt::Display for RootPageTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, entry) in self.entries.iter().enumerate() {
            if *entry != 0 {
                writeln!(
                    f,
                    "    {:4} {:08x} -> {:08x} ({})",
                    i,
                    (entry >> 10) << 12,
                    i * (1 << 22),
                    entry & 0xff
                )?;
            }
        }
        Ok(())
    }
}

impl fmt::Display for LeafPageTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, entry) in self.entries.iter().enumerate() {
            if *entry != 0 {
                writeln!(
                    f,
                    "    {:4} {:08x} -> {:08x} ({})",
                    i,
                    (entry >> 10) << 12,
                    i * (1 << 10),
                    entry & 0xff
                )?;
            }
        }
        Ok(())
    }
}

/// Map the given page to the specified process table.  If necessary,
/// allocate a new page.
///
/// # Errors
///
/// * OutOfMemory - Tried to allocate a new pagetable, but ran out of memory.
pub fn map_page_inner(
    mm: &mut MemoryManager,
    pid: XousPid,
    phys: usize,
    virt: usize,
    req_flags: MemoryFlags,
) -> Result<(), XousError> {
    let ppn1 = (phys >> 22) & ((1 << 12) - 1);
    let ppn0 = (phys >> 12) & ((1 << 10) - 1);
    let ppo = (phys >> 0) & ((1 << 12) - 1);

    let vpn1 = (virt >> 22) & ((1 << 10) - 1);
    let vpn0 = (virt >> 12) & ((1 << 10) - 1);
    let vpo = (virt >> 0) & ((1 << 12) - 1);

    let mut flags = MMUFlags::NONE;
    if req_flags & xous::MemoryFlags::R == xous::MemoryFlags::R {
        flags |= MMUFlags::R;
    }
    if req_flags & xous::MemoryFlags::W == xous::MemoryFlags::W {
        flags |= MMUFlags::W;
    }
    if req_flags & xous::MemoryFlags::X == xous::MemoryFlags::X {
        flags |= MMUFlags::X;
    }
    // The kernel runs in Supervisor mode, and therefore always needs
    // exclusive access to this memory.
    // Additionally, any address below the user area must be accessible
    // by the kernel.
    if pid != 1 && virt >= USER_AREA_START {
        flags |= MMUFlags::USER;
    }

    assert!(ppn1 < 4096);
    assert!(ppn0 < 1024);
    assert!(ppo < 4096);
    assert!(vpn1 < 1024);
    assert!(vpn0 < 1024);
    assert!(vpo < 4096);

    // The root (l1) pagetable is defined to be mapped into our virtual
    // address space at this address.
    let l1_pt = unsafe { &mut (*(PAGE_TABLE_ROOT_OFFSET as *mut RootPageTable)) };
    let ref mut l1_pt = l1_pt.entries;

    // Subsequent pagetables are defined as being mapped starting at
    // offset 0x0020_0004, so 4 must be added to the ppn1 value.
    let l0pt_virt = PAGE_TABLE_OFFSET + vpn1 * PAGE_SIZE;
    let ref mut l0_pt = unsafe { &mut (*(l0pt_virt as *mut LeafPageTable)) };

    // Allocate a new level 1 pagetable entry if one doesn't exist.
    if l1_pt[vpn1 as usize] & MMUFlags::VALID.bits() == 0 {
        // Allocate a fresh page
        let l0pt_phys = mm.alloc_page(pid)?;

        // Mark this entry as a leaf node (WRX as 0), and indicate
        // it is a valid page by setting "V".
        l1_pt[vpn1 as usize] = ((l0pt_phys >> 12) << 10) | MMUFlags::VALID.bits();
        unsafe { flush_mmu() };

        // Map the new physical page to the virtual page, so we can access it.
        map_page_inner(mm, pid, l0pt_phys, l0pt_virt, MemoryFlags::W | MemoryFlags::R)?;

        // Zero-out the new page
        let page_addr = l0pt_virt as *mut usize;
        unsafe {
            for i in 0..PAGE_SIZE / core::mem::size_of::<usize>() {
                *page_addr.add(i) = 0;
            }
        }
    }

    // Ensure the entry hasn't already been mapped.
    if l0_pt.entries[vpn0 as usize] & 1 != 0 {
        println!("Page {:08x} already allocated!", virt);
    }
    l0_pt.entries[vpn0 as usize] =
        (ppn1 << 20) | (ppn0 << 10) | (flags | MMUFlags::VALID | MMUFlags::D | MMUFlags::A).bits();
    unsafe { flush_mmu() };

    Ok(())
}

/// Ummap the given page from the specified process table.  Never
/// allocate a new page.
///
/// # Errors
///
/// * BadAddress - Address was not already mapped.
pub fn unmap_page_inner(
    _mm: &mut MemoryManager,
    _pid: XousPid,
    phys: usize,
    virt: usize,
    _flags: MemoryFlags,
) -> Result<(), XousError> {
    let ppn1 = (phys >> 22) & ((1 << 12) - 1);
    let ppn0 = (phys >> 12) & ((1 << 10) - 1);
    let ppo = (phys >> 0) & ((1 << 12) - 1);

    let vpn1 = (virt >> 22) & ((1 << 10) - 1);
    let vpn0 = (virt >> 12) & ((1 << 10) - 1);
    let vpo = (virt >> 0) & ((1 << 12) - 1);

    assert!(ppn1 < 4096);
    assert!(ppn0 < 1024);
    assert!(ppo < 4096);
    assert!(vpn1 < 1024);
    assert!(vpn0 < 1024);
    assert!(vpo < 4096);

    // The root (l1) pagetable is defined to be mapped into our virtual
    // address space at this address.
    let l1_pt = unsafe { &mut (*(PAGE_TABLE_ROOT_OFFSET as *mut RootPageTable)) };
    let ref mut l1_pt = l1_pt.entries;

    // Subsequent pagetables are defined as being mapped starting at
    // offset 0x0020_0004, so 4 must be added to the ppn1 value.
    let l0pt_virt = PAGE_TABLE_OFFSET + vpn1 * PAGE_SIZE;
    let ref mut l0_pt = unsafe { &mut (*(l0pt_virt as *mut LeafPageTable)) };

    // Allocate a new level 1 pagetable entry if one doesn't exist.
    if l1_pt[vpn1 as usize] & MMUFlags::VALID.bits() == 0 {
        return Err(XousError::BadAddress);
    }

    // Ensure the entry hasn't already been mapped.
    if l0_pt.entries[vpn0 as usize] & 1 == 0 {
        return Err(XousError::BadAddress);
    }
    l0_pt.entries[vpn0 as usize] = 0;
    unsafe { flush_mmu() };

    Ok(())
}
