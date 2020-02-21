use crate::args::KernelArguments;
use crate::definitions::{MemoryAddress, XousError, XousPid};
use core::fmt;
use core::mem;
use core::slice;
use core::str;
use vexriscv::register::satp;

const USER_STACK_OFFSET: usize = 0xdfff_fffc;
const PAGE_TABLE_OFFSET: usize = 0x0040_0000;
const PAGE_TABLE_ROOT_OFFSET: usize = 0x0080_0000;
const USER_AREA_START: usize = 0x00c0_0000;

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

const PAGE_SIZE: usize = 4096;

#[derive(Debug)]
enum ClaimOrRelease {
    Claim,
    Release,
}

#[repr(C)]
pub struct MemoryRangeExtra {
    mem_start: u32,
    mem_size: u32,
    mem_tag: u32,
    _padding: u32,
}

impl fmt::Display for MemoryRangeExtra {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tag_name_bytes = self.mem_tag.to_le_bytes();
        let s = unsafe {
            // First, we build a &[u8]...
            let slice = slice::from_raw_parts(tag_name_bytes.as_ptr(), 4);
            // ... and then convert that slice into a string slice
            str::from_utf8_unchecked(slice)
        };

        write!(
            f,
            "{} ({:08x}) {:08x} - {:08x} {} bytes):",
            s,
            self.mem_tag,
            self.mem_start,
            self.mem_start + self.mem_size,
            self.mem_size
        )
    }
}

pub struct MemoryManager {
    allocations: &'static mut [XousPid],
    extra: &'static [MemoryRangeExtra],
    ram_start: usize,
    ram_size: usize,
}

static mut MEMORY_MANAGER: MemoryManager = MemoryManager {
    allocations: &mut [],
    extra: &[],
    ram_start: 0,
    ram_size: 0,
};

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

/// Initialize the memory map.
/// This will go through memory and map anything that the kernel is
/// using to process 1, then allocate a pagetable for this process
/// and place it at the usual offset.  The MMU will not be enabled yet,
/// as the process entry has not yet been created.
impl MemoryManager {
    pub fn new(
        base: *mut u32,
        args: &KernelArguments,
    ) -> Result<&'static mut MemoryManager, XousError> {
        let ref mut mm = unsafe { &mut MEMORY_MANAGER };
        let mut args_iter = args.iter();
        let xarg_def = args_iter.next().expect("mm: no kernel arguments found");
        assert!(
            xarg_def.name == make_type!("XArg"),
            "mm: first tag wasn't XArg"
        );
        assert!(xarg_def.data[1] == 1, "mm: xarg had unexpected version");
        mm.ram_start = xarg_def.data[2] as usize;
        mm.ram_size = xarg_def.data[3] as usize;

        let mut mem_size = mm.ram_size;
        for tag in args_iter {
            if tag.name == make_type!("MREx") {
                assert!(mm.extra.len() == 0, "mm: MREx tag appears twice!");
                let ptr = tag.data.as_ptr() as *mut MemoryRangeExtra;
                mm.extra = unsafe {
                    slice::from_raw_parts_mut(
                        ptr,
                        tag.data.len() * 4 / mem::size_of::<MemoryRangeExtra>(),
                    )
                };
            }
        }

        for range in mm.extra.iter() {
            mem_size += range.mem_size as usize;
        }

        mm.allocations =
            unsafe { slice::from_raw_parts_mut(base as *mut XousPid, mem_size as usize) };
        Ok(unsafe { &mut MEMORY_MANAGER })
    }

    pub unsafe fn get() -> &'static mut MemoryManager {
        &mut MEMORY_MANAGER
    }

    pub fn print(&self) {
        sprintln!("Memory Maps:");
        let l1_pt = unsafe { &mut (*(PAGE_TABLE_ROOT_OFFSET as *mut RootPageTable)) };
        for (i, l1_entry) in l1_pt.entries.iter().enumerate() {
            if *l1_entry == 0 {
                continue;
            }
            let superpage_addr = i as u32 * (1 << 22);
            sprintln!(
                "    {:4} Superpage for {:08x} @ {:08x} (flags: {:?})",
                i,
                superpage_addr,
                (*l1_entry >> 10) << 12,
                MMUFlags::from_bits(l1_entry & 0xff).unwrap()
            );
            // let l0_pt_addr = ((l1_entry >> 10) << 12) as *const u32;
            let l0_pt = unsafe { &mut (*((PAGE_TABLE_OFFSET + i * 4096) as *mut LeafPageTable)) };
            for (j, l0_entry) in l0_pt.entries.iter().enumerate() {
                if *l0_entry == 0 {
                    continue;
                }
                let page_addr = j as u32 * (1 << 12);
                sprintln!(
                    "        {:4} {:08x} -> {:08x} (flags: {:?})",
                    j,
                    superpage_addr + page_addr,
                    (*l0_entry >> 10) << 12,
                    MMUFlags::from_bits(l0_entry & 0xff).unwrap()
                );
            }
        }
    }
    /// Allocate a single page to the given process.
    /// Ensures the page is zeroed out prior to handing it over to
    /// the specified process.
    pub fn alloc_page(&mut self, pid: XousPid) -> Result<usize, XousError> {
        // Go through all RAM pages looking for a free page.
        // Optimization: start from the previous address.
        // sprintln!("Allocating page for PID {}", pid);
        for index in 0..(self.ram_size as usize) / PAGE_SIZE {
            // sprintln!("    Checking {:08x}...", index * PAGE_SIZE + self.ram_start as usize);
            if self.allocations[index] == 0 {
                self.allocations[index] = pid + 1;
                return Ok(index * PAGE_SIZE + self.ram_start);
            }
        }
        Err(XousError::OutOfMemory)
    }

    /// Map the given page to the specified process table.  If necessary,
    /// allocate a new page.
    ///
    /// # Errors
    ///
    /// * OutOfMemory - Tried to allocate a new pagetable, but ran out of memory.
    fn map_page_inner(
        &mut self,
        pid: XousPid,
        phys: usize,
        virt: usize,
        flags: MMUFlags,
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
            // Allocate a fresh page
            let l0pt_phys = self.alloc_page(pid)?;

            // Mark this entry as a leaf node (WRX as 0), and indicate
            // it is a valid page by setting "V".
            l1_pt[vpn1 as usize] = ((l0pt_phys >> 12) << 10) | MMUFlags::VALID.bits();
            unsafe { flush_mmu() };

            // Map the new physical page to the virtual page, so we can access it.
            self.map_page_inner(pid, l0pt_phys, l0pt_virt, MMUFlags::W | MMUFlags::R)?;

            // Zero-out the new page
            let page_addr = l0pt_virt as *mut usize;
            unsafe {
                for i in 0..PAGE_SIZE / mem::size_of::<usize>() {
                    *page_addr.add(i) = 0;
                }
            }
        }

        // Ensure the entry hasn't already been mapped.
        // if l0_pt[vpn0 as usize] & 1 != 0 {
        //     panic!("Page already allocated!");
        // }
        l0_pt.entries[vpn0 as usize] = (ppn1 << 20)
            | (ppn0 << 10)
            | (flags | MMUFlags::VALID | MMUFlags::D | MMUFlags::A).bits();
        unsafe { flush_mmu() };

        Ok(())
    }

    /// Attempt to map the given physical address into the virtual address space
    /// of this process.
    ///
    /// # Errors
    ///
    /// * MemoryInUse - The specified page is already mapped
    pub fn map_page(
        &mut self,
        phys: *mut usize,
        virt: *mut usize,
        flags: MMUFlags,
    ) -> Result<MemoryAddress, XousError> {
        let current_satp = satp::read().bits();
        let pid = ((current_satp >> 22) & ((1 << 9) - 1)) as XousPid;

        self.claim_page(phys, pid)?;
        match self.map_page_inner(pid, phys as usize, virt as usize, flags) {
            Ok(_) => {
                unsafe { flush_mmu() };
                MemoryAddress::new(virt as usize).ok_or(XousError::BadAddress)
            }
            Err(e) => {
                self.release_page(phys, pid)?;
                Err(e)
            }
        }
    }

    fn claim_or_release(
        &mut self,
        addr: *mut usize,
        pid: XousPid,
        action: ClaimOrRelease,
    ) -> Result<(), XousError> {
        fn action_inner(
            addr: &mut XousPid,
            pid: XousPid,
            action: ClaimOrRelease,
        ) -> Result<(), XousError> {
            if *addr != 0 && *addr != pid + 1 {
                return Err(XousError::MemoryInUse);
            }
            match action {
                ClaimOrRelease::Claim => {
                    *addr = pid + 1;
                }
                ClaimOrRelease::Release => {
                    *addr = 0;
                }
            }
            Ok(())
        }
        let addr = addr as usize;

        // Ensure the address lies on a page boundary
        if addr & 0xfff != 0 {
            return Err(XousError::BadAlignment);
        }

        let mut offset = 0;
        // Happy path: The address is in main RAM
        if addr > self.ram_start && addr < self.ram_start + self.ram_size {
            offset += (addr - self.ram_start) / PAGE_SIZE;
            return action_inner(&mut self.allocations[offset], pid, action);
        }

        offset += self.ram_size / PAGE_SIZE;
        // Go through additional regions looking for this address, and claim it
        // if it's not in use.
        for region in self.extra {
            if addr > (region.mem_start as usize)
                && addr < (region.mem_start + region.mem_size) as usize
            {
                offset += (addr - (region.mem_start as usize)) / PAGE_SIZE;
                return action_inner(&mut self.allocations[offset], pid, action);
            }
            offset += self.ram_size / PAGE_SIZE;
        }
        // sprintln!("mem: unable to claim or release");
        Err(XousError::BadAddress)
    }

    /// Mark a given address as being owned by the specified process ID
    fn claim_page(&mut self, addr: *mut usize, pid: XousPid) -> Result<(), XousError> {
        self.claim_or_release(addr, pid, ClaimOrRelease::Claim)
    }

    /// Mark a given address as no longer being owned by the specified process ID
    fn release_page(&mut self, addr: *mut usize, pid: XousPid) -> Result<(), XousError> {
        self.claim_or_release(addr, pid, ClaimOrRelease::Release)
    }
}
