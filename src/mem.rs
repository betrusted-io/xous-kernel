use crate::args::KernelArguments;
use crate::definitions::{MemoryAddress, XousError, XousPid};
use core::fmt;
use core::mem;
use core::slice;
use core::str;
use vexriscv::register::satp;

extern "C" {
    fn flush_mmu();
}

bitflags! {
    pub struct MMUFlags: u32 {
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

enum ClaimOrRelease {
    Claim,
    Release,
}

pub struct MemoryRangeExtra {
    mem_start: u32,
    mem_size: u32,
    mem_tag: u32,
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
    ram_start: u32,
    ram_size: u32,
}

// impl core::fmt::Debug for MemoryManagerInner {
//     fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::result::Result<(), core::fmt::Error> {
//         writeln!(fmt, "Ranges: ")?;
//         writeln!(
//             fmt,
//             "    flash: {:08x} .. {:08x} ({} pages)",
//             FLASH_START,
//             FLASH_END,
//             self.flash.len()
//         )?;
//         writeln!(
//             fmt,
//             "    ram:   {:08x} .. {:08x} ({} pages)",
//             RAM_START,
//             RAM_END,
//             self.ram.len()
//         )?;
//         writeln!(
//             fmt,
//             "    io:    {:08x} .. {:08x} ({} pages)",
//             IO_START,
//             IO_END,
//             self.io.len()
//         )?;
//         writeln!(
//             fmt,
//             "    lcd:   {:08x} .. {:08x} ({} pages)",
//             LCD_START,
//             LCD_END,
//             self.lcd.len()
//         )?;
//         Ok(())
//     }
// }

// impl core::fmt::Debug for MemoryManager {
//     fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::result::Result<(), core::fmt::Error> {
//         unsafe { write!(fmt, "{:?}", MM) }
//     }
// }

/// A single RISC-V page table entry.  In order to resolve an address,
/// we need two entries: the top level, followed by the lower level.
struct RootPageTable {
    entries: [u32; 1024],
}

struct LeafPageTable {
    entries: [u32; 1024],
}

impl fmt::Display for RootPageTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, entry) in self.entries.iter().enumerate() {
            if *entry != 0 {
                writeln!(f, "    {:4} {:08x} -> {:08x} ({})", i, (entry>>10)<<12, i * (1<<22), entry & 0xff)?;
            }
        }
        Ok(())
    }
}

impl fmt::Display for LeafPageTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, entry) in self.entries.iter().enumerate() {
            if *entry != 0 {
                writeln!(f, "    {:4} {:08x} -> {:08x} ({})", i, (entry>>10)<<12, i * (1<<10), entry & 0xff)?;
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
    pub fn new(base: *mut u32, args: &KernelArguments) -> Result<MemoryManager, XousError> {
        let mut args_iter = args.iter();
        let xarg_def = args_iter.next().expect("mm: no kernel arguments found");
        assert!(
            xarg_def.name == make_type!("XArg"),
            "mm: first tag wasn't XArg"
        );
        assert!(xarg_def.data[1] == 1, "mm: xarg had unexpected version");
        let ram_start = xarg_def.data[2];
        let ram_size = xarg_def.data[3];

        let mut mem_size = ram_size;
        let mut extra = unsafe { slice::from_raw_parts_mut(0 as *mut MemoryRangeExtra, 0) };
        for tag in args_iter {
            if tag.name == make_type!("MREx") {
                assert!(extra.len() == 0, "mm: MREx tag appears twice!");
                let ptr = tag.data.as_ptr() as *mut MemoryRangeExtra;
                extra = unsafe {
                    slice::from_raw_parts_mut(
                        ptr,
                        tag.data.len() * 4 / mem::size_of::<MemoryRangeExtra>(),
                    )
                };
            }
        }

        for range in extra.iter() {
            mem_size += range.mem_size;
        }

        // sprintln!("Memory Maps:");
        // let l1_pt = unsafe { &mut (*(0x0020_0000 as *mut RootPageTable)) };
        // for (i, l1_entry) in l1_pt.entries.iter().enumerate() {
        //     if *l1_entry == 0 {
        //         continue;
        //     }
        //     let superpage_addr = i as u32 * (1<<22);
        //     sprintln!("    {:4} Superpage for {:08x} @ {:08x} (flags: {})", i,  superpage_addr, (*l1_entry>>10)<<12, l1_entry & 0xff);
        //     // let l0_pt_addr = ((l1_entry >> 10) << 12) as *const u32;
        //     let l0_pt = unsafe { &mut (*((0x0040_0000 + i*4096) as *mut LeafPageTable)) };
        //     for (j, l0_entry) in l0_pt.entries.iter().enumerate() {
        //         if *l0_entry == 0 {
        //             continue;
        //         }
        //         let page_addr = j as u32 * (1<<12);
        //         sprintln!("        {:4} {:08x} -> {:08x} (flags: {})", j, superpage_addr + page_addr, (*l0_entry>>10)<<12, l0_entry & 0xff);
        //     }
        // }

        let allocations =
            unsafe { slice::from_raw_parts_mut(base as *mut XousPid, mem_size as usize) };
        Ok(MemoryManager {
            allocations,
            extra,
            ram_start,
            ram_size,
        })
    }

    /// Allocate a single page to the given process.
    /// Ensures the page is zeroed out prior to handing it over to
    /// the specified process.
    pub fn alloc_page(&mut self, pid: XousPid) -> Result<u32, XousError> {
        // Go through all RAM pages looking for a free page.
        // Optimization: start from the previous address.
        // sprintln!("Allocating page for PID {}", pid);
        for index in 0..(self.ram_size as usize) / PAGE_SIZE {
            // sprintln!("    Checking {:08x}...", index * PAGE_SIZE + self.ram_start as usize);
            if self.allocations[index] == 0 {
                self.allocations[index] = pid + 1;
                return Ok((index * PAGE_SIZE + self.ram_start as usize) as u32);
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
        phys: u32,
        virt: u32,
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
        let l1_pt = unsafe { &mut (*(0x0020_0000 as *mut RootPageTable)) };
        let ref mut l1_pt = l1_pt.entries;

        // Subsequent pagetables are defined as being mapped starting at
        // offset 0x0020_0004, so 4 must be added to the ppn1 value.
        let l0pt_virt = 0x0040_0000 + vpn1 * PAGE_SIZE as u32;
        let ref mut l0_pt =
            unsafe { &mut (*(l0pt_virt as *mut LeafPageTable)) };

        // Allocate a new level 1 pagetable entry if one doesn't exist.
        if l1_pt[vpn1 as usize] & MMUFlags::VALID.bits() == 0 {
            // Allocate a fresh page
            let l0pt_phys = self.alloc_page(pid)?;

            // Mark this entry as a leaf node (WRX as 0), and indicate
            // it is a valid page by setting "V".
            l1_pt[vpn1 as usize] = ((l0pt_phys >> 12) << 10) | MMUFlags::VALID.bits();
            unsafe { flush_mmu() };

            // Map the new physical page to the virtual page, so we can access it.
            self.map_page_inner(
                pid,
                l0pt_phys,
                l0pt_virt,
                MMUFlags::W | MMUFlags::R,
            )?;

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
        phys: u32,
        virt: u32,
        flags: MMUFlags,
    ) -> Result<MemoryAddress, XousError> {
        let current_satp = satp::read().bits();
        let pid = ((current_satp >> 22) & ((1 << 9) - 1)) as XousPid;

        self.claim_page(phys, pid)?;
        match self.map_page_inner(pid, phys, virt, flags) {
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
        addr: u32,
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

        // Ensure the address lies on a page boundary
        if addr & 0xfff != 0 {
            return Err(XousError::BadAlignment);
        }

        let mut offset = 0;
        // Happy path: The address is in main RAM
        if addr > self.ram_start && addr < self.ram_start + self.ram_size {
            offset += (addr - self.ram_start) / PAGE_SIZE as u32;
            return action_inner(&mut self.allocations[offset as usize], pid, action);
        }

        offset += self.ram_size / PAGE_SIZE as u32;
        // Go through additional regions looking for this address, and claim it
        // if it's not in use.
        for region in self.extra {
            if addr > region.mem_start && addr < region.mem_start + region.mem_size {
                offset += (addr - region.mem_start) / PAGE_SIZE as u32;
                return action_inner(&mut self.allocations[offset as usize], pid, action);
            }
            offset += self.ram_size / PAGE_SIZE as u32;
        }
        // sprintln!("mem: unable to claim or release");
        Err(XousError::BadAddress)
    }

    /// Mark a given address as being owned by the specified process ID
    fn claim_page(&mut self, addr: u32, pid: XousPid) -> Result<(), XousError> {
        self.claim_or_release(addr, pid, ClaimOrRelease::Claim)
    }

    /// Mark a given address as no longer being owned by the specified process ID
    fn release_page(&mut self, addr: u32, pid: XousPid) -> Result<(), XousError> {
        self.claim_or_release(addr, pid, ClaimOrRelease::Release)
    }
}
