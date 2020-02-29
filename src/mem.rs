use crate::args::KernelArguments;
use crate::definitions::{MemoryAddress, XousError, XousPid};
use core::fmt;
use core::mem;
use core::slice;
use core::str;

pub use crate::arch::mem::PAGE_SIZE;
use xous::MemoryFlags;

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
            "{} ({:08x}) {:08x} - {:08x} {} bytes",
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
    ram_name: u32,
}

static mut MEMORY_MANAGER: MemoryManager = MemoryManager {
    allocations: &mut [],
    extra: &[],
    ram_start: 0,
    ram_size: 0,
    ram_name: 0,
};



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
        assert!(xarg_def.data[1] == 1, "mm: XArg had unexpected version");
        mm.ram_start = xarg_def.data[2] as usize;
        mm.ram_size = xarg_def.data[3] as usize;
        mm.ram_name = xarg_def.data[4];

        let mut mem_size = mm.ram_size / PAGE_SIZE;
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
            mem_size += range.mem_size as usize / PAGE_SIZE;
        }

        mm.allocations =
            unsafe { slice::from_raw_parts_mut(base as *mut XousPid, mem_size) };
        Ok(unsafe { &mut MEMORY_MANAGER })
    }

    pub unsafe fn get() -> &'static mut MemoryManager {
        &mut MEMORY_MANAGER
    }

    // pub fn print_map(&self) {
    //     println!("Memory Maps:");
    //     let l1_pt = unsafe { &mut (*(PAGE_TABLE_ROOT_OFFSET as *mut RootPageTable)) };
    //     for (i, l1_entry) in l1_pt.entries.iter().enumerate() {
    //         if *l1_entry == 0 {
    //             continue;
    //         }
    //         let superpage_addr = i as u32 * (1 << 22);
    //         println!(
    //             "    {:4} Superpage for {:08x} @ {:08x} (flags: {:?})",
    //             i,
    //             superpage_addr,
    //             (*l1_entry >> 10) << 12,
    //             MMUFlags::from_bits(l1_entry & 0xff).unwrap()
    //         );
    //         // let l0_pt_addr = ((l1_entry >> 10) << 12) as *const u32;
    //         let l0_pt = unsafe { &mut (*((PAGE_TABLE_OFFSET + i * 4096) as *mut LeafPageTable)) };
    //         for (j, l0_entry) in l0_pt.entries.iter().enumerate() {
    //             if *l0_entry == 0 {
    //                 continue;
    //             }
    //             let page_addr = j as u32 * (1 << 12);
    //             println!(
    //                 "        {:4} {:08x} -> {:08x} (flags: {:?})",
    //                 j,
    //                 superpage_addr + page_addr,
    //                 (*l0_entry >> 10) << 12,
    //                 MMUFlags::from_bits(l0_entry & 0xff).unwrap()
    //             );
    //         }
    //     }
    // }

    // pub fn print_ownership(&self) {
    //     println!("Ownership ({} bytes in all):", self.allocations.len());

    //     let mut offset = 0;
    //     unsafe {
    //         // First, we build a &[u8]...
    //         let name_bytes = self.ram_name.to_le_bytes();
    //         // ... and then convert that slice into a string slice
    //         let ram_name = str::from_utf8_unchecked(&name_bytes);
    //         println!("    Region {} ({:08x}) {:08x} - {:08x} {} bytes:", ram_name, self.ram_name,
    //     self.ram_start, self.ram_start + self.ram_size, self.ram_size);
    //     };
    //     for o in 0..self.ram_size/PAGE_SIZE {
    //         if self.allocations[offset+o] != 0 {
    //             println!("        {:08x} => {}", self.ram_size + o * PAGE_SIZE, self.allocations[o]);
    //         }
    //     }

    //     offset += self.ram_size / PAGE_SIZE;

    //     // Go through additional regions looking for this address, and claim it
    //     // if it's not in use.
    //     for region in self.extra {
    //         println!("    Region {}:", region);
    //         for o in 0..(region.mem_size as usize)/PAGE_SIZE {
    //             if self.allocations[offset+o] != 0 {
    //                 println!("        {:08x} => {}",
    //                     (region.mem_start as usize) + o*PAGE_SIZE,
    //                     self.allocations[offset+o]
    //                 )
    //             }
    //         }
    //         offset += region.mem_size as usize / PAGE_SIZE;
    //     }
    // }

    /// Allocate a single page to the given process.
    /// Ensures the page is zeroed out prior to handing it over to
    /// the specified process.
    pub fn alloc_page(&mut self, pid: XousPid) -> Result<usize, XousError> {
        // Go through all RAM pages looking for a free page.
        // Optimization: start from the previous address.
        // println!("Allocating page for PID {}", pid);
        for index in 0..(self.ram_size as usize) / PAGE_SIZE {
            // println!("    Checking {:08x}...", index * PAGE_SIZE + self.ram_start as usize);
            if self.allocations[index] == 0 {
                self.allocations[index] = pid;
                return Ok(index * PAGE_SIZE + self.ram_start);
            }
        }
        Err(XousError::OutOfMemory)
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
        flags: MemoryFlags,
    ) -> Result<MemoryAddress, XousError> {
        let pid = crate::arch::current_pid();

        self.claim_page(phys, pid)?;
        if pid != 1 {
            println!("Mapping page inner...");
        }
        match crate::arch::mem::map_page_inner(self, pid, phys as usize, virt as usize, flags) {
            Ok(_) => {
                println!("Good result!");
                MemoryAddress::new(virt as usize).ok_or(XousError::BadAddress)
            }
            Err(e) => {
                println!("Failure -- releasing page");
                self.release_page(phys, pid)?;
                Err(e)
            }
        }
    }

    /// Attempt to map the given physical address into the virtual address space
    /// of this process.
    ///
    /// # Errors
    ///
    /// * MemoryInUse - The specified page is already mapped
    pub fn unmap_page(
        &mut self,
        phys: *mut usize,
        virt: *mut usize,
        flags: MemoryFlags,
    ) -> Result<(), XousError> {
        let pid = crate::arch::current_pid();
        self.release_page(phys, pid)?;
        crate::arch::mem::unmap_page_inner(self, pid, phys as usize, virt as usize, flags)
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
            if *addr != 0 && *addr != pid {
                return Err(XousError::MemoryInUse);
            }
            match action {
                ClaimOrRelease::Claim => {
                    *addr = pid;
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
        if addr >= self.ram_start && addr < self.ram_start + self.ram_size {
            offset += (addr - self.ram_start) / PAGE_SIZE;
            return action_inner(&mut self.allocations[offset], pid, action);
        }

        offset += self.ram_size / PAGE_SIZE;
        // Go through additional regions looking for this address, and claim it
        // if it's not in use.
        for region in self.extra {
            if addr >= (region.mem_start as usize)
                && addr < (region.mem_start + region.mem_size) as usize
            {
                offset += (addr - (region.mem_start as usize)) / PAGE_SIZE;
                return action_inner(&mut self.allocations[offset], pid, action);
            }
            offset += region.mem_size as usize / PAGE_SIZE;
        }
        println!("mem: unable to claim or release physical address {:08x}", addr);
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
