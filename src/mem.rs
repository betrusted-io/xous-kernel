use crate::definitions::{MemoryAddress, XousError, XousPid};
use crate::processtable::Process;
use crate::{print, println};
use core::num::NonZeroUsize;
use vexriscv::register::mstatus;

const FLASH_START: usize = 0x20000000;
const FLASH_SIZE: usize = 16_777_216;
const FLASH_END: usize = FLASH_START + FLASH_SIZE;
const RAM_START: usize = 0x40000000;
const RAM_SIZE: usize = 16_777_216;
const RAM_END: usize = RAM_START + RAM_SIZE;
const IO_START: usize = 0xe0000000;
const IO_SIZE: usize = 65_536;
const IO_END: usize = IO_START + IO_SIZE;
const LCD_START: usize = 0xB0000000;
const LCD_SIZE: usize = 32_768;
const LCD_END: usize = LCD_START + LCD_SIZE;

const PAGE_SIZE: usize = 4096;

const FLASH_PAGE_COUNT: usize = FLASH_SIZE / PAGE_SIZE;
const RAM_PAGE_COUNT: usize = RAM_SIZE / PAGE_SIZE;
const IO_PAGE_COUNT: usize = IO_SIZE;
const LCD_PAGE_COUNT: usize = LCD_SIZE / PAGE_SIZE;

extern "Rust" {
    fn flush_mmu();
}

pub struct MemoryManagerInner {
    ram: [XousPid; RAM_PAGE_COUNT],
    flash: [XousPid; FLASH_PAGE_COUNT],
    io: [XousPid; IO_PAGE_COUNT],
    lcd: [XousPid; LCD_PAGE_COUNT],
}

pub struct MemoryManager {}

static mut MM: MemoryManagerInner = MemoryManagerInner {
    flash: [0; FLASH_PAGE_COUNT],
    ram: [0; RAM_PAGE_COUNT],
    io: [0; IO_PAGE_COUNT],
    lcd: [0; LCD_PAGE_COUNT],
};

impl core::fmt::Debug for MemoryManagerInner {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::result::Result<(), core::fmt::Error> {
        writeln!(fmt, "Ranges: ")?;
        writeln!(
            fmt,
            "    flash: {:08x} .. {:08x} ({} pages)",
            FLASH_START,
            FLASH_END,
            self.flash.len()
        )?;
        writeln!(
            fmt,
            "    ram:   {:08x} .. {:08x} ({} pages)",
            RAM_START,
            RAM_END,
            self.ram.len()
        )?;
        writeln!(
            fmt,
            "    io:    {:08x} .. {:08x} ({} pages)",
            IO_START,
            IO_END,
            self.io.len()
        )?;
        writeln!(
            fmt,
            "    lcd:   {:08x} .. {:08x} ({} pages)",
            LCD_START,
            LCD_END,
            self.lcd.len()
        )?;
        Ok(())
    }
}

impl core::fmt::Debug for MemoryManager {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::result::Result<(), core::fmt::Error> {
        unsafe { write!(fmt, "{:?}", MM) }
    }
}

/// A single RISC-V page table entry.  In order to resolve an address,
/// we need two entries: the top level, followed by the lower level.
struct PageTable {
    entries: [usize; 1024],
}

extern "C" {
    // Boundaries of the .bss section
    static mut _ebss: usize;
    static mut _sbss: usize;

    // Boundaries of the .data section
    static mut _edata: usize;
    static mut _sdata: usize;

    // Boundaries of the stack
    static mut _estack: usize;
    static mut _sstack: usize;

    // Boundaries of the .text section
    static mut _stext: usize;
    static mut _etext: usize;

    // Boundaries of the heap
    static _sheap: usize;
    static _eheap: usize;

    // Initial values of the .data section (stored in Flash)
    static _sidata: usize;
}

use core::mem::transmute;

/// Enable transmuting from pointers-to-addresses to addresses.
/// This is required because the linker creates variables
/// such as _stext that are located at specific offsets -- such
/// as the start of the text section -- and their address is
/// the actual piece of data we want.
/// Rust really doesn't like going from addresses to values, so
/// we transmute from one to the other in order to construct a
/// range that we can loop through.
macro_rules! mem_range {
    ( $s:expr, $e:expr ) => {{
        let start = unsafe { transmute::<&usize, usize>(&$s) };
        let end = unsafe { transmute::<&usize, usize>(&$e) };
        (start..end).step_by(PAGE_SIZE)
    }}
}

/// Initialize the memory map.
/// This will go through memory and map anything that the kernel is
/// using to process 1, then allocate a pagetable for this process
/// and place it at the usual offset.  The MMU will not be enabled yet,
/// as the process entry has not yet been created.
impl MemoryManager {
    pub fn new() -> Result<MemoryManager, XousError> {
        Ok(MemoryManager {})
    }

    pub fn init(&mut self) -> Result<(), XousError> {
        println!("Initializing Memory Manager: {:?}", self);

        // Claim existing pages for PID 1, in preparation for turning on
        // the MMU.
        unsafe { mstatus::clear_mie() };

        let mut ranges = [
            mem_range!(&_sbss, &_ebss),
            mem_range!(&_sdata, &_edata),
            mem_range!(&_sstack, &_estack),
            mem_range!(&_stext, &_etext),
        ];
        for range in &mut ranges {
            for region in range {
                self.claim_page(region & !0xfff, 1)?;
            }
        }
        self.claim_page(0xe000_1000, 1)?;

        unsafe { mstatus::set_mie() };

        Ok(())
    }

    /// Allocate a single page to the given process.
    /// Ensures the page is zeroed out prior to handing it over to
    /// the specified process.
    pub fn alloc_page(&mut self, pid: XousPid) -> Result<MemoryAddress, XousError> {
        assert!(pid != 0);
        let mut mm = unsafe { &mut MM };

        // Go through all RAM pages looking for a free page.
        // Optimization: start from the previous address.
        // println!("Allocating page for PID {}", pid);
        for index in 0..RAM_PAGE_COUNT {
            // println!("    Checking {:08x}...", index * PAGE_SIZE + RAM_START);
            if mm.ram[index] == 0 {
                mm.ram[index] = pid;
                let page_addr = (index * PAGE_SIZE + RAM_START) as *mut u32;
                // Zero-out the page
                unsafe {
                    for i in 0..PAGE_SIZE / 4 {
                        *page_addr.add(i) = 0;
                    }
                }
                let new_page = unsafe { transmute::<*mut u32, usize>(page_addr) };
                // println!("    Page {:08x} is free", new_page);
                return Ok(NonZeroUsize::new(new_page).expect("Allocated an invalid page"));
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
        root: &mut PageTable,
        phys: usize,
        virt: usize,
    ) -> Result<(), XousError> {
        let ppn1 = (phys >> 22) & ((1 << 12) - 1);
        let ppn0 = (phys >> 12) & ((1 << 10) - 1);
        let ppo = (phys >> 0) & ((1 << 12) - 1);

        let vpn1 = (virt >> 22) & ((1 << 10) - 1);
        let vpn0 = (virt >> 12) & ((1 << 10) - 1);
        let vpo = (virt >> 0) & ((1 << 12) - 1);

        println!(
            "Mapping phys: {:08x} -> virt: {:08x}  (vpn1: {:04x}  vpn0: {:04x}    ppn1: {:04x}  ppn0: {:04x})",
            phys, virt, vpn1, vpn0, ppn1, ppn0
        );
        assert!(ppn1 < 4096);
        assert!(ppn0 < 1024);
        assert!(ppo < 4096);
        assert!(vpn1 < 1024);
        assert!(vpn0 < 1024);
        assert!(vpo < 4096);

        let ref mut l1_pt = root.entries;
        println!("l1_pt is at {:p}  ({:p})", &l1_pt, &l1_pt[vpn1]);

        // Allocate a new level 1 pagetable entry if one doesn't exist.
        if l1_pt[vpn1] & 1 == 0 {
            println!(
                "    top-level VPN1 {:04x}: {:08x} (will allocate a new one)",
                vpn1, l1_pt[vpn1]
            );
            // Allocate the page to the kernel (PID 1)
            let new_addr = self.alloc_page(1)?.get();
            println!(
                "    Allocated new top-level page for VPN1 {:04x} in process @ {:08x}",
                vpn1, new_addr
            );

            // Mark this entry as a leaf node (WRX as 0), and indicate
            // it is a valid page by setting "V".
            let ppn = new_addr >> 12;
            l1_pt[vpn1] = (ppn << 10) | 1;
            println!("    New top-level page entry: {:08x}", l1_pt[vpn1]);
        }

        let l0_pt_idx =
            unsafe { &mut (*(((l1_pt[vpn1] << 2) & !((1 << 12) - 1)) as *mut PageTable)) };
        let ref mut l0_pt = l0_pt_idx.entries;
        println!("    l0_pt is at {:p}  ({:p})", &l0_pt, &l0_pt[vpn0]);

        // Allocate a new level 0 pagetable entry if one doesn't exist.
        if l0_pt[vpn0] & 1 != 0 {
            println!("Page already allocated!");
        }
        l0_pt[vpn0] = (ppn1 << 20) | (ppn0 << 10) | 1 | 0xe | 0xd0;
        Ok(())
    }

    /// Create an identity mapping, copying the kernel to itself
    pub fn create_identity(&mut self, satp: MemoryAddress) -> Result<(), XousError> {
        let root_page = (satp.get() & ((1 << 22) - 1)) << 12;
        assert!(root_page >= RAM_START);
        assert!(root_page < RAM_END);

        let pt = unsafe { &mut (*(root_page as *mut PageTable)) };
        println!(
            "Root page: {:08x}  pt: {:p}  pt: {:p}",
            root_page, &pt, pt
        );

        let mut ranges = [
            mem_range!(&_sbss, &_ebss),
            mem_range!(&_sdata, &_edata),
            mem_range!(&_sstack, &_estack),
            mem_range!(&_stext, &_etext),
        ];
        for range in &mut ranges {
            for region in range {
                self.map_page_inner(pt, region, region)?;
                println!("");
            }
        }

        self.map_page_inner(pt, 0xe0001000, 0x0e00_1000)?;
        println!("");
        unsafe { flush_mmu() };

        Ok(())
    }

    pub fn map_page(&mut self, satp: usize, phys: usize, virt: usize) -> Result<MemoryAddress, XousError> {
        let root_page = (satp & ((1 << 22) - 1)) << 12;
        let pid = ((satp >> 22) & ((1<<9)-1)) as XousPid;
        assert!(root_page >= RAM_START);
        assert!(root_page < RAM_END);
        assert!(pid != 0);
        let pt = unsafe { &mut (*(root_page as *mut PageTable)) };

        self.claim_page(phys, pid)?;
        match self.map_page_inner(pt, phys, virt) {
            Ok(_) => {
                unsafe { flush_mmu() };
                Ok(MemoryAddress::new(virt).expect("Virt address was not 0"))
            },
            Err(e) => {
                self.release_page(phys, pid);
                Err(e)
            }
        }
    }

    /// Mark a given address as being owned by the specified process ID
    fn claim_page(&mut self, addr: usize, pid: XousPid) -> Result<(), XousError> {
        let mut mm = unsafe { &mut MM };

        fn claim_page_inner(tbl: &mut [u8], addr: usize, pid: XousPid) -> Result<(), XousError> {
            let page = addr / PAGE_SIZE;
            if page > tbl.len() {
                return Err(XousError::BadAddress);
            }
            if tbl[page] != 0 && tbl[page] != pid {
                return Err(XousError::MemoryInUse);
            }
            tbl[page] = pid;
            Ok(())
        }

        // Ensure the address lies on a page boundary
        if addr & 0xfff != 0 {
            return Err(XousError::BadAlignment);
        }

        match addr {
            FLASH_START..=FLASH_END => claim_page_inner(&mut mm.flash, addr - FLASH_START, pid),
            RAM_START..=RAM_END => claim_page_inner(&mut mm.ram, addr - RAM_START, pid),
            IO_START..=IO_END => claim_page_inner(&mut mm.io, addr - IO_START, pid),
            LCD_START..=LCD_END => claim_page_inner(&mut mm.lcd, addr - LCD_START, pid),
            _ => Err(XousError::BadAddress),
        }
    }

    /// Mark a given address as being owned by the specified process ID
    fn release_page(&mut self, addr: usize, pid: XousPid) -> Result<(), XousError> {
        let mut mm = unsafe { &mut MM };

        fn release_page_inner(tbl: &mut [u8], addr: usize, pid: XousPid) -> Result<(), XousError> {
            let page = addr / PAGE_SIZE;
            if page > tbl.len() {
                return Err(XousError::BadAddress);
            }
            if tbl[page] != pid {
                return Err(XousError::MemoryInUse);
            }
            tbl[page] = 0;
            Ok(())
        }

        // Ensure the address lies on a page boundary
        if addr & 0xfff != 0 {
            return Err(XousError::BadAlignment);
        }

        match addr {
            FLASH_START..=FLASH_END => release_page_inner(&mut mm.flash, addr - FLASH_START, pid),
            RAM_START..=RAM_END => release_page_inner(&mut mm.ram, addr - RAM_START, pid),
            IO_START..=IO_END => release_page_inner(&mut mm.io, addr - IO_START, pid),
            LCD_START..=LCD_END => release_page_inner(&mut mm.lcd, addr - LCD_START, pid),
            _ => Err(XousError::BadAddress),
        }
    }
}
