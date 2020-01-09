use crate::definitions::{XousError, XousPid, MemoryAddress};
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
pub struct MemoryManager {
    flash: [XousPid; FLASH_PAGE_COUNT],
    ram: [XousPid; RAM_PAGE_COUNT],
    io: [XousPid; IO_PAGE_COUNT],
    lcd: [XousPid; LCD_PAGE_COUNT],
}

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

macro_rules! mem_range {
    ( $s:expr, $e:expr ) => {{
        let start = unsafe { transmute::<&usize, usize>(&$s) };
        let end = unsafe { transmute::<&usize, usize>(&$e) };
        (start..end).step_by(PAGE_SIZE)
    }}
}

/// Initialzie the memory map.
/// This will go through memory and map anything that the kernel is
/// using to process 1, then allocate a pagetable for this process
/// and place it at the usual offset.  The MMU will not be enabled yet,
/// as the process entry has not yet been created.
impl MemoryManager {
    pub fn new() -> MemoryManager {
        let mut mm = MemoryManager {
            flash: [0; FLASH_PAGE_COUNT],
            ram: [0; RAM_PAGE_COUNT],
            io: [0; IO_PAGE_COUNT],
            lcd: [0; LCD_PAGE_COUNT],
        };

        mm
    }

    /// Allocate a single page to the given process.
    pub fn alloc_page(&mut self, pid: XousPid) -> Result<MemoryAddress, XousError> {
        // Go through all RAM pages looking for a free page.
        // Optimization: start from the previous address.
        for index in 0..RAM_PAGE_COUNT {
            if self.ram[index] == 0 {
                self.ram[index] = pid;
                let page_addr = (index * PAGE_SIZE + RAM_START) as *mut u32;
                // Zero-out the page
                unsafe {
                    for i in 0..PAGE_SIZE/4 {
                        *page_addr.add(i) = 0;
                    }
                }
                let new_page = unsafe { transmute::<*mut u32, usize>(page_addr) };
                return Ok(NonZeroUsize::new(new_page).unwrap());
            }
        }
        Err(XousError::OutOfMemory)
    }

    /// Create an identity mapping, copying the kernel to itself
    pub fn create_identity(&mut self, satp: MemoryAddress, pid: XousPid) -> Result<(), XousError> {
        let pt = unsafe { transmute::<MemoryAddress, &mut PageTable>(satp) };

        unsafe { mstatus::clear_mie() };

        let ranges = [
            mem_range!(&_sbss, &_ebss),
            mem_range!(&_sdata, &_edata),
            mem_range!(&_estack, &_sstack), // NOTE: Stack is reversed
            mem_range!(&_stext, &_etext),
        ];
        for range in &ranges {
            for region in range.clone() {
                self.map_page(pt, pid)?;
                self.claim_page(region & !0xfff, 1)?;
            }
        }

        unsafe { mstatus::set_mie() };

        Err(XousError::OutOfMemory)
    }

    fn map_page(&mut self, satp: &mut PageTable, pid: XousPid) -> Result<(), XousError> {
        Err(XousError::OutOfMemory)
    }

    /// Mark a given address as being owned by the specified process ID
    fn claim_page(&mut self, addr: usize, pid: XousPid) -> Result<(), XousError> {
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
            FLASH_START..=FLASH_END => {
                claim_page_inner(&mut self.flash, addr - FLASH_START, pid)
            }
            RAM_START..=RAM_END => claim_page_inner(&mut self.ram, addr - RAM_START, pid),
            IO_START..=IO_END => claim_page_inner(&mut self.io, addr - IO_START, pid),
            LCD_START..=LCD_END => claim_page_inner(&mut self.lcd, addr - LCD_START, pid),
            _ => Err(XousError::BadAddress),
        }
    }

}
