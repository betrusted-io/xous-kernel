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

        unsafe { mstatus::clear_mie() };

        // Map the bss section
        let start_bss = unsafe { transmute::<&usize, usize>(&_sbss) };
        let end_bss = unsafe { transmute::<&usize, usize>(&_ebss) };
        let bss_range = (start_bss..end_bss).step_by(PAGE_SIZE);

        let start_data = unsafe { transmute::<&usize, usize>(&_sdata) };
        let end_data = unsafe { transmute::<&usize, usize>(&_edata) };
        let data_range = (start_data..end_data).step_by(PAGE_SIZE);

        // Note: stack grows downwards so these are swapped.
        let start_stack = unsafe { transmute::<&usize, usize>(&_estack) };
        let end_stack = unsafe { transmute::<&usize, usize>(&_sstack) };
        let stack_range = (start_stack..end_stack).step_by(PAGE_SIZE);

        let start_text = unsafe { transmute::<&usize, usize>(&_stext) };
        let end_text = unsafe { transmute::<&usize, usize>(&_etext) };
        let text_range = (start_text..end_text).step_by(PAGE_SIZE);

        for region in bss_range {
            mm.claim_page(region & !0xfff, 1).unwrap();
        }

        for region in data_range {
            mm.claim_page(region & !0xfff, 1).unwrap();
        }

        for region in stack_range {
            mm.claim_page(region & !0xfff, 1).unwrap();
        }

        for region in text_range {
            mm.claim_page(region & !0xfff, 1).unwrap();
        }

        unsafe { mstatus::set_mie() };
        mm
    }

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

    // Create an identity mapping, copying the kernel to itself.
    pub fn create_identity(&mut self, satp: MemoryAddress, pid: XousPid) -> Result<(), XousError> {

        Err(XousError::OutOfMemory)
    }

    fn claim_page(&mut self, addr: usize, pid: XousPid) -> Result<(), XousError> {
        // Ensure the address lies on a page boundary
        if addr & 0xfff != 0 {
            return Err(XousError::BadAlignment);
        }

        match addr {
            FLASH_START..=FLASH_END => {
                Self::claim_page_inner(&mut self.flash, addr - FLASH_START, pid)
            }
            RAM_START..=RAM_END => Self::claim_page_inner(&mut self.ram, addr - RAM_START, pid),
            IO_START..=IO_END => Self::claim_page_inner(&mut self.io, addr - IO_START, pid),
            LCD_START..=LCD_END => Self::claim_page_inner(&mut self.lcd, addr - LCD_START, pid),
            _ => Err(XousError::BadAddress),
        }
    }

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
}
