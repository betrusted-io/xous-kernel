static mut TIME_MS: u32 = 0;

pub fn irq(_irq_number: usize) {
    let timer_base = 0xE0002800 as *mut u8;
    unsafe {
        TIME_MS = TIME_MS + 1;
        timer_base.add(0x3c).write_volatile(1);
    };
}

pub fn get_time() -> u32 {
    unsafe { TIME_MS }
}

pub fn time_init() {
    let timer_base = 0xE0002800 as *mut u8;
    let period = 12_000_000 / 1000; // 12 MHz, 1 ms timer
    unsafe {
        // Disable, so we can update it
        timer_base.add(0x20).write_volatile(0);

        // Update "reload" register
        timer_base.add(0x10).write_volatile((period >> 24) as u8);
        timer_base.add(0x14).write_volatile((period >> 16) as u8);
        timer_base.add(0x18).write_volatile((period >> 8) as u8);
        timer_base.add(0x1c).write_volatile((period >> 0) as u8);

        // Update "load" register
        timer_base.add(0x00).write_volatile((period >> 24) as u8);
        timer_base.add(0x04).write_volatile((period >> 16) as u8);
        timer_base.add(0x08).write_volatile((period >> 8) as u8);
        timer_base.add(0x0c).write_volatile((period >> 0) as u8);

        // Enable ISR
        timer_base.add(0x40).write_volatile(1);

        // Set "pending" as well to clear it
        timer_base.add(0x38).write_volatile(1);

        // Finally, enable it
        timer_base.add(0x20).write_volatile(1);
    }
}
