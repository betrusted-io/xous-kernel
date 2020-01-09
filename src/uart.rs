use core::fmt::{Error, Write};

pub struct Uart {}

impl Uart {
    pub fn new() -> Uart {
        Uart {}
    }

    pub fn putc(&self, c: u8) {
        let ptr = 0xE000_1800 as *mut u32;
        unsafe {
            while ptr.add(1).read_volatile() == 0 {}
            ptr.add(0).write_volatile(c as u32);
        }
    }

    fn get(&self, base_addr: usize) -> Option<u8> {
        let ptr = 0xE000_1800 as *mut u32;
        unsafe {
            if ptr.add(2).read_volatile() == 0 {
                Some(ptr.add(0).read_volatile() as u8)
            } else {
                None
            }
        }
    }
}

// This is a slightly different syntax. Write is this "trait", meaning it is much like
// an interface where we're just guaranteeing a certain function signature. In the Write
// trait, one is absolutely required to be implemented, which is write_str. There are other
// functions, but they all rely on write_str(), so their default implementation is OK for now.
impl Write for Uart {
    // The trait Write expects us to write the function write_str
    // which looks like:
    fn write_str(&mut self, s: &str) -> Result<(), Error> {
        for c in s.bytes() {
            self.putc(c);
        }
        // Return that we succeeded.
        Ok(())
    }
}

#[macro_export]
macro_rules! print
{
	($($args:tt)+) => ({
			use core::fmt::Write;
			let _ = write!(crate::uart::Uart::new(), $($args)+);
	});
}
#[macro_export]
macro_rules! println
{
	() => ({
		print!("\r\n")
	});
	($fmt:expr) => ({
		print!(concat!($fmt, "\r\n"))
	});
	($fmt:expr, $($args:tt)+) => ({
		print!(concat!($fmt, "\r\n"), $($args)+)
	});
}
