// SPDX-License-Identifier: MPL-2.0

use crate::{
    arch::device::io_port::{ReadWriteAccess, WriteOnlyAccess},
    info,
    io::{IoPort, sensitive_io_port},
    warn,
};

sensitive_io_port! {
    unsafe {
        static MASTER_CMD: IoPort<u8, WriteOnlyAccess> = IoPort::new(0x20);
        static MASTER_DATA: IoPort<u8, ReadWriteAccess> = IoPort::new(0x21);
        static SLAVE_CMD: IoPort<u8, WriteOnlyAccess> = IoPort::new(0xA0);
        static SLAVE_DATA: IoPort<u8, WriteOnlyAccess> = IoPort::new(0xA1);
    }
}

const MASK_ALL: u8 = 0xff;
const IRQ_OFFSET: u8 = 0x20;

/// Initializes and disables the 8259 Programmable Interrupt Controller (PIC).
pub fn init_and_disable() {
    info!("Initializing PIC as disabled");

    set_mask(MASK_ALL, MASK_ALL);
}

/// Detects whether a legacy 8259A PIC is present.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.0/source/arch/x86/kernel/i8259.c#L306>.
pub fn is_present() -> bool {
    // IRQ line 2 of the master PIC is wired to the slave PIC (the cascade line),
    // so it is left unmasked while probing.
    const CASCADE_LINE: u8 = 1 << 2;
    const PROBE_VAL: u8 = !CASCADE_LINE;

    SLAVE_DATA.write(MASK_ALL);
    MASTER_DATA.write(PROBE_VAL);
    let is_present = MASTER_DATA.read() == PROBE_VAL;
    if !is_present {
        warn!("no legacy PIC detected");
    }
    is_present
}

fn set_mask(master_mask: u8, slave_mask: u8) {
    // Start initialization
    MASTER_CMD.write(0x11);
    SLAVE_CMD.write(0x11);

    // Set offsets
    // - Map master PIC vector 0x00~0x07 to IRQ number 0x20~0x27
    MASTER_DATA.write(IRQ_OFFSET);
    // - Map slave PIC vector 0x00~0x07 to IRQ number 0x28~0x2f
    SLAVE_DATA.write(IRQ_OFFSET + 0x08);

    // Set up cascade (there is a slave PIC at IRQ2)
    MASTER_DATA.write(4);
    SLAVE_DATA.write(2);

    // Set up interrupt mode (1 is 8086/88 mode, 2 is auto EOI)
    MASTER_DATA.write(1);
    SLAVE_DATA.write(1);

    // Mask interrupts
    MASTER_DATA.write(master_mask);
    SLAVE_DATA.write(slave_mask);
}
