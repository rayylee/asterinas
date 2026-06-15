// SPDX-License-Identifier: MPL-2.0

//! Linux kernel AIO (asynchronous I/O) context management.
//!
//! Implements the data structures and operations backing the `io_setup`, `io_submit`,
//! `io_getevents`, `io_cancel`, and `io_destroy` syscalls.

use align_ext::AlignExt;
use core::{mem::size_of, sync::atomic::AtomicUsize, time::Duration};
use ostd::sync::WaitQueue;

use crate::{
    prelude::*,
    time::wait::ManagedTimeout,
    vm::{
        page_cache::{Vmo, VmoOptions},
        perms::VmPerms,
        vmar::Vmar,
    },
};

// ---------------------------------------------------------------------------
// Public AIO opcodes (match Linux IOCB_CMD_* values)
// ---------------------------------------------------------------------------

pub const IOCB_CMD_PREAD: u16 = 0;
pub const IOCB_CMD_PWRITE: u16 = 1;
pub const IOCB_CMD_FSYNC: u16 = 2;
pub const IOCB_CMD_FDSYNC: u16 = 3;

// ---------------------------------------------------------------------------
// Wire-compatible structs (must match Linux kernel ABI)
// ---------------------------------------------------------------------------

/// Header of the `aio_ring` shared between kernel and user space.
/// Placed at the beginning of the mmap'd region.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct AioRingHeader {
    pub id: u32,
    pub nr: u32,
    pub head: u32,
    pub tail: u32,
    pub magic: u32,
    pub compat_features: u32,
    pub incompat_features: u32,
    pub header_length: u32,
}

pub const AIO_RING_MAGIC: u32 = 0xa10a10a1;
pub const AIO_RING_HEADER_SIZE: usize = size_of::<AioRingHeader>();

/// The `iocb` struct as seen by user space (64 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct Iocb {
    pub data: u64,
    pub key: u32,
    pub rw_flags: u32,
    pub opcode: u16,
    pub reqprio: i16,
    pub fildes: u32,
    pub buf: u64,
    pub nbytes: u64,
    pub offset: i64,
    pub reserved2: u64,
    pub flags: u32,
    pub resfd: u32,
}

/// The `io_event` struct returned by `io_getevents` (32 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct IoEvent {
    pub data: u64,
    pub obj: u64,
    pub res: i64,
    pub res2: i64,
}

// ---------------------------------------------------------------------------
// AioContext
// ---------------------------------------------------------------------------

pub struct AioContext {
    pub ring_va: u64,
    pub ring_vmo: Arc<Vmo>,
    pub ring_size: usize,
    pub nr_events: u32,
    pub pending: AtomicUsize,
    pub wait_queue: WaitQueue,
    inner: Mutex<AioInner>,
}

struct AioInner {
    /// Number of events currently stored in `events`.
    events: VecDeque<IoEvent>,
}

impl AioContext {
    /// Allocates a new AIO context, maps the ring into user space, and returns
    /// `(ring_va, Arc<AioContext>)`.
    pub fn alloc(nr_events: u32, vmar: &Vmar) -> Result<(u64, Arc<Self>)> {
        if nr_events == 0 || nr_events > 0x10000 {
            return_errno_with_message!(Errno::EINVAL, "invalid nr_events for io_setup");
        }

        let event_area = nr_events as usize * size_of::<IoEvent>();
        let ring_size = (AIO_RING_HEADER_SIZE + event_area).align_up(PAGE_SIZE);

        let vmo = VmoOptions::new(ring_size).alloc()?;

        // Write the ring header into the VMO.
        let header = AioRingHeader {
            id: 0,
            nr: nr_events,
            head: 0,
            tail: 0,
            magic: AIO_RING_MAGIC,
            compat_features: 1,
            incompat_features: 0,
            header_length: AIO_RING_HEADER_SIZE as u32,
        };
        vmo.write(
            0,
            &mut VmReader::from(header.as_bytes()).to_fallible(),
        )
        .map_err(|_| Error::with_message(Errno::ENOMEM, "failed to write aio_ring header"))?;

        // Map the VMO into the user VMAR (readable + writable, shared).
        let ring_va = vmar
            .new_map(ring_size, VmPerms::READ | VmPerms::WRITE)?
            .vmo(vmo.clone())
            .is_shared(true)
            .build()? as u64;

        let ctx = Arc::new(AioContext {
            ring_va,
            ring_vmo: vmo,
            ring_size,
            nr_events,
            pending: AtomicUsize::new(0),
            wait_queue: WaitQueue::new(),
            inner: Mutex::new(AioInner {
                events: VecDeque::new(),
            }),
        });

        Ok((ring_va, ctx))
    }

    /// Pushes a completed `io_event` into the context and wakes waiters.
    #[allow(dead_code)]
    pub fn push_event(&self, event: IoEvent) {
        {
            let mut inner = self.inner.lock();
            inner.events.push_back(event);
        }
        self.wait_queue.wake_all();
    }

    /// Harvests up to `nr` completed events without blocking.
    pub fn harvest_events(&self, nr: u32) -> Vec<IoEvent> {
        let mut inner = self.inner.lock();
        let take = (nr as usize).min(inner.events.len());
        inner.events.drain(..take).collect()
    }

    /// Reads the current head value from the ring VMO (updated by user space).
    #[allow(dead_code)]
    fn ring_head(&self) -> u32 {
        let mut buf = [0u8; 4];
        let offset = core::mem::offset_of!(AioRingHeader, head);
        let _ = self
            .ring_vmo
            .read(offset, &mut VmWriter::from(buf.as_mut_slice()).to_fallible());
        u32::from_ne_bytes(buf)
    }

    /// Writes the kernel-side tail into the ring VMO so user space can poll it.
    fn write_ring_tail(&self, tail: u32) {
        let offset = core::mem::offset_of!(AioRingHeader, tail);
        let _ = self.ring_vmo.write(
            offset,
            &mut VmReader::from(tail.to_ne_bytes().as_slice()).to_fallible(),
        );
    }

    /// Writes an `io_event` into the ring VMO at slot `idx`.
    fn write_ring_event(&self, idx: u32, event: &IoEvent) {
        let offset = AIO_RING_HEADER_SIZE + idx as usize * size_of::<IoEvent>();
        let _ = self.ring_vmo.write(
            offset,
            &mut VmReader::from(event.as_bytes()).to_fallible(),
        );
    }

    /// Pushes `event` into the VMO ring (in addition to the in-kernel queue).
    /// Called from completion callbacks to make events visible to user space polling.
    pub fn push_event_to_ring(&self, event: IoEvent) {
        // Append to kernel-internal queue (for io_getevents blocking path).
        {
            let mut inner = self.inner.lock();
            let tail = {
                let offset = core::mem::offset_of!(AioRingHeader, tail);
                let mut buf = [0u8; 4];
                let _ = self
                    .ring_vmo
                    .read(offset, &mut VmWriter::from(buf.as_mut_slice()).to_fallible());
                u32::from_ne_bytes(buf)
            };
            let slot = tail % self.nr_events;
            self.write_ring_event(slot, &event);
            let new_tail = (tail + 1) % self.nr_events;
            self.write_ring_tail(new_tail);
            inner.events.push_back(event);
        }
        self.wait_queue.wake_all();
    }

    /// Waits until at least `min_nr` events are available, then returns up to `nr` events.
    ///
    /// `timeout` is a relative duration. Returns `ETIME` on timeout.
    pub fn wait_for_events(
        &self,
        min_nr: u32,
        nr: u32,
        timeout: Option<Duration>,
    ) -> Result<Vec<IoEvent>> {
        if min_nr == 0 {
            return Ok(self.harvest_events(nr));
        }

        let managed_timeout = timeout.map(ManagedTimeout::new);

        self.wait_queue.wait_until_or_timeout(
            || {
                let count = self.inner.lock().events.len();
                if count >= min_nr as usize {
                    Some(())
                } else {
                    None
                }
            },
            managed_timeout,
        )?;

        Ok(self.harvest_events(nr))
    }
}
