// SPDX-License-Identifier: MPL-2.0

use core::{
    mem,
    ops::Range,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use ostd::sync::WaitQueue;

use crate::{
    fs::{self, file::FileLike},
    prelude::*,
    thread::work_queue::{self, WorkPriority},
    vm::{perms::VmPerms, vmar::Vmar},
};

const AIO_RING_MAGIC: u32 = 0xa10a10a1;
const AIO_RING_COMPAT_FEATURES: u32 = 1;
const AIO_RING_INCOMPAT_FEATURES: u32 = 0;
const AIO_MAX_EVENTS: usize = 65_536;

static AIO_NR_EVENTS: AtomicUsize = AtomicUsize::new(0);

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod)]
struct RawAioRing {
    id: u32,
    nr: u32,
    head: u32,
    tail: u32,
    magic: u32,
    compat_features: u32,
    incompat_features: u32,
    header_length: u32,
}

/// Notifies userspace that an AIO request has completed.
pub(crate) trait AioNotifier: Send + Sync {
    /// Sends a best-effort completion notification.
    fn notify(&self);
}

/// A per-address-space native AIO context table.
pub(crate) struct AioTable {
    contexts: Mutex<BTreeMap<u64, Arc<AioContext>>>,
}

impl AioTable {
    /// Creates an empty AIO table.
    pub(crate) fn new() -> Self {
        Self {
            contexts: Mutex::new(BTreeMap::new()),
        }
    }

    /// Creates a new AIO context and returns its ID.
    pub(crate) fn setup_context(&self, vmar: &Vmar, max_events: usize) -> Result<u64> {
        let quota = AioQuotaGuard::reserve(max_events)?;
        let ring = AioRing::map(vmar, max_events)?;
        let ctx_id = ring.base() as u64;
        let context = Arc::new(AioContext::new(max_events, ring, quota));

        let mut contexts = self.contexts.lock();
        if contexts.contains_key(&ctx_id) {
            context.destroy();
            context.unmap_ring(vmar);
            return_errno_with_message!(Errno::EAGAIN, "AIO context ID collides");
        }

        contexts.insert(ctx_id, context);
        Ok(ctx_id)
    }

    /// Looks up an AIO context by ID.
    pub(crate) fn lookup_context(&self, ctx_id: u64) -> Result<Arc<AioContext>> {
        validate_context_id(ctx_id)?;

        self.contexts
            .lock()
            .get(&ctx_id)
            .cloned()
            .ok_or_else(|| Error::with_message(Errno::EINVAL, "AIO context ID does not exist"))
    }

    /// Removes an AIO context by ID.
    pub(crate) fn remove_context(&self, ctx_id: u64) -> Result<Arc<AioContext>> {
        validate_context_id(ctx_id)?;

        self.contexts
            .lock()
            .remove(&ctx_id)
            .ok_or_else(|| Error::with_message(Errno::EINVAL, "AIO context ID does not exist"))
    }
}

impl Drop for AioTable {
    fn drop(&mut self) {
        let contexts = mem::take(&mut *self.contexts.lock());
        for context in contexts.into_values() {
            context.destroy();
        }
    }
}

fn validate_context_id(ctx_id: u64) -> Result<()> {
    if ctx_id == 0 {
        return_errno_with_message!(Errno::EINVAL, "invalid AIO context ID");
    }

    Ok(())
}

struct AioQuotaGuard {
    nr_events: usize,
}

impl AioQuotaGuard {
    fn reserve(nr_events: usize) -> Result<Self> {
        let mut current = AIO_NR_EVENTS.load(Ordering::Relaxed);
        loop {
            let Some(next) = current.checked_add(nr_events) else {
                return_errno_with_message!(Errno::EAGAIN, "AIO event quota is exhausted");
            };
            if next > AIO_MAX_EVENTS {
                return_errno_with_message!(Errno::EAGAIN, "AIO event quota is exhausted");
            }

            match AIO_NR_EVENTS.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(Self { nr_events }),
                Err(observed) => current = observed,
            }
        }
    }
}

impl Drop for AioQuotaGuard {
    fn drop(&mut self) {
        let old_nr_events = AIO_NR_EVENTS.fetch_sub(self.nr_events, Ordering::AcqRel);
        debug_assert!(old_nr_events >= self.nr_events);
    }
}

/// A native AIO context.
pub(crate) struct AioContext {
    max_events: usize,
    _quota: AioQuotaGuard,
    ring: AioRing,
    inner: Mutex<AioContextInner>,
    wait_queue: WaitQueue,
}

struct AioContextInner {
    active: usize,
    destroying: bool,
}

impl AioContext {
    fn new(max_events: usize, ring: AioRing, quota: AioQuotaGuard) -> Self {
        Self {
            max_events,
            _quota: quota,
            ring,
            inner: Mutex::new(AioContextInner {
                active: 0,
                destroying: false,
            }),
            wait_queue: WaitQueue::new(),
        }
    }

    /// Reserves one completion slot for a submitted request.
    pub(crate) fn reserve_event(&self, vmar: &Vmar) -> Result<()> {
        let mut inner = self.inner.lock();
        if inner.destroying {
            return_errno_with_message!(Errno::EINVAL, "AIO context is being destroyed");
        }
        if inner.active >= self.max_events {
            return_errno_with_message!(Errno::EAGAIN, "AIO context has no free event slots");
        }
        if !self.ring.can_reserve(vmar, inner.active)? {
            return_errno_with_message!(Errno::EAGAIN, "AIO completion ring is full");
        }
        inner.active += 1;
        Ok(())
    }

    /// Submits a request to the global workqueue.
    pub(crate) fn submit(self: &Arc<Self>, request: AioRequest) {
        let context = self.clone();
        work_queue::submit_work_func(
            move || {
                request.finish(&context);
            },
            WorkPriority::Normal,
        );
    }

    fn complete(&self, vmar: &Vmar, event: AioEvent) -> bool {
        let mut inner = self.inner.lock();
        inner.active = inner.active.saturating_sub(1);
        if inner.destroying {
            self.wait_queue.wake_all();
            return false;
        }

        if let Err(err) = self.ring.push_event(vmar, event) {
            warn!("failed to push an AIO event to userspace ring: {:?}", err);
            self.wait_queue.wake_all();
            return false;
        }

        self.wait_queue.wake_all();
        true
    }

    /// Destroys this context.
    pub(crate) fn destroy(&self) {
        let mut inner = self.inner.lock();
        inner.destroying = true;
        self.wait_queue.wake_all();
    }

    /// Unmaps the userspace AIO ring.
    pub(crate) fn unmap_ring(&self, vmar: &Vmar) {
        let _ = vmar.remove_mapping(self.ring.mapping_range());
    }

    /// Waits for completed AIO events.
    pub(crate) fn wait_events(
        &self,
        vmar: &Vmar,
        min_nr: usize,
        nr: usize,
        timeout: Option<&Duration>,
    ) -> Result<Vec<AioEvent>> {
        let take_ready = || self.take_ready_events(vmar, min_nr, nr);

        if let Some(events) = take_ready() {
            return events;
        }

        match self.wait_queue.wait_until_or_timeout(take_ready, timeout) {
            Ok(events) => events,
            Err(err) if err.error() == Errno::ETIME => {
                self.take_any_events(vmar, nr).unwrap_or(Ok(Vec::new()))
            }
            Err(err) => Err(err),
        }
    }

    fn take_ready_events(
        &self,
        vmar: &Vmar,
        min_nr: usize,
        nr: usize,
    ) -> Option<Result<Vec<AioEvent>>> {
        let inner = self.inner.lock();
        let ready_count = match self.ring.available_events(vmar) {
            Ok(count) => count,
            Err(err) => return Some(Err(err)),
        };

        if inner.destroying && ready_count < min_nr {
            return Some(Ok(Vec::new()));
        }
        if ready_count < min_nr {
            return None;
        }

        Some(self.ring.drain_events(vmar, nr))
    }

    fn take_any_events(&self, vmar: &Vmar, nr: usize) -> Option<Result<Vec<AioEvent>>> {
        let _inner = self.inner.lock();
        match self.ring.available_events(vmar) {
            Ok(0) => None,
            Ok(_) => Some(self.ring.drain_events(vmar, nr)),
            Err(err) => Some(Err(err)),
        }
    }
}

struct AioRing {
    base: Vaddr,
    mapping_size: usize,
    nr_events: usize,
}

impl AioRing {
    fn map(vmar: &Vmar, max_events: usize) -> Result<Self> {
        let nr_events = max_events
            .checked_add(1)
            .ok_or_else(|| Error::with_message(Errno::EINVAL, "too many AIO events"))?;
        if nr_events > u32::MAX as usize {
            return_errno_with_message!(Errno::EINVAL, "too many AIO events");
        }
        let mapping_size = ring_mapping_size(nr_events)?;
        let base = vmar
            .new_map(mapping_size, VmPerms::READ | VmPerms::WRITE)?
            .build()?;

        let ring = Self {
            base,
            mapping_size,
            nr_events,
        };
        if let Err(err) = ring.init(vmar) {
            let _ = vmar.remove_mapping(ring.mapping_range());
            return Err(err);
        }

        Ok(ring)
    }

    const fn base(&self) -> Vaddr {
        self.base
    }

    fn mapping_range(&self) -> Range<Vaddr> {
        self.base..self.base + self.mapping_size
    }

    fn init(&self, vmar: &Vmar) -> Result<()> {
        let header = RawAioRing {
            id: self.base as u32,
            nr: self.nr_events as u32,
            head: 0,
            tail: 0,
            magic: AIO_RING_MAGIC,
            compat_features: AIO_RING_COMPAT_FEATURES,
            incompat_features: AIO_RING_INCOMPAT_FEATURES,
            header_length: size_of::<RawAioRing>() as u32,
        };
        write_user_val(vmar, self.base, &header)
    }

    fn can_reserve(&self, vmar: &Vmar, active: usize) -> Result<bool> {
        let available_slots = self.free_slots(vmar)?;
        Ok(active < available_slots)
    }

    fn available_events(&self, vmar: &Vmar) -> Result<usize> {
        let header = self.read_header(vmar)?;
        Ok(self.occupied_len(header.head as usize, header.tail as usize))
    }

    fn free_slots(&self, vmar: &Vmar) -> Result<usize> {
        let header = self.read_header(vmar)?;
        let occupied = self.occupied_len(header.head as usize, header.tail as usize);
        Ok(self.nr_events - 1 - occupied)
    }

    fn push_event(&self, vmar: &Vmar, event: AioEvent) -> Result<()> {
        let header = self.read_header(vmar)?;
        let head = header.head as usize;
        let tail = header.tail as usize;
        let next_tail = self.next_index(tail);
        if next_tail == head {
            return_errno_with_message!(Errno::EAGAIN, "AIO completion ring is full");
        }

        write_user_val(vmar, self.event_addr(tail)?, &event)?;
        write_user_val(vmar, self.tail_addr(), &(next_tail as u32))
    }

    fn drain_events(&self, vmar: &Vmar, max_events: usize) -> Result<Vec<AioEvent>> {
        let header = self.read_header(vmar)?;
        let mut head = header.head as usize;
        let available = self.occupied_len(head, header.tail as usize);
        let count = max_events.min(available);
        if count == 0 {
            return Ok(Vec::new());
        }

        let mut events = Vec::new();
        events
            .try_reserve_exact(count)
            .map_err(|_| Error::new(Errno::ENOMEM))?;

        for _ in 0..count {
            events.push(read_user_val::<AioEvent>(vmar, self.event_addr(head)?)?);
            head = self.next_index(head);
        }

        write_user_val(vmar, self.head_addr(), &(head as u32))?;
        Ok(events)
    }

    fn read_header(&self, vmar: &Vmar) -> Result<RawAioRing> {
        let header = read_user_val::<RawAioRing>(vmar, self.base)?;
        if header.magic != AIO_RING_MAGIC
            || header.nr as usize != self.nr_events
            || header.header_length as usize != size_of::<RawAioRing>()
            || header.head as usize >= self.nr_events
            || header.tail as usize >= self.nr_events
        {
            return_errno_with_message!(Errno::EINVAL, "invalid AIO ring header");
        }

        Ok(header)
    }

    fn occupied_len(&self, head: usize, tail: usize) -> usize {
        if tail >= head {
            tail - head
        } else {
            self.nr_events - head + tail
        }
    }

    fn next_index(&self, index: usize) -> usize {
        let next = index + 1;
        if next == self.nr_events { 0 } else { next }
    }

    fn event_addr(&self, index: usize) -> Result<Vaddr> {
        let offset = size_of::<RawAioRing>()
            .checked_add(index.checked_mul(size_of::<AioEvent>()).ok_or_else(|| {
                Error::with_message(Errno::EINVAL, "AIO ring event offset overflow")
            })?)
            .ok_or_else(|| Error::with_message(Errno::EINVAL, "AIO ring event offset overflow"))?;
        self.base
            .checked_add(offset)
            .ok_or_else(|| Error::with_message(Errno::EINVAL, "AIO ring event address overflow"))
    }

    fn head_addr(&self) -> Vaddr {
        self.base + 2 * size_of::<u32>()
    }

    fn tail_addr(&self) -> Vaddr {
        self.base + 3 * size_of::<u32>()
    }
}

fn ring_mapping_size(nr_events: usize) -> Result<usize> {
    let events_size = nr_events
        .checked_mul(size_of::<AioEvent>())
        .ok_or_else(|| Error::with_message(Errno::EINVAL, "AIO ring size overflow"))?;
    let ring_size = size_of::<RawAioRing>()
        .checked_add(events_size)
        .ok_or_else(|| Error::with_message(Errno::EINVAL, "AIO ring size overflow"))?;
    align_up(ring_size, PAGE_SIZE)
}

fn align_up(value: usize, align: usize) -> Result<usize> {
    let remainder = value % align;
    if remainder == 0 {
        return Ok(value);
    }

    value
        .checked_add(align - remainder)
        .ok_or_else(|| Error::with_message(Errno::EINVAL, "aligned size overflow"))
}

fn read_user_val<T: Pod>(vmar: &Vmar, addr: Vaddr) -> Result<T> {
    let mut val = T::new_zeroed();
    let mut writer = VmWriter::from(val.as_mut_bytes()).to_fallible();
    read_alien_exact(vmar, addr, &mut writer)?;
    Ok(val)
}

fn write_user_val<T: Pod>(vmar: &Vmar, addr: Vaddr, val: &T) -> Result<()> {
    let mut reader = VmReader::from(val.as_bytes()).to_fallible();
    write_alien_exact(vmar, addr, &mut reader)
}

/// A native AIO completion event.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod)]
pub(crate) struct AioEvent {
    pub(crate) data: u64,
    pub(crate) obj: u64,
    pub(crate) res: i64,
    pub(crate) res2: i64,
}

/// A submitted native AIO request.
pub(crate) struct AioRequest {
    file: Option<Arc<dyn FileLike>>,
    vmar: Arc<Vmar>,
    data: u64,
    obj: u64,
    operation: AioOperation,
    notifier: Option<Arc<dyn AioNotifier>>,
}

impl AioRequest {
    /// Creates a submitted AIO request.
    pub(crate) fn new(
        file: Option<Arc<dyn FileLike>>,
        vmar: Arc<Vmar>,
        data: u64,
        obj: u64,
        operation: AioOperation,
        notifier: Option<Arc<dyn AioNotifier>>,
    ) -> Self {
        Self {
            file,
            vmar,
            data,
            obj,
            operation,
            notifier,
        }
    }

    fn finish(&self, context: &AioContext) {
        let result = self.operation.execute(self.file.as_ref(), &self.vmar);
        let event = AioEvent {
            data: self.data,
            obj: self.obj,
            res: result_to_event_res(result),
            res2: 0,
        };

        if context.complete(&self.vmar, event)
            && let Some(notifier) = self.notifier.as_ref()
        {
            notifier.notify();
        }
    }
}

/// A native AIO operation.
pub(crate) enum AioOperation {
    Read {
        buffers: Vec<AioIoVec>,
        total_len: usize,
        offset: usize,
    },
    Write {
        data: Vec<u8>,
        offset: usize,
    },
    Sync {
        data_only: bool,
    },
    Noop,
}

impl AioOperation {
    /// Creates a read operation.
    pub(crate) fn read(buffers: Vec<AioIoVec>, total_len: usize, offset: usize) -> Self {
        Self::Read {
            buffers,
            total_len,
            offset,
        }
    }

    /// Creates a write operation by copying user buffers during submission.
    pub(crate) fn write_from_user(
        vmar: &Vmar,
        buffers: &[AioIoVec],
        total_len: usize,
        offset: usize,
    ) -> Result<Self> {
        let data = read_user_buffers(vmar, buffers, total_len)?;
        Ok(Self::Write { data, offset })
    }

    /// Creates a sync operation.
    pub(crate) const fn sync(data_only: bool) -> Self {
        Self::Sync { data_only }
    }

    /// Creates a no-op operation.
    pub(crate) const fn noop() -> Self {
        Self::Noop
    }

    fn execute(&self, file: Option<&Arc<dyn FileLike>>, vmar: &Vmar) -> Result<usize> {
        match self {
            AioOperation::Read {
                buffers,
                total_len,
                offset,
            } => {
                let file = operation_file(file)?;
                let mut data = alloc_zeroed_vec(*total_len)?;
                let mut writer = VmWriter::from(data.as_mut_slice()).to_fallible();
                let read_len = file.read_at(*offset, &mut writer)?;
                if read_len > 0 {
                    write_user_buffers(vmar, buffers, &data[..read_len])?;
                    fs::vfs::notify::on_access(file);
                }
                Ok(read_len)
            }
            AioOperation::Write { data, offset } => {
                let file = operation_file(file)?;
                let mut reader = VmReader::from(data.as_slice()).to_fallible();
                let write_len = file.write_at(*offset, &mut reader)?;
                if write_len > 0 {
                    fs::vfs::notify::on_modify(file);
                }
                Ok(write_len)
            }
            AioOperation::Sync { data_only } => {
                let file = operation_file(file)?;
                let path = file.as_inode_handle_or_err()?.path();
                if *data_only {
                    path.sync_data()?;
                } else {
                    path.sync_all()?;
                }
                Ok(0)
            }
            AioOperation::Noop => Ok(0),
        }
    }
}

fn operation_file(file: Option<&Arc<dyn FileLike>>) -> Result<&Arc<dyn FileLike>> {
    file.ok_or_else(|| Error::with_message(Errno::EINVAL, "AIO operation requires a file"))
}

/// A user buffer descriptor captured for an AIO request.
#[derive(Clone, Copy)]
pub(crate) struct AioIoVec {
    pub(crate) base: Vaddr,
    pub(crate) len: usize,
}

impl AioIoVec {
    /// Creates an AIO I/O vector.
    pub(crate) const fn new(base: Vaddr, len: usize) -> Self {
        Self { base, len }
    }

    /// Returns whether this I/O vector is empty.
    pub(crate) const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Returns the total length of the I/O vectors.
    pub(crate) fn total_len(iovecs: &[Self]) -> Result<usize> {
        let mut total = 0usize;
        for iov in iovecs {
            total = total
                .checked_add(iov.len)
                .ok_or_else(|| Error::with_message(Errno::EINVAL, "I/O vector length overflow"))?;
        }
        Ok(total)
    }
}

fn read_user_buffers(vmar: &Vmar, buffers: &[AioIoVec], total_len: usize) -> Result<Vec<u8>> {
    let mut data = alloc_zeroed_vec(total_len)?;
    let mut copied = 0usize;
    for buffer in buffers {
        if buffer.len == 0 {
            continue;
        }
        let end = copied + buffer.len;
        let mut writer = VmWriter::from(&mut data[copied..end]).to_fallible();
        read_alien_exact(vmar, buffer.base, &mut writer)?;
        copied = end;
    }
    Ok(data)
}

fn write_user_buffers(vmar: &Vmar, buffers: &[AioIoVec], data: &[u8]) -> Result<()> {
    let mut copied = 0usize;
    for buffer in buffers {
        if copied == data.len() {
            return Ok(());
        }

        let len = buffer.len.min(data.len() - copied);
        let mut reader = VmReader::from(&data[copied..copied + len]).to_fallible();
        write_alien_exact(vmar, buffer.base, &mut reader)?;
        copied += len;
    }

    Ok(())
}

fn read_alien_exact(vmar: &Vmar, addr: Vaddr, writer: &mut VmWriter) -> Result<()> {
    let expected_len = writer.avail();
    match vmar.read_alien(addr, writer) {
        Ok(len) if len == expected_len => Ok(()),
        Ok(_) => Err(Error::with_message(
            Errno::EFAULT,
            "failed to read the full user buffer",
        )),
        Err((err, _)) => Err(err),
    }
}

fn write_alien_exact(vmar: &Vmar, addr: Vaddr, reader: &mut VmReader) -> Result<()> {
    let expected_len = reader.remain();
    match vmar.write_alien(addr, reader) {
        Ok(len) if len == expected_len => Ok(()),
        Ok(_) => Err(Error::with_message(
            Errno::EFAULT,
            "failed to write the full user buffer",
        )),
        Err((err, _)) => Err(err),
    }
}

fn alloc_zeroed_vec(len: usize) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    data.try_reserve_exact(len)
        .map_err(|_| Error::new(Errno::ENOMEM))?;
    data.resize(len, 0);
    Ok(data)
}

fn result_to_event_res(result: Result<usize>) -> i64 {
    match result {
        Ok(len) => len as i64,
        Err(err) => -(err.error() as i32 as i64),
    }
}
