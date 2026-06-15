// SPDX-License-Identifier: MPL-2.0

use core::time::Duration;

use ostd::mm::VmIo;

use super::{SyscallReturn, eventfd};
use crate::{
    fs::file::{
        FileLike,
        file_table::{RawFileDesc, get_file_fast},
    },
    prelude::*,
    process::{
        aio::{AioEvent, AioIoVec, AioNotifier, AioOperation, AioRequest},
        posix_thread::ContextPthreadAdminApi,
        signal::sig_mask::SigMask,
    },
    time::timespec_t,
    vm::vmar::Vmar,
};

const IOCB_CMD_PREAD: u16 = 0;
const IOCB_CMD_PWRITE: u16 = 1;
const IOCB_CMD_FSYNC: u16 = 2;
const IOCB_CMD_FDSYNC: u16 = 3;
const IOCB_CMD_NOOP: u16 = 6;
const IOCB_CMD_PREADV: u16 = 7;
const IOCB_CMD_PWRITEV: u16 = 8;

const IOCB_FLAG_RESFD: u32 = 1 << 0;
const MAX_IO_VECTOR_LENGTH: usize = 1024;
const MAX_TOTAL_IOV_BYTES: usize = isize::MAX as usize;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod)]
struct RawIocb {
    aio_data: u64,
    aio_key: u32,
    aio_rw_flags: i32,
    aio_lio_opcode: u16,
    aio_reqprio: i16,
    aio_fildes: u32,
    aio_buf: u64,
    aio_nbytes: u64,
    aio_offset: i64,
    aio_reserved2: u64,
    aio_flags: u32,
    aio_resfd: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod)]
struct RawIoEvent {
    data: u64,
    obj: u64,
    res: i64,
    res2: i64,
}

impl From<AioEvent> for RawIoEvent {
    fn from(event: AioEvent) -> Self {
        Self {
            data: event.data,
            obj: event.obj,
            res: event.res,
            res2: event.res2,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod)]
struct UserIoVec {
    base: Vaddr,
    len: isize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod)]
struct AioSigSet {
    sigmask: Vaddr,
    sigsetsize: usize,
}

pub fn sys_io_setup(nr_events: u32, ctx_id_addr: Vaddr, ctx: &Context) -> Result<SyscallReturn> {
    debug!(
        "io_setup: nr_events = {}, ctx_id_addr = 0x{:x}",
        nr_events, ctx_id_addr
    );

    if nr_events == 0 {
        return_errno_with_message!(Errno::EINVAL, "nr_events must be positive");
    }

    let user_space = ctx.user_space();
    let old_ctx_id: u64 = user_space.read_val(ctx_id_addr)?;
    if old_ctx_id != 0 {
        return_errno_with_message!(Errno::EINVAL, "AIO context pointer is not zero");
    }

    let vmar = user_space.vmar();
    let aio_table = vmar.process_vm().aio_table();
    let ctx_id = aio_table.setup_context(vmar, nr_events as usize)?;
    if let Err(err) = user_space.write_val(ctx_id_addr, &ctx_id) {
        if let Ok(aio_context) = aio_table.remove_context(ctx_id) {
            aio_context.destroy();
            aio_context.unmap_ring(vmar);
        }
        return Err(err.into());
    }

    Ok(SyscallReturn::Return(0))
}

pub fn sys_io_destroy(ctx_id: u64, ctx: &Context) -> Result<SyscallReturn> {
    debug!("io_destroy: ctx_id = 0x{:x}", ctx_id);

    let user_space = ctx.user_space();
    let aio_context = user_space
        .vmar()
        .process_vm()
        .aio_table()
        .remove_context(ctx_id)?;
    aio_context.destroy();
    aio_context.unmap_ring(user_space.vmar());

    Ok(SyscallReturn::Return(0))
}

pub fn sys_io_submit(
    ctx_id: u64,
    nr: isize,
    iocb_array_addr: Vaddr,
    ctx: &Context,
) -> Result<SyscallReturn> {
    debug!(
        "io_submit: ctx_id = 0x{:x}, nr = {}, iocb_array_addr = 0x{:x}",
        ctx_id, nr, iocb_array_addr
    );

    if nr < 0 {
        return_errno_with_message!(Errno::EINVAL, "nr must not be negative");
    }
    if nr == 0 {
        return Ok(SyscallReturn::Return(0));
    }

    let user_space = ctx.user_space();
    let vmar = user_space.vmar_arc();
    let aio_context = vmar.process_vm().aio_table().lookup_context(ctx_id)?;
    let mut submitted = 0isize;

    for idx in 0..(nr as usize) {
        let iocb_ptr_addr = match array_entry_addr(iocb_array_addr, idx, size_of::<Vaddr>()) {
            Ok(addr) => addr,
            Err(_) if submitted > 0 => return Ok(SyscallReturn::Return(submitted as _)),
            Err(err) => return Err(err.into()),
        };

        let iocb_addr = match user_space.read_val::<Vaddr>(iocb_ptr_addr) {
            Ok(addr) => addr,
            Err(_) if submitted > 0 => return Ok(SyscallReturn::Return(submitted as _)),
            Err(err) => return Err(err.into()),
        };

        let raw_iocb = match user_space.read_val::<RawIocb>(iocb_addr) {
            Ok(iocb) => iocb,
            Err(_) if submitted > 0 => return Ok(SyscallReturn::Return(submitted as _)),
            Err(err) => return Err(err.into()),
        };

        let request = match prepare_request(ctx, &vmar, iocb_addr, raw_iocb) {
            Ok(request) => request,
            Err(_) if submitted > 0 => return Ok(SyscallReturn::Return(submitted as _)),
            Err(err) => return Err(err),
        };

        if let Err(err) = aio_context.reserve_event(&vmar) {
            if submitted > 0 {
                return Ok(SyscallReturn::Return(submitted as _));
            }
            return Err(err);
        }

        aio_context.submit(request);
        submitted += 1;
    }

    Ok(SyscallReturn::Return(submitted as _))
}

pub fn sys_io_getevents(
    ctx_id: u64,
    min_nr: isize,
    nr: isize,
    events_addr: Vaddr,
    timeout_addr: Vaddr,
    ctx: &Context,
) -> Result<SyscallReturn> {
    debug!(
        "io_getevents: ctx_id = 0x{:x}, min_nr = {}, nr = {}, events_addr = 0x{:x}, timeout_addr = 0x{:x}",
        ctx_id, min_nr, nr, events_addr, timeout_addr
    );

    let timeout = read_optional_timeout(timeout_addr, ctx)?;
    let count = do_io_getevents(ctx_id, min_nr, nr, events_addr, timeout, ctx)?;
    Ok(SyscallReturn::Return(count as _))
}

pub fn sys_io_pgetevents(
    ctx_id: u64,
    min_nr: isize,
    nr: isize,
    events_addr: Vaddr,
    timeout_addr: Vaddr,
    sigset_addr: Vaddr,
    ctx: &Context,
) -> Result<SyscallReturn> {
    debug!(
        "io_pgetevents: ctx_id = 0x{:x}, min_nr = {}, nr = {}, events_addr = 0x{:x}, timeout_addr = 0x{:x}, sigset_addr = 0x{:x}",
        ctx_id, min_nr, nr, events_addr, timeout_addr, sigset_addr
    );

    if sigset_addr != 0 {
        let aio_sigset = ctx.user_space().read_val::<AioSigSet>(sigset_addr)?;
        if aio_sigset.sigmask != 0 {
            if aio_sigset.sigsetsize != size_of::<SigMask>() {
                return_errno_with_message!(Errno::EINVAL, "invalid sigmask size");
            }
            let sigmask = ctx.user_space().read_val::<SigMask>(aio_sigset.sigmask)?;
            ctx.save_and_set_sig_mask(sigmask);
        }
    }

    let timeout = read_optional_timeout(timeout_addr, ctx)?;
    let count = do_io_getevents(ctx_id, min_nr, nr, events_addr, timeout, ctx)?;
    Ok(SyscallReturn::Return(count as _))
}

pub fn sys_io_cancel(
    ctx_id: u64,
    _iocb_addr: Vaddr,
    _event_addr: Vaddr,
    ctx: &Context,
) -> Result<SyscallReturn> {
    debug!("io_cancel: ctx_id = 0x{:x}", ctx_id);

    let user_space = ctx.user_space();
    let _ = user_space
        .vmar()
        .process_vm()
        .aio_table()
        .lookup_context(ctx_id)?;
    return_errno_with_message!(
        Errno::EINVAL,
        "AIO cancellation is not supported for submitted requests"
    );
}

fn do_io_getevents(
    ctx_id: u64,
    min_nr: isize,
    nr: isize,
    events_addr: Vaddr,
    timeout: Option<Duration>,
    ctx: &Context,
) -> Result<usize> {
    if min_nr < 0 || nr < 0 || min_nr > nr {
        return_errno_with_message!(Errno::EINVAL, "invalid event count");
    }

    let nr = nr as usize;
    let min_nr = min_nr as usize;
    if nr == 0 {
        return Ok(0);
    }

    let user_space = ctx.user_space();
    let aio_context = user_space
        .vmar()
        .process_vm()
        .aio_table()
        .lookup_context(ctx_id)?;
    let events = aio_context.wait_events(user_space.vmar(), min_nr, nr, timeout.as_ref())?;

    for (idx, event) in events.iter().enumerate() {
        let write_addr = array_entry_addr(events_addr, idx, size_of::<RawIoEvent>())?;
        user_space.write_val(write_addr, &RawIoEvent::from(*event))?;
    }

    Ok(events.len())
}

fn read_optional_timeout(timeout_addr: Vaddr, ctx: &Context) -> Result<Option<Duration>> {
    if timeout_addr == 0 {
        return Ok(None);
    }

    let timeout = ctx.user_space().read_val::<timespec_t>(timeout_addr)?;
    Ok(Some(Duration::try_from(timeout)?))
}

fn prepare_request(
    ctx: &Context,
    vmar: &Arc<Vmar>,
    iocb_addr: Vaddr,
    raw_iocb: RawIocb,
) -> Result<AioRequest> {
    validate_iocb_flags(raw_iocb)?;

    let notifier: Option<Arc<dyn AioNotifier>> = if raw_iocb.aio_flags & IOCB_FLAG_RESFD != 0 {
        let file = get_file(ctx, raw_iocb.aio_resfd as RawFileDesc)?;
        if !eventfd::is_event_file(&file) {
            return_errno_with_message!(Errno::EINVAL, "aio_resfd is not an eventfd");
        }
        Some(Arc::new(EventfdNotifier { file }))
    } else {
        None
    };

    let file = match raw_iocb.aio_lio_opcode {
        IOCB_CMD_NOOP => None,
        _ => Some(get_file(ctx, raw_iocb.aio_fildes as RawFileDesc)?),
    };

    let operation = build_operation(vmar, raw_iocb)?;
    Ok(AioRequest::new(
        file,
        vmar.clone(),
        raw_iocb.aio_data,
        iocb_addr as u64,
        operation,
        notifier,
    ))
}

fn validate_iocb_flags(raw_iocb: RawIocb) -> Result<()> {
    if raw_iocb.aio_rw_flags != 0 {
        return_errno_with_message!(Errno::EOPNOTSUPP, "aio_rw_flags are not supported");
    }

    if raw_iocb.aio_flags & !IOCB_FLAG_RESFD != 0 {
        return_errno_with_message!(Errno::EINVAL, "unknown AIO iocb flags");
    }

    Ok(())
}

fn build_operation(vmar: &Vmar, raw_iocb: RawIocb) -> Result<AioOperation> {
    match raw_iocb.aio_lio_opcode {
        IOCB_CMD_PREAD => {
            let len = user_len_from_u64(raw_iocb.aio_nbytes)?;
            validate_offset(raw_iocb.aio_offset, len)?;
            Ok(AioOperation::read(
                vec![AioIoVec::new(raw_iocb.aio_buf as Vaddr, len)],
                len,
                raw_iocb.aio_offset as usize,
            ))
        }
        IOCB_CMD_PWRITE => {
            let len = user_len_from_u64(raw_iocb.aio_nbytes)?;
            validate_offset(raw_iocb.aio_offset, len)?;
            let buffers = [AioIoVec::new(raw_iocb.aio_buf as Vaddr, len)];
            AioOperation::write_from_user(vmar, &buffers, len, raw_iocb.aio_offset as usize)
        }
        IOCB_CMD_FSYNC => Ok(AioOperation::sync(false)),
        IOCB_CMD_FDSYNC => Ok(AioOperation::sync(true)),
        IOCB_CMD_NOOP => Ok(AioOperation::noop()),
        IOCB_CMD_PREADV => {
            let buffers = read_iovecs(vmar, raw_iocb.aio_buf as Vaddr, raw_iocb.aio_nbytes)?;
            let total_len = AioIoVec::total_len(&buffers)?;
            validate_offset(raw_iocb.aio_offset, total_len)?;
            Ok(AioOperation::read(
                buffers,
                total_len,
                raw_iocb.aio_offset as usize,
            ))
        }
        IOCB_CMD_PWRITEV => {
            let buffers = read_iovecs(vmar, raw_iocb.aio_buf as Vaddr, raw_iocb.aio_nbytes)?;
            let total_len = AioIoVec::total_len(&buffers)?;
            validate_offset(raw_iocb.aio_offset, total_len)?;
            AioOperation::write_from_user(vmar, &buffers, total_len, raw_iocb.aio_offset as usize)
        }
        _ => return_errno_with_message!(Errno::EINVAL, "unsupported AIO opcode"),
    }
}

fn get_file(ctx: &Context, raw_fd: RawFileDesc) -> Result<Arc<dyn FileLike>> {
    let mut file_table = ctx.thread_local.borrow_file_table_mut();
    Ok(get_file_fast!(&mut file_table, raw_fd.try_into()?).into_owned())
}

fn read_iovecs(vmar: &Vmar, iov_addr: Vaddr, count: u64) -> Result<Vec<AioIoVec>> {
    let count = usize::try_from(count)
        .map_err(|_| Error::with_message(Errno::EINVAL, "too many I/O vectors"))?;
    if count > MAX_IO_VECTOR_LENGTH {
        return_errno_with_message!(Errno::EINVAL, "too many I/O vectors");
    }

    let mut iovecs = Vec::new();
    iovecs
        .try_reserve_exact(count)
        .map_err(|_| Error::new(Errno::ENOMEM))?;

    let mut remaining = MAX_TOTAL_IOV_BYTES;
    for idx in 0..count {
        let addr = array_entry_addr(iov_addr, idx, size_of::<UserIoVec>())?;
        let user_iov = read_user_val::<UserIoVec>(vmar, addr)?;
        if user_iov.len < 0 {
            return_errno_with_message!(Errno::EINVAL, "negative I/O vector length");
        }

        let len = (user_iov.len as usize).min(remaining);
        remaining -= len;
        let iov = AioIoVec::new(user_iov.base, len);
        if !iov.is_empty() {
            iovecs.push(iov);
        }
    }

    Ok(iovecs)
}

fn read_user_val<T: Pod>(vmar: &Vmar, addr: Vaddr) -> Result<T> {
    let mut val = T::new_zeroed();
    let mut writer = VmWriter::from(val.as_mut_bytes()).to_fallible();
    read_alien_exact(vmar, addr, &mut writer)?;
    Ok(val)
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

fn array_entry_addr(base: Vaddr, index: usize, entry_size: usize) -> Result<Vaddr> {
    let offset = index
        .checked_mul(entry_size)
        .ok_or_else(|| Error::with_message(Errno::EINVAL, "user array offset overflow"))?;
    base.checked_add(offset)
        .ok_or_else(|| Error::with_message(Errno::EINVAL, "user array address overflow"))
}

fn validate_offset(offset: i64, len: usize) -> Result<()> {
    if offset < 0 {
        return_errno_with_message!(Errno::EINVAL, "offset cannot be negative");
    }

    let len = i64::try_from(len)
        .map_err(|_| Error::with_message(Errno::EINVAL, "I/O length is too large"))?;
    offset
        .checked_add(len)
        .ok_or_else(|| Error::with_message(Errno::EINVAL, "offset plus length overflow"))?;
    Ok(())
}

fn user_len_from_u64(len: u64) -> Result<usize> {
    let len = usize::try_from(len)
        .map_err(|_| Error::with_message(Errno::EINVAL, "I/O length is too large"))?;
    if len > MAX_TOTAL_IOV_BYTES {
        return_errno_with_message!(Errno::EINVAL, "I/O length is too large");
    }
    Ok(len)
}

struct EventfdNotifier {
    file: Arc<dyn FileLike>,
}

impl AioNotifier for EventfdNotifier {
    fn notify(&self) {
        let _ = eventfd::signal_file(&self.file);
    }
}
