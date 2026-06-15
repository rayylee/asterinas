// SPDX-License-Identifier: MPL-2.0

//! Linux AIO syscalls: io_setup / io_destroy / io_submit / io_getevents / io_cancel

use align_ext::AlignExt;
use core::{mem::size_of, sync::atomic::Ordering, time::Duration};

use ostd::mm::{VmIo, VmSpace};

use super::SyscallReturn;
use crate::{
    prelude::*,
    process::aio::{AioContext, Iocb, IoEvent, IOCB_CMD_FDSYNC, IOCB_CMD_FSYNC, IOCB_CMD_PREAD, IOCB_CMD_PWRITE},
    thread::work_queue::{WorkPriority, submit_work_func},
    time::timespec_t,
    vm::vmar::VMAR_CAP_ADDR,
};

// ---------------------------------------------------------------------------
// io_setup (206)
// ---------------------------------------------------------------------------

pub fn sys_io_setup(nr_events: u64, ctx_idp: u64, ctx: &Context) -> Result<SyscallReturn> {
    let nr_events = nr_events as u32;
    if nr_events == 0 {
        return_errno_with_message!(Errno::EINVAL, "nr_events must be positive");
    }
    // Linux returns EAGAIN when nr_events exceeds the system-wide limit.
    if nr_events > 0x10000 {
        return_errno_with_message!(Errno::EAGAIN, "nr_events exceeds system limit");
    }
    if ctx_idp == 0 {
        return_errno_with_message!(Errno::EFAULT, "ctx_idp is NULL");
    }

    let user_space = ctx.user_space();
    let vmar = user_space.vmar();
    let (ring_va, aio_ctx) = AioContext::alloc(nr_events, vmar)?;

    ctx.process.aio_table().lock().insert(ring_va, aio_ctx);
    user_space.write_val(ctx_idp as usize, &ring_va)?;

    Ok(SyscallReturn::Return(0))
}

// ---------------------------------------------------------------------------
// io_destroy (207)
// ---------------------------------------------------------------------------

pub fn sys_io_destroy(ctx_id: u64, ctx: &Context) -> Result<SyscallReturn> {
    let aio_ctx = ctx
        .process
        .aio_table()
        .lock()
        .remove(&ctx_id)
        .ok_or_else(|| Error::with_message(Errno::EINVAL, "invalid aio context"))?;

    // Wait for all in-flight operations to complete.
    aio_ctx.wait_queue.wait_until(|| {
        if aio_ctx.pending.load(Ordering::Acquire) == 0 {
            Some(())
        } else {
            None
        }
    });

    // Unmap the ring from user address space.
    let ring_size = aio_ctx.ring_size;
    let ring_va = aio_ctx.ring_va as usize;
    if ring_va != 0 && ring_va < VMAR_CAP_ADDR {
        let addr_range = ring_va..(ring_va + ring_size).align_up(PAGE_SIZE);
        let user_space = ctx.user_space();
        let vmar = user_space.vmar();
        // Best-effort unmap: ignore error if already unmapped.
        let _ = vmar.remove_mapping(addr_range);
    }

    Ok(SyscallReturn::Return(0))
}

// ---------------------------------------------------------------------------
// io_getevents (208)
// ---------------------------------------------------------------------------

pub fn sys_io_getevents(
    ctx_id: u64,
    min_nr: i64,
    nr: i64,
    events_ptr: u64,
    timeout_ptr: u64,
    ctx: &Context,
) -> Result<SyscallReturn> {
    if min_nr < 0 || nr < 0 {
        return_errno_with_message!(Errno::EINVAL, "min_nr or nr is negative");
    }
    if min_nr > nr {
        return_errno_with_message!(Errno::EINVAL, "min_nr > nr");
    }

    let aio_ctx = ctx
        .process
        .aio_table()
        .lock()
        .get(&ctx_id)
        .cloned()
        .ok_or_else(|| Error::with_message(Errno::EINVAL, "invalid aio context"))?;

    let timeout = if timeout_ptr != 0 {
        let ts: timespec_t = ctx.user_space().read_val(timeout_ptr as usize)?;
        Some(Duration::try_from(ts)?)
    } else {
        None
    };

    let events = aio_ctx.wait_for_events(min_nr as u32, nr as u32, timeout)?;

    let user_space = ctx.user_space();
    let event_size = size_of::<IoEvent>();
    for (i, ev) in events.iter().enumerate() {
        user_space.write_val(events_ptr as usize + i * event_size, ev)?;
    }

    Ok(SyscallReturn::Return(events.len() as _))
}

// ---------------------------------------------------------------------------
// io_submit (209)
// ---------------------------------------------------------------------------

pub fn sys_io_submit(ctx_id: u64, nr: i64, iocbpp: u64, ctx: &Context) -> Result<SyscallReturn> {
    if nr < 0 {
        return_errno_with_message!(Errno::EINVAL, "nr must be non-negative");
    }
    if nr == 0 {
        return Ok(SyscallReturn::Return(0));
    }

    let aio_ctx = ctx
        .process
        .aio_table()
        .lock()
        .get(&ctx_id)
        .cloned()
        .ok_or_else(|| Error::with_message(Errno::EINVAL, "invalid aio context"))?;

    let user_space = ctx.user_space();
    let nr = nr as usize;

    // Capture the VmSpace so worker threads can access user memory.
    let vm_space = user_space.vmar().vm_space().clone();

    // Pre-fetch all iocbs and validate synchronously before dispatching.
    let mut iocbs: Vec<(u64, Iocb)> = Vec::with_capacity(nr);
    for i in 0..nr {
        let iocb_ptr: u64 = user_space.read_val(iocbpp as usize + i * 8)?;
        if iocb_ptr == 0 {
            // Linux returns EFAULT for a NULL iocb pointer.
            return_errno_with_message!(Errno::EFAULT, "iocb pointer is NULL");
        }
        let iocb: Iocb = user_space.read_val(iocb_ptr as usize)?;
        // Validate opcode synchronously so io_submit returns EINVAL immediately.
        match iocb.opcode {
            IOCB_CMD_PREAD | IOCB_CMD_PWRITE | IOCB_CMD_FSYNC | IOCB_CMD_FDSYNC => {}
            _ => return_errno_with_message!(Errno::EINVAL, "unsupported iocb opcode"),
        }
        iocbs.push((iocb_ptr, iocb));
    }

    // Acquire file handles upfront.
    let mut work_items: Vec<(Arc<dyn crate::fs::file::FileLike>, u64, Iocb)> =
        Vec::with_capacity(nr);
    {
        let mut file_table_ref = ctx.thread_local.borrow_file_table_mut();
        let file_table = file_table_ref.unwrap().read();
        for (iocb_ptr, iocb) in &iocbs {
            let raw_fd = iocb.fildes as crate::fs::file::file_table::RawFileDesc;
            let fd: crate::fs::file::file_table::FileDesc = raw_fd.try_into()?;
            let file = file_table.get_file(fd)?.clone();
            work_items.push((file, *iocb_ptr, *iocb));
        }
    }

    for (file, iocb_ptr, iocb) in work_items {
        aio_ctx.pending.fetch_add(1, Ordering::Release);
        let aio_ctx_clone = aio_ctx.clone();
        let vm_space_clone = vm_space.clone();
        dispatch_iocb(file, iocb_ptr, iocb, aio_ctx_clone, vm_space_clone);
    }

    Ok(SyscallReturn::Return(nr as _))
}

fn dispatch_iocb(
    file: Arc<dyn crate::fs::file::FileLike>,
    iocb_ptr: u64,
    iocb: Iocb,
    aio_ctx: Arc<AioContext>,
    vm_space: Arc<VmSpace>,
) {
    submit_work_func(
        move || {
            let result = execute_iocb(&file, &iocb, &vm_space);
            let res = match result {
                Ok(n) => n as i64,
                Err(e) => -(e.error() as i64),
            };
            let event = IoEvent {
                data: iocb.data,
                obj: iocb_ptr,
                res,
                res2: 0,
            };
            aio_ctx.pending.fetch_sub(1, Ordering::Release);
            aio_ctx.push_event_to_ring(event);
        },
        WorkPriority::High,
    );
}

fn execute_iocb(
    file: &Arc<dyn crate::fs::file::FileLike>,
    iocb: &Iocb,
    vm_space: &Arc<VmSpace>,
) -> Result<usize> {
    match iocb.opcode {
        IOCB_CMD_PREAD => {
            let len = iocb.nbytes as usize;
            let user_buf_ptr = iocb.buf as usize;
            let base_offset = iocb.offset as usize;

            let mut buf = alloc::vec![0u8; len];
            // Loop to handle short reads.
            let mut total_read = 0usize;
            while total_read < len {
                let mut writer = VmWriter::from(&mut buf[total_read..]).to_fallible();
                let n = file.read_at(base_offset + total_read, &mut writer)?;
                if n == 0 {
                    break; // EOF
                }
                total_read += n;
            }
            // Copy from kernel buffer to user space via VmSpace.
            if total_read > 0 {
                let mut user_writer = vm_space
                    .writer(user_buf_ptr, total_read)
                    .map_err(|_| Error::with_message(Errno::EFAULT, "bad user buffer"))?;
                let mut reader = VmReader::from(&buf[..total_read]).to_fallible();
                user_writer
                    .write_fallible(&mut reader)
                    .map_err(|(err, _)| err)?;
            }
            Ok(total_read)
        }
        IOCB_CMD_PWRITE => {
            let len = iocb.nbytes as usize;
            let user_buf_ptr = iocb.buf as usize;
            let base_offset = iocb.offset as usize;

            // Copy from user space to a kernel buffer.
            let mut buf = alloc::vec![0u8; len];
            {
                let mut user_reader = vm_space
                    .reader(user_buf_ptr, len)
                    .map_err(|_| Error::with_message(Errno::EFAULT, "bad user buffer"))?;
                let mut writer = VmWriter::from(buf.as_mut_slice()).to_fallible();
                writer
                    .write_fallible(&mut user_reader)
                    .map_err(|(err, _)| err)?;
            }
            // Loop to handle short writes.
            let mut total_written = 0usize;
            while total_written < len {
                let mut reader = VmReader::from(&buf[total_written..]).to_fallible();
                let n = file.write_at(base_offset + total_written, &mut reader)?;
                if n == 0 {
                    break; // Cannot make progress
                }
                total_written += n;
            }
            Ok(total_written)
        }
        IOCB_CMD_FSYNC | IOCB_CMD_FDSYNC => {
            // AIO fsync/fdsync: best-effort, return success.
            Ok(0)
        }
        _ => {
            return_errno_with_message!(Errno::EINVAL, "unsupported iocb opcode");
        }
    }
}

// ---------------------------------------------------------------------------
// io_cancel (210)
// ---------------------------------------------------------------------------

pub fn sys_io_cancel(
    ctx_id: u64,
    _iocb_ptr: u64,
    _result_ptr: u64,
    ctx: &Context,
) -> Result<SyscallReturn> {
    let _aio_ctx = ctx
        .process
        .aio_table()
        .lock()
        .get(&ctx_id)
        .cloned()
        .ok_or_else(|| Error::with_message(Errno::EINVAL, "invalid aio context"))?;

    // In Asterinas, worker-dispatched iocbs cannot be cancelled.
    // Linux returns EINVAL when the iocb is not found in the pending queue.
    return_errno_with_message!(Errno::EINVAL, "io_cancel: iocb not found in pending queue");
}
