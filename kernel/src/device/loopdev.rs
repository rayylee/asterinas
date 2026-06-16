// SPDX-License-Identifier: MPL-2.0

use core::fmt;

use aster_block::{
    BlockDevice, BlockDeviceMeta, SECTOR_SIZE,
    bio::{BioEnqueueError, BioStatus, BioType, SubmittedBio},
};
use device_id::{DeviceId, MajorId, MinorId};
use ostd::{mm::io::util::HasVmReaderWriter, task::Task};
use spin::Once;

use crate::{
    device::{Device, DeviceType, DevtmpfsInodeMeta, registry::char},
    events::IoEvents,
    fs::{
        file::{
            FileLike, PerOpenFileOps, StatusFlags,
            file_table::{FileDesc, RawFileDesc, WithFileTable},
        },
        vfs::inode::FileOps,
    },
    prelude::*,
    process::signal::{PollHandle, Pollable},
    util::ioctl::{RawIoctl, dispatch_ioctl},
};

// Reference: <https://elixir.bootlin.com/linux/v7.0/source/include/uapi/linux/major.h#L22>
const LOOP_MAJOR: u16 = 7;
const LOOP_CONTROL_MAJOR: u16 = 10;
const LOOP_CONTROL_MINOR: u32 = 237;
const NR_LOOP_DEVICES: usize = 8;

// Reference: <https://elixir.bootlin.com/linux/v7.0/source/include/uapi/linux/loop.h#L9>
const LOOP_NAME_SIZE: usize = 64;
const LOOP_KEY_SIZE: usize = 32;
const LO_FLAGS_READ_ONLY: u32 = 1;

static LOOP_MAJOR_OWNER: Once<aster_block::MajorIdOwner> = Once::new();
static LOOP_DEVICES: Once<Vec<Arc<LoopDevice>>> = Once::new();

pub(super) fn init_in_first_process() {
    LOOP_DEVICES.call_once(|| {
        LOOP_MAJOR_OWNER.call_once(|| {
            aster_block::acquire_major(MajorId::new(LOOP_MAJOR))
                .expect("failed to acquire loop block-device major")
        });

        let major = LOOP_MAJOR_OWNER.get().unwrap().get();
        let mut devices = Vec::with_capacity(NR_LOOP_DEVICES);

        // Create devices (loop0 to loop7)
        for index in 0..NR_LOOP_DEVICES {
            let device = Arc::new(LoopDevice::new(index, major));
            if let Err(err) = aster_block::register(device.clone()) {
                warn!(
                    "failed to register loop device {}: {:?}",
                    device.name(),
                    err
                );
                continue;
            }
            devices.push(device);
        }

        if let Err(err) = char::register(Arc::new(LoopControlDevice)) {
            warn!("failed to register loop-control device: {:?}", err);
        }
        devices
    });
}

pub(super) struct LoopDevice {
    id: DeviceId,
    index: usize,
    name: String,
    inner: Mutex<LoopDeviceInner>,
}

impl LoopDevice {
    fn new(index: usize, major: MajorId) -> Self {
        Self {
            id: DeviceId::new(major, MinorId::new(index as u32)),
            index,
            name: {
                let mut name = String::from("loop");
                name.push_str(index.to_string().as_str());
                name
            },
            inner: Mutex::new(LoopDeviceInner::new()),
        }
    }

    pub(super) fn ioctl(&self, raw_ioctl: RawIoctl) -> Option<Result<i32>> {
        use ioctl_defs::*;

        dispatch_ioctl!(match raw_ioctl {
            cmd @ LoopSetFd => {
                Some(self.set_fd(cmd.get()))
            }
            LoopClrFd => {
                Some(self.clear_fd())
            }
            cmd @ LoopSetStatus64 => {
                Some(cmd.read().and_then(|info| self.set_status(info)))
            }
            cmd @ LoopGetStatus64 => {
                Some(self.get_status(cmd))
            }
            LoopSetCapacity => {
                Some(self.set_capacity())
            }
            cmd @ LoopConfigure => {
                Some(cmd.read().and_then(|config| self.configure(config)))
            }
            _ => None,
        })
    }

    fn binding(&self) -> Option<LoopBinding> {
        self.inner.lock().binding.clone()
    }

    fn is_bound(&self) -> bool {
        self.inner.lock().binding.is_some()
    }

    fn set_fd(&self, raw_fd: RawFileDesc) -> Result<i32> {
        let backing_file = get_file_from_current(raw_fd)?;
        let binding = LoopBinding::new(backing_file)?;

        let mut inner = self.inner.lock();
        if inner.binding.is_some() {
            return_errno_with_message!(Errno::EBUSY, "the loop device is already bound");
        }

        inner.binding = Some(binding);
        Ok(0)
    }

    fn clear_fd(&self) -> Result<i32> {
        let mut inner = self.inner.lock();
        if inner.binding.take().is_none() {
            return_errno_with_message!(Errno::ENXIO, "the loop device is not bound");
        }
        Ok(0)
    }

    fn set_status(&self, info: LoopInfo64) -> Result<i32> {
        let mut inner = self.inner.lock();
        let Some(binding) = inner.binding.as_mut() else {
            return_errno_with_message!(Errno::ENXIO, "the loop device is not bound");
        };

        binding.set_status(info)?;
        Ok(0)
    }

    fn get_status(&self, cmd: ioctl_defs::LoopGetStatus64) -> Result<i32> {
        let Some(binding) = self.binding() else {
            return_errno_with_message!(Errno::ENXIO, "the loop device is not bound");
        };

        let backing_metadata = binding.file.path().metadata();
        let mut info = LoopInfo64::new_zeroed();
        info.lo_device = backing_metadata.container_dev_id.as_encoded_u64();
        info.lo_inode = backing_metadata.ino;
        info.lo_rdevice = backing_metadata
            .self_dev_id
            .map_or(0, |device_id| device_id.as_encoded_u64());
        info.lo_offset = binding.offset as u64;
        info.lo_sizelimit = binding.size_limit.unwrap_or(0) as u64;
        info.lo_number = self.index as u32;
        info.lo_flags = binding.flags;

        // Copy filename to info (C-string style, null-terminated)
        info.lo_file_name.fill(0);
        let name_bytes = binding.name.as_bytes();
        let len = name_bytes.len().min(info.lo_file_name.len().saturating_sub(1));
        info.lo_file_name[..len].copy_from_slice(&name_bytes[..len]);

        cmd.write(&info)?;
        Ok(0)
    }

    fn set_capacity(&self) -> Result<i32> {
        if self.binding().is_none() {
            return_errno_with_message!(Errno::ENXIO, "the loop device is not bound");
        }
        Ok(0)
    }

    fn configure(&self, config: LoopConfig) -> Result<i32> {
        let raw_fd = i32::try_from(config.fd)
            .map_err(|_| Error::with_message(Errno::EBADF, "the backing FD is invalid"))?;
        let backing_file = get_file_from_current(raw_fd)?;
        let mut binding = LoopBinding::new(backing_file)?;
        binding.set_status(config.info)?;

        let mut inner = self.inner.lock();
        if inner.binding.is_some() {
            return_errno_with_message!(Errno::EBUSY, "the loop device is already bound");
        }

        inner.binding = Some(binding);
        Ok(0)
    }
}

struct LoopControlDevice;

impl Device for LoopControlDevice {
    fn type_(&self) -> DeviceType {
        DeviceType::Char
    }

    fn id(&self) -> DeviceId {
        DeviceId::new(
            MajorId::new(LOOP_CONTROL_MAJOR),
            MinorId::new(LOOP_CONTROL_MINOR),
        )
    }

    fn devtmpfs_meta(&self) -> Option<DevtmpfsInodeMeta<'_>> {
        Some(DevtmpfsInodeMeta::new("loop-control"))
    }

    fn open(&self) -> Result<Box<dyn PerOpenFileOps>> {
        Ok(Box::new(LoopControlFile))
    }
}

struct LoopControlFile;

impl FileOps for LoopControlFile {
    fn read_at(
        &self,
        _offset: usize,
        _writer: &mut VmWriter,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        return_errno_with_message!(Errno::EINVAL, "loop-control is not readable");
    }

    fn write_at(
        &self,
        _offset: usize,
        _reader: &mut VmReader,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        return_errno_with_message!(Errno::EINVAL, "loop-control is not writable");
    }
}

impl Pollable for LoopControlFile {
    fn poll(&self, mask: IoEvents, _: Option<&mut PollHandle>) -> IoEvents {
        let events = IoEvents::IN | IoEvents::OUT;
        events & mask
    }
}

impl PerOpenFileOps for LoopControlFile {
    fn check_seekable(&self) -> Result<()> {
        return_errno_with_message!(Errno::ESPIPE, "loop-control is not seekable");
    }

    fn is_offset_aware(&self) -> bool {
        false
    }

    fn ioctl(&self, raw_ioctl: RawIoctl) -> Result<i32> {
        use ioctl_defs::*;

        dispatch_ioctl!(match raw_ioctl {
            LoopCtlGetFree => {
                get_free_loop_device()
            }
            _ => return_errno_with_message!(
                Errno::ENOTTY,
                "the ioctl command is not supported by loop-control"
            ),
        })
    }
}

impl BlockDevice for LoopDevice {
    fn enqueue(&self, bio: SubmittedBio) -> core::result::Result<(), BioEnqueueError> {
        let status = match self.binding() {
            Some(binding) => process_bio(&binding, bio.type_(), &bio),
            None => BioStatus::IoError,
        };
        bio.complete(status);
        Ok(())
    }

    fn metadata(&self) -> BlockDeviceMeta {
        BlockDeviceMeta {
            max_nr_segments_per_bio: usize::MAX,
            nr_sectors: self
                .binding()
                .map(|binding| binding.capacity_bytes() / SECTOR_SIZE)
                .unwrap_or(0),
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn id(&self) -> DeviceId {
        self.id
    }
}

impl Debug for LoopDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoopDevice")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("bound", &self.inner.lock().binding.is_some())
            .finish()
    }
}

#[derive(Clone)]
struct LoopBinding {
    file: Arc<dyn FileLike>,
    offset: usize,
    size_limit: Option<usize>,
    flags: u32,
    name: String,
    is_writable: bool,
}

impl LoopBinding {
    fn new(file: Arc<dyn FileLike>) -> Result<Self> {
        let access_mode = file.access_mode();
        if !access_mode.is_readable() {
            return_errno_with_message!(Errno::EBADF, "the backing file is not readable");
        }
        let status_flags = file.status_flags();
        if status_flags.contains(StatusFlags::O_PATH) {
            return_errno_with_message!(Errno::EBADF, "the backing file is opened as a path");
        }
        if status_flags.contains(StatusFlags::O_APPEND) {
            return_errno_with_message!(
                Errno::EINVAL,
                "append-only backing files are not supported"
            );
        }
        if status_flags.contains(StatusFlags::O_DIRECT) {
            return_errno_with_message!(Errno::EINVAL, "direct-I/O backing files are not supported");
        }
        if !file.path().type_().is_regular_file() {
            return_errno_with_message!(Errno::EINVAL, "only regular backing files are supported");
        }

        Ok(Self {
            offset: 0,
            size_limit: None,
            flags: if access_mode.is_writable() {
                0
            } else {
                LO_FLAGS_READ_ONLY
            },
            name: file.path().name(),
            is_writable: access_mode.is_writable(),
            file,
        })
    }

    fn set_status(&mut self, info: LoopInfo64) -> Result<()> {
        let offset = usize::try_from(info.lo_offset)
            .map_err(|_| Error::with_message(Errno::EOVERFLOW, "loop offset is too large"))?;
        let size_limit = if info.lo_sizelimit == 0 {
            None
        } else {
            Some(usize::try_from(info.lo_sizelimit).map_err(|_| {
                Error::with_message(Errno::EOVERFLOW, "loop size limit is too large")
            })?)
        };

        if offset > self.file.path().size() {
            return_errno_with_message!(Errno::EINVAL, "loop offset is beyond the backing file");
        }

        self.offset = offset;
        self.size_limit = size_limit;

        // Ensure that the read-only flag is set correctly
        self.flags = if self.is_writable {
            info.lo_flags
        } else {
            info.lo_flags | LO_FLAGS_READ_ONLY
        };

        // Extract the name (C-string style) from the user-provided `lo_file_name`
        if let Some(name) = {
            let bytes = &info.lo_file_name;
            let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            (len > 0).then(|| String::from_utf8_lossy(&bytes[..len]).into_owned())
        } {
            self.name = name;
        }

        Ok(())
    }

    fn capacity_bytes(&self) -> usize {
        let backing_size = self.file.path().size();
        let available = backing_size.saturating_sub(self.offset);
        self.size_limit
            .map(|size_limit| size_limit.min(available))
            .unwrap_or(available)
    }

    fn is_read_only(&self) -> bool {
        self.flags & LO_FLAGS_READ_ONLY != 0
    }
}

struct LoopDeviceInner {
    binding: Option<LoopBinding>,
}

impl LoopDeviceInner {
    fn new() -> Self {
        Self { binding: None }
    }
}

fn process_bio(binding: &LoopBinding, bio_type: BioType, bio: &SubmittedBio) -> BioStatus {
    match bio_type {
        BioType::Read => read_bio(binding, bio),
        BioType::Write => write_bio(binding, bio),
        BioType::Flush => flush_bio(binding),
    }
}

fn read_bio(binding: &LoopBinding, bio: &SubmittedBio) -> BioStatus {
    let Some(mut file_offset) = bio_file_offset(binding, bio) else {
        return BioStatus::IoError;
    };

    for segment in bio.segments() {
        let writer = match segment.inner_dma_slice().writer() {
            Ok(writer) => writer,
            Err(_) => return BioStatus::IoError,
        };
        let mut writer = writer.to_fallible();
        let segment_len = segment.nbytes();
        let read_len = match binding.file.read_at(file_offset, &mut writer) {
            Ok(read_len) => read_len,
            Err(_) => return BioStatus::IoError,
        };

        if read_len > segment_len {
            return BioStatus::IoError;
        }
        if read_len < segment_len && writer.fill_zeros(segment_len - read_len).is_err() {
            return BioStatus::IoError;
        }
        file_offset = match file_offset.checked_add(segment_len) {
            Some(file_offset) => file_offset,
            None => return BioStatus::IoError,
        };
    }

    BioStatus::Complete
}

fn write_bio(binding: &LoopBinding, bio: &SubmittedBio) -> BioStatus {
    if binding.is_read_only() {
        return BioStatus::IoError;
    }

    let Some(mut file_offset) = bio_file_offset(binding, bio) else {
        return BioStatus::IoError;
    };

    for segment in bio.segments() {
        let reader = match segment.inner_dma_slice().reader() {
            Ok(reader) => reader,
            Err(_) => return BioStatus::IoError,
        };
        let mut reader = reader.to_fallible();
        let segment_len = segment.nbytes();
        let write_len = match binding.file.write_at(file_offset, &mut reader) {
            Ok(write_len) => write_len,
            Err(_) => return BioStatus::IoError,
        };

        if write_len != segment_len {
            return BioStatus::IoError;
        }
        file_offset = match file_offset.checked_add(segment_len) {
            Some(file_offset) => file_offset,
            None => return BioStatus::IoError,
        };
    }

    BioStatus::Complete
}

fn flush_bio(binding: &LoopBinding) -> BioStatus {
    match binding.file.path().sync_all() {
        Ok(()) => BioStatus::Complete,
        Err(_) => BioStatus::IoError,
    }
}

fn bio_file_offset(binding: &LoopBinding, bio: &SubmittedBio) -> Option<usize> {
    let start_sector = bio
        .sid_range()
        .start
        .to_raw()
        .checked_add(bio.sid_offset())?;
    let device_offset = usize::try_from(start_sector)
        .ok()?
        .checked_mul(SECTOR_SIZE)?;
    let bio_len = bio
        .segments()
        .iter()
        .try_fold(0usize, |len, segment| len.checked_add(segment.nbytes()))?;
    let bio_end = device_offset.checked_add(bio_len)?;
    if bio_end > binding.capacity_bytes() {
        return None;
    }

    binding.offset.checked_add(device_offset)
}

fn get_file_from_current(raw_fd: RawFileDesc) -> Result<Arc<dyn FileLike>> {
    let fd = FileDesc::try_from(raw_fd)?;
    let task = Task::current().ok_or_else(|| {
        Error::with_message(
            Errno::EBADF,
            "the current task has no file descriptor table",
        )
    })?;
    let thread_local = task.as_thread_local().ok_or_else(|| {
        Error::with_message(
            Errno::EBADF,
            "the current task has no file descriptor table",
        )
    })?;
    let mut file_table = thread_local.borrow_file_table_mut();
    let file = file_table.read_with(|table| table.get_file(fd).cloned())?;
    Ok(file)
}

fn get_free_loop_device() -> Result<i32> {
    let devices = LOOP_DEVICES
        .get()
        .ok_or_else(|| Error::with_message(Errno::ENODEV, "loop devices are not initialized"))?;

    devices
        .iter()
        .find(|device| !device.is_bound())
        .map(|device| device.index as i32)
        .ok_or_else(|| Error::with_message(Errno::ENOSPC, "no free loop device is available"))
}

mod ioctl_defs {
    use super::{LoopConfig, LoopInfo64};
    use crate::util::ioctl::{InData, NoData, OutData, PassByVal, ioc};

    // Reference: <https://elixir.bootlin.com/linux/v7.0/source/include/uapi/linux/loop.h#L104>
    pub(super) type LoopSetFd = ioc!(LOOP_SET_FD, 0x4C00, InData<i32, PassByVal>);
    pub(super) type LoopClrFd = ioc!(LOOP_CLR_FD, 0x4C01, NoData);
    pub(super) type LoopSetStatus64 = ioc!(LOOP_SET_STATUS64, 0x4C04, InData<LoopInfo64>);
    pub(super) type LoopGetStatus64 = ioc!(LOOP_GET_STATUS64, 0x4C05, OutData<LoopInfo64>);
    pub(super) type LoopSetCapacity = ioc!(LOOP_SET_CAPACITY, 0x4C07, NoData);
    pub(super) type LoopConfigure = ioc!(LOOP_CONFIGURE, 0x4C0A, InData<LoopConfig>);
    pub(super) type LoopCtlGetFree = ioc!(LOOP_CTL_GET_FREE, 0x4C82, NoData);
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub(super) struct LoopInfo64 {
    lo_device: u64,
    lo_inode: u64,
    lo_rdevice: u64,
    lo_offset: u64,
    lo_sizelimit: u64,
    lo_number: u32,
    lo_encrypt_type: u32,
    lo_encrypt_key_size: u32,
    lo_flags: u32,
    lo_file_name: [u8; LOOP_NAME_SIZE],
    lo_crypt_name: [u8; LOOP_NAME_SIZE],
    lo_encrypt_key: [u8; LOOP_KEY_SIZE],
    lo_init: [u64; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub(super) struct LoopConfig {
    fd: u32,
    block_size: u32,
    info: LoopInfo64,
    reserved: [u64; 8],
}
