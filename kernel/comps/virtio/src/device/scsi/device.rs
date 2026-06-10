// SPDX-License-Identifier: MPL-2.0

use alloc::{
    boxed::Box,
    collections::BTreeMap,
    format,
    string::String,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    fmt::{self, Debug},
    sync::atomic::{AtomicU32, Ordering},
};

use aster_block::{
    BlockDeviceMeta, EXTENDED_DEVICE_ID_ALLOCATOR, MajorIdOwner, PartitionInfo, PartitionNode,
    bio::{BioEnqueueError, BioStatus, BioType, SubmittedBio, bio_segment_pool_init},
    request_queue::{BioRequest, BioRequestSingleQueue},
};
use aster_util::mem_obj_slice::Slice;
use device_id::{DeviceId, MinorId};
use ostd::{
    arch::trap::TrapFrame,
    debug, error, info,
    mm::{PAGE_SIZE, VmIo, dma::DmaStream, io::util::HasVmReaderWriter},
    sync::{LocalIrqDisabled, SpinLock},
    warn,
};
use spin::Once;

use super::{
    COMMAND_REQUEST_SIZE, COMMAND_RESPONSE_SIZE, CONTROL_QUEUE_INDEX, DEFAULT_QUEUE_SIZE,
    DEVICE_NAME, EVENT_QUEUE_INDEX, INQUIRY_DATA_LEN, LogicalBlockSize, Lun, MODE_SENSE_HEADER_LEN,
    READ_CAPACITY_10_DATA_LEN, READ_CAPACITY_16_DATA_LEN, REQUEST_QUEUE_INDEX,
    REQUEST_SENSE_DATA_LEN, ScsiCapacity, ScsiCdb, ScsiCommandRequest, ScsiCommandResponse,
    ScsiDeviceKind, ScsiIoPlan, VirtioScsiConfig, bounded_queue_size, formatted_cdrom_name,
    formatted_disk_name, parse_write_protect, supported_features,
};
use crate::{
    device::VirtioDeviceError,
    dma_buf::DmaBuf,
    id_alloc::SyncIdAlloc,
    queue::VirtQueue,
    transport::{ConfigManager, VirtioTransport},
};

/// The number of minor device numbers allocated for each SCSI disk.
const SCSI_DISK_MINORS: u32 = 16;

static SCSI_DISK_MAJOR_ID: Once<MajorIdOwner> = Once::new();
static SCSI_CDROM_MAJOR_ID: Once<MajorIdOwner> = Once::new();

static NR_SCSI_DISK_DEVICE: AtomicU32 = AtomicU32::new(0);
static NR_SCSI_CDROM_DEVICE: AtomicU32 = AtomicU32::new(0);

/// A virtio-scsi controller.
pub struct ScsiDevice;

impl ScsiDevice {
    /// Negotiates feature bits supported by the virtio-scsi driver.
    pub(crate) fn negotiate_features(features: u64) -> u64 {
        supported_features(features)
    }

    /// Initializes a virtio-scsi controller and registers discovered block devices.
    pub(crate) fn init(mut transport: Box<dyn VirtioTransport>) -> Result<(), VirtioDeviceError> {
        SCSI_DISK_MAJOR_ID.call_once(|| aster_block::allocate_major().unwrap());
        SCSI_CDROM_MAJOR_ID.call_once(|| aster_block::allocate_major().unwrap());

        let config_manager = VirtioScsiConfig::new_manager(transport.as_ref());
        config_manager.set_default_command_sizes();

        let total_queues = transport.num_queues();
        if total_queues <= REQUEST_QUEUE_INDEX || config_manager.request_queue_count() == 0 {
            return Err(VirtioDeviceError::UnsupportedConfig);
        }

        let control_queue = Self::new_queue(CONTROL_QUEUE_INDEX, 8, transport.as_mut())?;
        let event_queue = Self::new_queue(EVENT_QUEUE_INDEX, 8, transport.as_mut())?;
        let request_queue =
            Self::new_queue(REQUEST_QUEUE_INDEX, DEFAULT_QUEUE_SIZE, transport.as_mut())?;
        let request_queue_size = request_queue.queue_size();

        let device = Arc::new(DeviceInner::new(
            config_manager,
            control_queue,
            event_queue,
            request_queue,
            transport,
        )?);

        {
            let mut transport = device.transport.lock();
            transport.register_cfg_callback(Box::new(|_: &TrapFrame| {
                debug!("virtio-scsi configuration space changed");
            }))?;
            transport.finish_init();
        }

        let block_devices = device.probe_block_devices(request_queue_size);
        if block_devices.is_empty() {
            warn!("{} found no supported LUN", DEVICE_NAME);
            return Ok(());
        }

        {
            let mut transport = device.transport.lock();
            let cloned_device = device.clone();
            transport.register_queue_callback(
                REQUEST_QUEUE_INDEX,
                Box::new(move |_: &TrapFrame| {
                    cloned_device.handle_request_irq();
                }),
                false,
            )?;
        }

        for block_device in block_devices {
            aster_block::register(block_device).unwrap();
        }

        bio_segment_pool_init();
        Ok(())
    }

    fn new_queue(
        index: u16,
        preferred_size: u16,
        transport: &mut dyn VirtioTransport,
    ) -> Result<VirtQueue, VirtioDeviceError> {
        let max_queue_size = transport
            .max_queue_size(index)
            .map_err(VirtioDeviceError::from)?;
        let queue_size = bounded_queue_size(preferred_size, max_queue_size)
            .ok_or(VirtioDeviceError::InvalidQueueArgs)?;

        VirtQueue::new(index, queue_size, transport).map_err(Into::into)
    }
}

/// A block device exposed through a virtio-scsi logical unit.
pub struct ScsiBlockDevice {
    controller: Arc<DeviceInner>,
    queue: BioRequestSingleQueue,
    id: DeviceId,
    name: String,
    lun: Lun,
    kind: ScsiDeviceKind,
    logical_block_size: LogicalBlockSize,
    nr_sectors: usize,
    read_only: bool,
    partitions: SpinLock<Option<Vec<Arc<PartitionNode>>>>,
    weak_self: Weak<Self>,
}

impl ScsiBlockDevice {
    fn new(
        controller: Arc<DeviceInner>,
        info: ScsiLogicalUnitInfo,
        max_nr_segments_per_bio: usize,
    ) -> Arc<Self> {
        let (index, id, name) = match info.kind {
            ScsiDeviceKind::Disk => {
                let index = NR_SCSI_DISK_DEVICE.fetch_add(1, Ordering::Relaxed);
                let id = DeviceId::new(
                    SCSI_DISK_MAJOR_ID.get().unwrap().get(),
                    MinorId::new(index * SCSI_DISK_MINORS),
                );
                (index, id, formatted_disk_name("sd", index))
            }
            ScsiDeviceKind::Cdrom => {
                let index = NR_SCSI_CDROM_DEVICE.fetch_add(1, Ordering::Relaxed);
                let id = DeviceId::new(
                    SCSI_CDROM_MAJOR_ID.get().unwrap().get(),
                    MinorId::new(index),
                );
                (index, id, formatted_cdrom_name(index))
            }
        };

        let device = Arc::new_cyclic(|weak_self| Self {
            controller,
            queue: BioRequestSingleQueue::with_max_nr_segments_per_bio(max_nr_segments_per_bio),
            id,
            name,
            lun: info.lun,
            kind: info.kind,
            logical_block_size: info.capacity.block_size,
            nr_sectors: info.capacity.nr_512b_sectors().unwrap(),
            read_only: info.read_only,
            partitions: SpinLock::new(None),
            weak_self: weak_self.clone(),
        });

        info!(
            "registered virtio-scsi {:?} target {} as {} (index {}, block_size {}, sectors {})",
            device.kind,
            info.target,
            device.name,
            index,
            device.logical_block_size.bytes(),
            device.nr_sectors
        );
        device
    }

    /// Dequeues and processes one staged BIO request.
    pub fn handle_requests(&self) {
        let request = self.queue.dequeue();
        debug!("handle virtio-scsi request: {:?}", request);

        match request.type_() {
            BioType::Read => self
                .controller
                .read(self.lun, self.logical_block_size, request),
            BioType::Write if self.read_only || !self.kind.is_writable() => {
                complete_request(request, BioStatus::NotSupported);
            }
            BioType::Write => self
                .controller
                .write(self.lun, self.logical_block_size, request),
            BioType::Flush if self.read_only || !self.kind.is_writable() => {
                complete_request(request, BioStatus::Complete);
            }
            BioType::Flush => self.controller.flush(self.lun, request),
        }
    }
}

impl Debug for ScsiBlockDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScsiBlockDevice")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("lun", &self.lun)
            .field("kind", &self.kind)
            .field("logical_block_size", &self.logical_block_size)
            .field("nr_sectors", &self.nr_sectors)
            .field("read_only", &self.read_only)
            .finish()
    }
}

impl aster_block::BlockDevice for ScsiBlockDevice {
    fn enqueue(&self, bio: SubmittedBio) -> Result<(), BioEnqueueError> {
        self.queue.enqueue(bio)
    }

    fn metadata(&self) -> BlockDeviceMeta {
        BlockDeviceMeta {
            max_nr_segments_per_bio: self.queue.max_nr_segments_per_bio(),
            nr_sectors: self.nr_sectors,
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn id(&self) -> DeviceId {
        self.id
    }

    fn set_partitions(&self, infos: Vec<Option<PartitionInfo>>) {
        if self.kind != ScsiDeviceKind::Disk {
            return;
        }

        let mut partitions = self.partitions.lock();
        if let Some(old_partitions) = partitions.take() {
            for partition in old_partitions {
                let _ = aster_block::unregister(partition.id());
            }
        }

        let mut new_partitions = Vec::new();
        for (index, info_opt) in infos.iter().enumerate() {
            let Some(info) = info_opt else {
                continue;
            };

            let index = index as u32 + 1;
            let id = if index < SCSI_DISK_MINORS {
                DeviceId::new(self.id.major(), MinorId::new(self.id.minor().get() + index))
            } else {
                EXTENDED_DEVICE_ID_ALLOCATOR.get().unwrap().allocate()
            };
            let name = format!("{}{}", self.name(), index);
            let device = self.weak_self.upgrade().unwrap();

            let partition = Arc::new(PartitionNode::new(id, name, device, *info));
            new_partitions.push(partition);
        }

        for partition in new_partitions.iter() {
            let _ = aster_block::register(partition.clone());
        }

        *partitions = Some(new_partitions);
    }

    fn partitions(&self) -> Option<Vec<Arc<dyn aster_block::BlockDevice>>> {
        let partitions = self.partitions.lock();
        let devices = partitions
            .as_ref()?
            .iter()
            .map(|partition| partition.clone() as Arc<dyn aster_block::BlockDevice>)
            .collect();
        Some(devices)
    }
}

#[derive(Clone, Copy, Debug)]
struct ScsiLogicalUnitInfo {
    target: u8,
    lun: Lun,
    kind: ScsiDeviceKind,
    capacity: ScsiCapacity,
    read_only: bool,
}

struct DeviceInner {
    config_manager: ConfigManager<VirtioScsiConfig>,
    control_queue: SpinLock<VirtQueue, LocalIrqDisabled>,
    event_queue: SpinLock<VirtQueue, LocalIrqDisabled>,
    request_queue: SpinLock<VirtQueue, LocalIrqDisabled>,
    transport: SpinLock<Box<dyn VirtioTransport>>,
    command_requests: Arc<DmaStream>,
    command_responses: Arc<DmaStream>,
    id_allocator: SyncIdAlloc,
    submitted_requests: SpinLock<BTreeMap<u16, SubmittedRequest>, LocalIrqDisabled>,
}

impl DeviceInner {
    fn new(
        config_manager: ConfigManager<VirtioScsiConfig>,
        control_queue: VirtQueue,
        event_queue: VirtQueue,
        request_queue: VirtQueue,
        transport: Box<dyn VirtioTransport>,
    ) -> Result<Self, VirtioDeviceError> {
        let command_request_frames =
            frames_for_len(DEFAULT_QUEUE_SIZE as usize * COMMAND_REQUEST_SIZE);
        let command_response_frames =
            frames_for_len(DEFAULT_QUEUE_SIZE as usize * COMMAND_RESPONSE_SIZE);

        Ok(Self {
            config_manager,
            control_queue: SpinLock::new(control_queue),
            event_queue: SpinLock::new(event_queue),
            request_queue: SpinLock::new(request_queue),
            transport: SpinLock::new(transport),
            command_requests: Arc::new(
                DmaStream::alloc(command_request_frames, false)
                    .map_err(VirtioDeviceError::ResourceAlloc)?,
            ),
            command_responses: Arc::new(
                DmaStream::alloc(command_response_frames, false)
                    .map_err(VirtioDeviceError::ResourceAlloc)?,
            ),
            id_allocator: SyncIdAlloc::with_capacity(DEFAULT_QUEUE_SIZE as usize),
            submitted_requests: SpinLock::new(BTreeMap::new()),
        })
    }

    fn probe_block_devices(self: &Arc<Self>, request_queue_size: u16) -> Vec<Arc<ScsiBlockDevice>> {
        let max_target = self.config_manager.max_target().min(u8::MAX as u16) as u8;

        let max_nr_segments_per_bio = request_queue_size.saturating_sub(2) as usize;
        let mut devices = Vec::new();
        for target in 0..=max_target {
            let Some(info) = self.probe_target(target) else {
                continue;
            };
            devices.push(ScsiBlockDevice::new(
                self.clone(),
                info,
                max_nr_segments_per_bio,
            ));
        }

        devices
    }

    fn probe_target(&self, target: u8) -> Option<ScsiLogicalUnitInfo> {
        let lun = Lun::new(target, 0).unwrap();

        let inquiry = match self.execute_probe_command_sync(
            lun,
            ScsiCdb::inquiry(INQUIRY_DATA_LEN as u16),
            INQUIRY_DATA_LEN,
        ) {
            Ok(data) => data,
            Err(ScsiCommandError::BadTarget) => return None,
            Err(error) => {
                debug!("failed to probe SCSI target {target}: {:?}", error);
                return None;
            }
        };

        let kind = ScsiDeviceKind::from_inquiry_data(&inquiry)?;
        let capacity = self.read_capacity(lun)?;
        if capacity.last_lba > u32::MAX as u64 {
            warn!(
                "SCSI target {} is too large for READ(10): last_lba={}",
                target, capacity.last_lba
            );
            return None;
        }

        let read_only = match kind {
            ScsiDeviceKind::Disk => self.read_write_protect(lun).unwrap_or(false),
            ScsiDeviceKind::Cdrom => true,
        };

        Some(ScsiLogicalUnitInfo {
            target,
            lun,
            kind,
            capacity,
            read_only,
        })
    }

    fn read_capacity(&self, lun: Lun) -> Option<ScsiCapacity> {
        let data = self
            .execute_probe_command_sync(lun, ScsiCdb::read_capacity_10(), READ_CAPACITY_10_DATA_LEN)
            .ok()?;
        let capacity = ScsiCapacity::parse_read_capacity_10(&data)?;
        if capacity.last_lba != u32::MAX as u64 {
            return Some(capacity);
        }

        let data = self
            .execute_probe_command_sync(
                lun,
                ScsiCdb::read_capacity_16(READ_CAPACITY_16_DATA_LEN as u32),
                READ_CAPACITY_16_DATA_LEN,
            )
            .ok()?;
        ScsiCapacity::parse_read_capacity_16(&data)
    }

    fn read_write_protect(&self, lun: Lun) -> Option<bool> {
        let data = self
            .execute_probe_command_sync(
                lun,
                ScsiCdb::mode_sense_6(MODE_SENSE_HEADER_LEN as u8),
                MODE_SENSE_HEADER_LEN,
            )
            .ok()?;
        parse_write_protect(&data)
    }

    fn read(&self, lun: Lun, block_size: LogicalBlockSize, request: BioRequest) {
        let Some(plan) =
            block_size.plan_read(request.sid_range().start.to_raw(), request.num_sectors())
        else {
            complete_request(request, BioStatus::IoError);
            return;
        };

        let Some(lba) = plan.lba32() else {
            complete_request(request, BioStatus::IoError);
            return;
        };

        let cdb = ScsiCdb::read_10(lba, plan.num_blocks);
        if plan.uses_bounce_buffer {
            self.read_with_bounce(lun, cdb, plan, request);
        } else {
            self.submit_bio_request(lun, cdb, request, DataTransfer::DirectRead);
        }
    }

    fn write(&self, lun: Lun, block_size: LogicalBlockSize, request: BioRequest) {
        let Some(plan) =
            block_size.plan_write(request.sid_range().start.to_raw(), request.num_sectors())
        else {
            complete_request(request, BioStatus::NotSupported);
            return;
        };

        let Some(lba) = plan.lba32() else {
            complete_request(request, BioStatus::IoError);
            return;
        };

        let cdb = ScsiCdb::write_10(lba, plan.num_blocks);
        self.submit_bio_request(lun, cdb, request, DataTransfer::DirectWrite);
    }

    fn flush(&self, lun: Lun, request: BioRequest) {
        self.submit_bio_request(
            lun,
            ScsiCdb::synchronize_cache_10(),
            request,
            DataTransfer::None,
        );
    }

    fn read_with_bounce(&self, lun: Lun, cdb: ScsiCdb, plan: ScsiIoPlan, request: BioRequest) {
        let buffer = match DmaStream::alloc(frames_for_len(plan.data_len), false) {
            Ok(buffer) => Arc::new(buffer),
            Err(_) => {
                complete_request(request, BioStatus::IoError);
                return;
            }
        };

        self.submit_bio_request(
            lun,
            cdb,
            request,
            DataTransfer::BounceRead {
                buffer,
                byte_offset: plan.byte_offset,
                data_len: plan.data_len,
            },
        );
    }

    fn submit_bio_request(
        &self,
        lun: Lun,
        cdb: ScsiCdb,
        request: BioRequest,
        transfer: DataTransfer,
    ) {
        if matches!(transfer, DataTransfer::DirectWrite) {
            sync_request_data_to_device(&request);
        }

        let id = self.id_allocator.alloc();
        let req_slice = self.prepare_command_request(id, lun, cdb);
        let resp_slice = self.prepare_command_response(id);
        let num_used_descs = 2 + transfer.num_data_descriptors(&request);

        loop {
            let mut queue = self.request_queue.lock();
            if num_used_descs > queue.available_desc() {
                continue;
            }

            let token = match &transfer {
                DataTransfer::None => queue.add_dma_bufs(&[&req_slice], &[&resp_slice]),
                DataTransfer::DirectRead => {
                    let mut outputs = Vec::with_capacity(request.num_segments().saturating_add(1));
                    outputs.push(&resp_slice);
                    outputs.extend(request_dma_slices(&request));
                    queue.add_dma_bufs(&[&req_slice], outputs.as_slice())
                }
                DataTransfer::DirectWrite => {
                    let mut inputs = Vec::with_capacity(request.num_segments().saturating_add(1));
                    inputs.push(&req_slice);
                    inputs.extend(request_dma_slices(&request));
                    queue.add_dma_bufs(inputs.as_slice(), &[&resp_slice])
                }
                DataTransfer::BounceRead {
                    buffer, data_len, ..
                } => {
                    let data_slice = Slice::new(buffer.clone(), 0..*data_len);
                    queue.add_dma_bufs(&[&req_slice], &[&resp_slice, &data_slice])
                }
            }
            .expect("adding a checked virtio-scsi descriptor chain should succeed");

            let submitted_request = SubmittedRequest::new(id, request, transfer);
            self.submitted_requests
                .lock()
                .insert(token, submitted_request);
            if queue.should_notify() {
                queue.notify();
            }
            return;
        }
    }

    fn handle_request_irq(&self) {
        loop {
            let submitted_request = {
                let mut queue = self.request_queue.lock();
                let submitted_requests = self.submitted_requests.lock();
                let result =
                    queue.pop_used_with_len_bound(COMMAND_RESPONSE_SIZE, |token, output_len| {
                        submitted_requests
                            .get(&token)
                            .map(|request| request.max_used_len(output_len as usize))
                            .unwrap_or(output_len as usize)
                    });
                drop(submitted_requests);

                let Ok((token, _)) = result else {
                    return;
                };

                let Some(request) = self.submitted_requests.lock().remove(&token) else {
                    error!("virtio-scsi completion uses unknown token {}", token);
                    continue;
                };
                request
            };

            self.complete_submitted_request(submitted_request);
        }
    }

    fn complete_submitted_request(&self, submitted_request: SubmittedRequest) {
        let id = submitted_request.id;
        let resp_slice = self.response_slice(id);
        resp_slice.sync_from_device().unwrap();
        let response = resp_slice.read_val::<ScsiCommandResponse>(0).unwrap();
        self.id_allocator.dealloc(id);

        let status = if response.is_success() && response.resid() == 0 {
            self.finish_data_transfer(&submitted_request)
        } else {
            BioStatus::IoError
        };

        complete_request(submitted_request.request, status);
    }

    fn finish_data_transfer(&self, submitted_request: &SubmittedRequest) -> BioStatus {
        match &submitted_request.transfer {
            DataTransfer::None | DataTransfer::DirectWrite => BioStatus::Complete,
            DataTransfer::DirectRead => {
                sync_request_data_from_device(&submitted_request.request);
                BioStatus::Complete
            }
            DataTransfer::BounceRead {
                buffer,
                byte_offset,
                data_len,
            } => {
                if buffer.sync_from_device(0..*data_len).is_err() {
                    return BioStatus::IoError;
                }
                if copy_bounce_buffer(&submitted_request.request, buffer, *byte_offset).is_err() {
                    return BioStatus::IoError;
                }
                BioStatus::Complete
            }
        }
    }

    fn execute_command_sync(
        &self,
        lun: Lun,
        cdb: ScsiCdb,
        data_in_len: usize,
    ) -> Result<Vec<u8>, ScsiCommandError> {
        let id = self.id_allocator.alloc();
        let req_slice = self.prepare_command_request(id, lun, cdb);
        let resp_slice = self.prepare_command_response(id);
        let data_buffer = if data_in_len > 0 {
            Some(Arc::new(
                DmaStream::alloc(frames_for_len(data_in_len), false)
                    .map_err(|_| ScsiCommandError::ResourceAlloc)?,
            ))
        } else {
            None
        };
        let data_slice = data_buffer
            .as_ref()
            .map(|buffer| Slice::new(buffer.clone(), 0..data_in_len));

        {
            let mut outputs = Vec::with_capacity(1 + usize::from(data_slice.is_some()));
            outputs.push(&resp_slice);
            if let Some(data_slice) = data_slice.as_ref() {
                outputs.push(data_slice);
            }

            let mut queue = self.request_queue.lock();
            if outputs.len() + 1 > queue.available_desc() {
                self.id_allocator.dealloc(id);
                return Err(ScsiCommandError::QueueFull);
            }
            queue
                .add_dma_bufs(&[&req_slice], outputs.as_slice())
                .unwrap();
            if queue.should_notify() {
                queue.notify();
            }
        }

        loop {
            let mut queue = self.request_queue.lock();
            if let Ok((_, _)) = queue.pop_used_with_min_bytes(COMMAND_RESPONSE_SIZE) {
                break;
            }
            core::hint::spin_loop();
        }

        resp_slice.sync_from_device().unwrap();
        let response = resp_slice.read_val::<ScsiCommandResponse>(0).unwrap();
        self.id_allocator.dealloc(id);

        if response.is_bad_target() {
            return Err(ScsiCommandError::BadTarget);
        }
        if !response.is_success() {
            return Err(ScsiCommandError::CommandFailed);
        }
        if response.resid() as usize > data_in_len {
            return Err(ScsiCommandError::CommandFailed);
        }

        let mut data = Vec::new();
        if let Some(data_slice) = data_slice {
            data_slice.sync_from_device().unwrap();
            data.resize(data_in_len - response.resid() as usize, 0);
            if !data.is_empty() {
                data_slice.read_bytes(0, data.as_mut_slice()).unwrap();
            }
        }

        Ok(data)
    }

    fn execute_probe_command_sync(
        &self,
        lun: Lun,
        cdb: ScsiCdb,
        data_in_len: usize,
    ) -> Result<Vec<u8>, ScsiCommandError> {
        const MAX_RETRIES: usize = 3;

        for retry in 0..=MAX_RETRIES {
            match self.execute_command_sync(lun, cdb, data_in_len) {
                Ok(data) => return Ok(data),
                Err(ScsiCommandError::CommandFailed) if retry < MAX_RETRIES => {
                    let _ = self.execute_command_sync(
                        lun,
                        ScsiCdb::request_sense(REQUEST_SENSE_DATA_LEN as u8),
                        REQUEST_SENSE_DATA_LEN,
                    );
                }
                Err(error) => return Err(error),
            }
        }

        Err(ScsiCommandError::CommandFailed)
    }

    fn prepare_command_request(&self, id: usize, lun: Lun, cdb: ScsiCdb) -> Slice<Arc<DmaStream>> {
        let req_slice = self.request_slice(id);
        let req = ScsiCommandRequest::new(lun, id as u64, cdb);
        req_slice.write_val(0, &req).unwrap();
        req_slice.sync_to_device().unwrap();
        req_slice
    }

    fn prepare_command_response(&self, id: usize) -> Slice<Arc<DmaStream>> {
        let resp_slice = self.response_slice(id);
        resp_slice
            .write_val(0, &ScsiCommandResponse::default())
            .unwrap();
        resp_slice.sync_to_device().unwrap();
        resp_slice
    }

    fn request_slice(&self, id: usize) -> Slice<Arc<DmaStream>> {
        let start = id * COMMAND_REQUEST_SIZE;
        Slice::new(
            self.command_requests.clone(),
            start..start + COMMAND_REQUEST_SIZE,
        )
    }

    fn response_slice(&self, id: usize) -> Slice<Arc<DmaStream>> {
        let start = id * COMMAND_RESPONSE_SIZE;
        Slice::new(
            self.command_responses.clone(),
            start..start + COMMAND_RESPONSE_SIZE,
        )
    }
}

impl Debug for DeviceInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceInner")
            .field("control_queue", &self.control_queue)
            .field("event_queue", &self.event_queue)
            .field("request_queue", &self.request_queue)
            .field("id_allocator", &self.id_allocator)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct SubmittedRequest {
    id: usize,
    request: BioRequest,
    transfer: DataTransfer,
}

impl SubmittedRequest {
    fn new(id: usize, request: BioRequest, transfer: DataTransfer) -> Self {
        Self {
            id,
            request,
            transfer,
        }
    }

    fn max_used_len(&self, output_len: usize) -> usize {
        match self.transfer {
            DataTransfer::DirectWrite => output_len.saturating_add(request_data_len(&self.request)),
            _ => output_len,
        }
    }
}

#[derive(Debug)]
enum DataTransfer {
    None,
    DirectRead,
    DirectWrite,
    BounceRead {
        buffer: Arc<DmaStream>,
        byte_offset: usize,
        data_len: usize,
    },
}

impl DataTransfer {
    fn num_data_descriptors(&self, request: &BioRequest) -> usize {
        match self {
            Self::None => 0,
            Self::DirectRead | Self::DirectWrite => request.num_segments(),
            Self::BounceRead { .. } => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScsiCommandError {
    BadTarget,
    CommandFailed,
    QueueFull,
    ResourceAlloc,
}

fn frames_for_len(len: usize) -> usize {
    len.div_ceil(PAGE_SIZE).max(1)
}

fn request_dma_slices(request: &BioRequest) -> impl Iterator<Item = &Slice<Arc<DmaStream>>> {
    request.bios().flat_map(|bio| {
        bio.segments()
            .iter()
            .map(|segment| segment.inner_dma_slice())
    })
}

fn request_data_len(request: &BioRequest) -> usize {
    request_dma_slices(request).map(|slice| slice.len()).sum()
}

fn sync_request_data_to_device(request: &BioRequest) {
    for dma_slice in request_dma_slices(request) {
        dma_slice.sync_to_device().unwrap();
    }
}

fn sync_request_data_from_device(request: &BioRequest) {
    for dma_slice in request_dma_slices(request) {
        dma_slice.sync_from_device().unwrap();
    }
}

fn copy_bounce_buffer(
    request: &BioRequest,
    buffer: &Arc<DmaStream>,
    mut byte_offset: usize,
) -> Result<(), ostd::Error> {
    for bio in request.bios() {
        for segment in bio.segments() {
            let len = segment.nbytes();
            let source = Slice::new(buffer.clone(), byte_offset..byte_offset + len);
            let mut reader = source.reader().unwrap().to_fallible();
            segment.inner_dma_slice().write(0, &mut reader)?;
            byte_offset += len;
        }
    }

    Ok(())
}

fn complete_request(request: BioRequest, status: BioStatus) {
    for bio in request.into_bios() {
        bio.complete(status);
    }
}
