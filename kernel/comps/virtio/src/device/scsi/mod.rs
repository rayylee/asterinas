// SPDX-License-Identifier: MPL-2.0

//! The virtio-scsi device protocol.

pub mod device;

use alloc::string::String;
use core::{cmp, mem::offset_of};

use aster_block::SECTOR_SIZE;
use aster_util::safe_ptr::SafePtr;
use bitflags::bitflags;
use int_to_c_enum::TryFromInt;

use crate::transport::{ConfigManager, VirtioTransport};

/// The device name used in log messages.
pub const DEVICE_NAME: &str = "Virtio-SCSI";

pub(super) const CONTROL_QUEUE_INDEX: u16 = 0;
pub(super) const EVENT_QUEUE_INDEX: u16 = 1;
pub(super) const REQUEST_QUEUE_INDEX: u16 = 2;

pub(super) const DEFAULT_QUEUE_SIZE: u16 = 64;
pub(super) const DEFAULT_CDB_SIZE: usize = 32;
pub(super) const DEFAULT_SENSE_SIZE: usize = 96;

pub(super) const INQUIRY_DATA_LEN: usize = 96;
pub(super) const MODE_SENSE_HEADER_LEN: usize = 4;
pub(super) const READ_CAPACITY_10_DATA_LEN: usize = 8;
pub(super) const READ_CAPACITY_16_DATA_LEN: usize = 32;

const LUN_ADDRESSING_METHOD: u8 = 1;
const MAX_LUN: u16 = 0x3fff;
const MAX_LOGICAL_BLOCK_SIZE: usize = 4096;

bitflags! {
    /// Feature bits for virtio-scsi devices.
    struct ScsiFeatures: u64 {
        const INOUT = 1 << 0;
        const HOTPLUG = 1 << 1;
        const CHANGE = 1 << 2;
        const T10_PI = 1 << 3;
    }
}

#[padding_struct]
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Pod)]
pub(super) struct VirtioScsiConfig {
    num_queues: u32,
    seg_max: u32,
    max_sectors: u32,
    cmd_per_lun: u32,
    event_info_size: u32,
    sense_size: u32,
    cdb_size: u32,
    max_channel: u16,
    max_target: u16,
    max_lun: u32,
}

impl VirtioScsiConfig {
    pub(super) fn new_manager(transport: &dyn VirtioTransport) -> ConfigManager<Self> {
        let safe_ptr = transport
            .device_config_mem()
            .map(|mem| SafePtr::new(mem, 0));
        let bar_space = transport.device_config_bar();

        ConfigManager::new(safe_ptr, bar_space)
    }
}

impl ConfigManager<VirtioScsiConfig> {
    pub(super) fn request_queue_count(&self) -> u32 {
        self.read_once::<u32>(offset_of!(VirtioScsiConfig, num_queues))
            .unwrap()
    }

    pub(super) fn max_target(&self) -> u16 {
        self.read_once::<u16>(offset_of!(VirtioScsiConfig, max_target))
            .unwrap()
    }

    pub(super) fn set_default_command_sizes(&self) {
        self.write_once::<u32>(
            offset_of!(VirtioScsiConfig, sense_size),
            DEFAULT_SENSE_SIZE as u32,
        )
        .unwrap();
        self.write_once::<u32>(
            offset_of!(VirtioScsiConfig, cdb_size),
            DEFAULT_CDB_SIZE as u32,
        )
        .unwrap();
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Pod)]
pub(super) struct ScsiCommandRequest {
    lun: [u8; 8],
    tag: u64,
    task_attr: u8,
    prio: u8,
    crn: u8,
    cdb: [u8; DEFAULT_CDB_SIZE],
}

impl ScsiCommandRequest {
    pub(super) fn new(lun: Lun, tag: u64, cdb: ScsiCdb) -> Self {
        Self {
            lun: lun.bytes(),
            tag,
            task_attr: ScsiTaskAttr::Simple as u8,
            prio: 0,
            crn: 0,
            cdb: cdb.into_bytes(),
        }
    }
}

pub(super) const COMMAND_REQUEST_SIZE: usize = size_of::<ScsiCommandRequest>();

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Pod)]
pub(super) struct ScsiCommandResponse {
    sense_len: u32,
    resid: u32,
    status_qualifier: u16,
    status: u8,
    response: u8,
    sense: [u8; DEFAULT_SENSE_SIZE],
}

impl ScsiCommandResponse {
    pub(super) fn is_success(&self) -> bool {
        self.response == ScsiResponseCode::Ok as u8 && self.status == ScsiStatus::Good as u8
    }

    pub(super) fn is_bad_target(&self) -> bool {
        self.response == ScsiResponseCode::BadTarget as u8
            || self.response == ScsiResponseCode::IncorrectLun as u8
    }

    pub(super) fn resid(&self) -> u32 {
        self.resid
    }
}

impl Default for ScsiCommandResponse {
    fn default() -> Self {
        Self {
            sense_len: 0,
            resid: 0,
            status_qualifier: 0,
            status: ScsiStatus::CheckCondition as u8,
            response: ScsiResponseCode::Failure as u8,
            sense: [0; DEFAULT_SENSE_SIZE],
        }
    }
}

pub(super) const COMMAND_RESPONSE_SIZE: usize = size_of::<ScsiCommandResponse>();

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
enum ScsiTaskAttr {
    Simple = 0,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, TryFromInt)]
pub(super) enum ScsiResponseCode {
    Ok = 0,
    Overrun = 1,
    Aborted = 2,
    BadTarget = 3,
    Reset = 4,
    Busy = 5,
    TransportFailure = 6,
    TargetFailure = 7,
    NexusFailure = 8,
    Failure = 9,
    FunctionSucceeded = 10,
    FunctionRejected = 11,
    IncorrectLun = 12,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, TryFromInt)]
pub(super) enum ScsiStatus {
    Good = 0x00,
    CheckCondition = 0x02,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ScsiDeviceKind {
    Disk = 0x00,
    Cdrom = 0x05,
}

impl ScsiDeviceKind {
    fn from_inquiry_byte(byte: u8) -> Option<Self> {
        match byte & 0x1f {
            value if value == Self::Disk as u8 => Some(Self::Disk),
            value if value == Self::Cdrom as u8 => Some(Self::Cdrom),
            _ => None,
        }
    }

    pub(super) fn from_inquiry_data(data: &[u8]) -> Option<Self> {
        data.first().copied().and_then(Self::from_inquiry_byte)
    }

    pub(super) fn is_writable(self) -> bool {
        matches!(self, Self::Disk)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Lun([u8; 8]);

impl Lun {
    pub(super) fn new(target: u8, lun: u16) -> Option<Self> {
        if lun > MAX_LUN {
            return None;
        }

        let mut bytes = [0; 8];
        bytes[0] = LUN_ADDRESSING_METHOD;
        bytes[1] = target;
        bytes[2] = (lun >> 8) as u8;
        bytes[3] = lun as u8;

        Some(Self(bytes))
    }

    pub(super) fn bytes(self) -> [u8; 8] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ScsiCdb([u8; DEFAULT_CDB_SIZE]);

impl ScsiCdb {
    pub(super) fn inquiry(allocation_len: u16) -> Self {
        let mut cdb = [0; DEFAULT_CDB_SIZE];
        cdb[0] = ScsiOpcode::Inquiry as u8;
        cdb[3..5].copy_from_slice(&allocation_len.to_be_bytes());
        Self(cdb)
    }

    pub(super) fn mode_sense_6(allocation_len: u8) -> Self {
        let mut cdb = [0; DEFAULT_CDB_SIZE];
        cdb[0] = ScsiOpcode::ModeSense6 as u8;
        // Disable block descriptors and request all current mode pages.
        cdb[1] = 0x08;
        cdb[2] = 0x3f;
        cdb[4] = allocation_len;
        Self(cdb)
    }

    pub(super) fn read_capacity_10() -> Self {
        let mut cdb = [0; DEFAULT_CDB_SIZE];
        cdb[0] = ScsiOpcode::ReadCapacity10 as u8;
        Self(cdb)
    }

    pub(super) fn read_capacity_16(allocation_len: u32) -> Self {
        let mut cdb = [0; DEFAULT_CDB_SIZE];
        cdb[0] = ScsiOpcode::ServiceActionIn16 as u8;
        cdb[1] = ScsiServiceActionIn16::ReadCapacity16 as u8;
        cdb[10..14].copy_from_slice(&allocation_len.to_be_bytes());
        Self(cdb)
    }

    pub(super) fn read_10(lba: u32, blocks: u16) -> Self {
        Self::rw_10(ScsiOpcode::Read10, lba, blocks)
    }

    pub(super) fn write_10(lba: u32, blocks: u16) -> Self {
        Self::rw_10(ScsiOpcode::Write10, lba, blocks)
    }

    pub(super) fn synchronize_cache_10() -> Self {
        let mut cdb = [0; DEFAULT_CDB_SIZE];
        cdb[0] = ScsiOpcode::SynchronizeCache10 as u8;
        Self(cdb)
    }

    pub(super) fn into_bytes(self) -> [u8; DEFAULT_CDB_SIZE] {
        self.0
    }

    fn rw_10(opcode: ScsiOpcode, lba: u32, blocks: u16) -> Self {
        let mut cdb = [0; DEFAULT_CDB_SIZE];
        cdb[0] = opcode as u8;
        cdb[2..6].copy_from_slice(&lba.to_be_bytes());
        cdb[7..9].copy_from_slice(&blocks.to_be_bytes());
        Self(cdb)
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
enum ScsiOpcode {
    Inquiry = 0x12,
    ModeSense6 = 0x1a,
    ReadCapacity10 = 0x25,
    Read10 = 0x28,
    Write10 = 0x2a,
    SynchronizeCache10 = 0x35,
    ServiceActionIn16 = 0x9e,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
enum ScsiServiceActionIn16 {
    ReadCapacity16 = 0x10,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ScsiCapacity {
    pub(super) last_lba: u64,
    pub(super) block_size: LogicalBlockSize,
}

impl ScsiCapacity {
    pub(super) fn parse_read_capacity_10(data: &[u8]) -> Option<Self> {
        if data.len() < READ_CAPACITY_10_DATA_LEN {
            return None;
        }

        let last_lba = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let block_size = u32::from_be_bytes(data[4..8].try_into().unwrap()) as usize;
        Some(Self {
            last_lba: last_lba as u64,
            block_size: LogicalBlockSize::new(block_size)?,
        })
    }

    pub(super) fn parse_read_capacity_16(data: &[u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }

        let last_lba = u64::from_be_bytes(data[0..8].try_into().unwrap());
        let block_size = u32::from_be_bytes(data[8..12].try_into().unwrap()) as usize;
        Some(Self {
            last_lba,
            block_size: LogicalBlockSize::new(block_size)?,
        })
    }

    pub(super) fn nr_512b_sectors(self) -> Option<usize> {
        let logical_blocks = self.last_lba.checked_add(1)?;
        let sectors = logical_blocks.checked_mul(self.block_size.sectors_per_block() as u64)?;
        sectors.try_into().ok()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct LogicalBlockSize(usize);

impl LogicalBlockSize {
    pub(super) fn new(size: usize) -> Option<Self> {
        if !(SECTOR_SIZE..=MAX_LOGICAL_BLOCK_SIZE).contains(&size)
            || !size.is_multiple_of(SECTOR_SIZE)
            || !size.is_power_of_two()
        {
            return None;
        }

        Some(Self(size))
    }

    pub(super) fn bytes(self) -> usize {
        self.0
    }

    pub(super) fn sectors_per_block(self) -> usize {
        self.bytes() / SECTOR_SIZE
    }

    pub(super) fn plan_read(self, start_sector: u64, num_sectors: usize) -> Option<ScsiIoPlan> {
        let sectors_per_block = self.sectors_per_block() as u64;
        let num_sectors = num_sectors as u64;
        let end_sector = start_sector.checked_add(num_sectors)?;
        let start_block = start_sector / sectors_per_block;
        let end_block = end_sector.div_ceil(sectors_per_block);
        let num_blocks = end_block.checked_sub(start_block)?;
        let byte_offset = ((start_sector % sectors_per_block) as usize) * SECTOR_SIZE;
        let requested_bytes = (num_sectors as usize).checked_mul(SECTOR_SIZE)?;
        let data_len = (num_blocks as usize).checked_mul(self.bytes())?;

        Some(ScsiIoPlan {
            lba: start_block,
            num_blocks: num_blocks.try_into().ok()?,
            data_len,
            byte_offset,
            requested_bytes,
            uses_bounce_buffer: byte_offset != 0 || data_len != requested_bytes,
        })
    }

    pub(super) fn plan_write(self, start_sector: u64, num_sectors: usize) -> Option<ScsiIoPlan> {
        let plan = self.plan_read(start_sector, num_sectors)?;
        if plan.uses_bounce_buffer {
            return None;
        }

        Some(plan)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ScsiIoPlan {
    pub(super) lba: u64,
    pub(super) num_blocks: u16,
    pub(super) data_len: usize,
    pub(super) byte_offset: usize,
    pub(super) requested_bytes: usize,
    pub(super) uses_bounce_buffer: bool,
}

impl ScsiIoPlan {
    pub(super) fn lba32(self) -> Option<u32> {
        self.lba.try_into().ok()
    }
}

pub(super) fn parse_write_protect(data: &[u8]) -> Option<bool> {
    data.get(2).map(|byte| byte & 0x80 != 0)
}

pub(super) fn formatted_disk_name(prefix: &str, mut index: u32) -> String {
    let mut suffix = [0u8; 8];
    let mut len = 0;

    loop {
        suffix[len] = b'a' + (index % 26) as u8;
        len += 1;
        index /= 26;
        if index == 0 {
            break;
        }
        index -= 1;
    }

    let mut name = String::from(prefix);
    for byte in suffix[..len].iter().rev() {
        name.push(*byte as char);
    }
    name
}

pub(super) fn formatted_cdrom_name(index: u32) -> String {
    use alloc::format;

    format!("sr{index}")
}

pub(super) fn supported_features(features: u64) -> u64 {
    let mut features = ScsiFeatures::from_bits_truncate(features);
    features.remove(
        ScsiFeatures::INOUT | ScsiFeatures::HOTPLUG | ScsiFeatures::CHANGE | ScsiFeatures::T10_PI,
    );
    features.bits()
}

pub(super) fn bounded_queue_size(preferred: u16, max: u16) -> Option<u16> {
    let mut size = cmp::min(preferred, max);
    while size > 0 && !size.is_power_of_two() {
        size -= 1;
    }
    (size > 0).then_some(size)
}

#[cfg(ktest)]
mod tests {
    use ostd::prelude::*;

    use super::*;

    #[ktest]
    fn scsi_encodes_lun0_for_targets() {
        assert_eq!(Lun::new(0, 0).unwrap().bytes(), [1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(Lun::new(7, 0).unwrap().bytes(), [1, 7, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            Lun::new(7, 0x1234).unwrap().bytes(),
            [1, 7, 0x12, 0x34, 0, 0, 0, 0]
        );
        assert!(Lun::new(0, 0x4000).is_none());
    }

    #[ktest]
    fn scsi_builds_common_cdbs() {
        let inquiry = ScsiCdb::inquiry(96).into_bytes();
        assert_eq!(&inquiry[..6], &[0x12, 0, 0, 0, 96, 0]);

        let capacity10 = ScsiCdb::read_capacity_10().into_bytes();
        assert_eq!(capacity10[0], 0x25);

        let capacity16 = ScsiCdb::read_capacity_16(32).into_bytes();
        assert_eq!(capacity16[0], 0x9e);
        assert_eq!(capacity16[1], 0x10);
        assert_eq!(&capacity16[10..14], &32u32.to_be_bytes());

        let read10 = ScsiCdb::read_10(0x1234_5678, 0x9abc).into_bytes();
        assert_eq!(read10[0], 0x28);
        assert_eq!(&read10[2..6], &0x1234_5678u32.to_be_bytes());
        assert_eq!(&read10[7..9], &0x9abcu16.to_be_bytes());

        let write10 = ScsiCdb::write_10(2, 4).into_bytes();
        assert_eq!(write10[0], 0x2a);
        assert_eq!(&write10[2..6], &2u32.to_be_bytes());
        assert_eq!(&write10[7..9], &4u16.to_be_bytes());

        let sync = ScsiCdb::synchronize_cache_10().into_bytes();
        assert_eq!(sync[0], 0x35);
    }

    #[ktest]
    fn scsi_parses_inquiry_and_capacity() {
        assert_eq!(
            ScsiDeviceKind::from_inquiry_data(&[0x00]),
            Some(ScsiDeviceKind::Disk)
        );
        assert_eq!(
            ScsiDeviceKind::from_inquiry_data(&[0x05]),
            Some(ScsiDeviceKind::Cdrom)
        );
        assert_eq!(ScsiDeviceKind::from_inquiry_data(&[0x1f]), None);

        let mut capacity10 = [0; READ_CAPACITY_10_DATA_LEN];
        capacity10[0..4].copy_from_slice(&7u32.to_be_bytes());
        capacity10[4..8].copy_from_slice(&512u32.to_be_bytes());
        let parsed = ScsiCapacity::parse_read_capacity_10(&capacity10).unwrap();
        assert_eq!(parsed.last_lba, 7);
        assert_eq!(parsed.block_size.bytes(), 512);
        assert_eq!(parsed.nr_512b_sectors(), Some(8));

        let mut capacity16 = [0; READ_CAPACITY_16_DATA_LEN];
        capacity16[0..8].copy_from_slice(&15u64.to_be_bytes());
        capacity16[8..12].copy_from_slice(&2048u32.to_be_bytes());
        let parsed = ScsiCapacity::parse_read_capacity_16(&capacity16).unwrap();
        assert_eq!(parsed.last_lba, 15);
        assert_eq!(parsed.block_size.bytes(), 2048);
        assert_eq!(parsed.nr_512b_sectors(), Some(64));
    }

    #[ktest]
    fn scsi_parses_command_response_status() {
        let ok = ScsiCommandResponse {
            status: ScsiStatus::Good as u8,
            response: ScsiResponseCode::Ok as u8,
            ..Default::default()
        };
        assert!(ok.is_success());

        let bad_target = ScsiCommandResponse {
            response: ScsiResponseCode::BadTarget as u8,
            ..Default::default()
        };
        assert!(bad_target.is_bad_target());

        let check_condition = ScsiCommandResponse {
            status: ScsiStatus::CheckCondition as u8,
            response: ScsiResponseCode::Ok as u8,
            ..Default::default()
        };
        assert!(!check_condition.is_success());
    }

    #[ktest]
    fn scsi_formats_device_names() {
        assert_eq!(formatted_disk_name("sd", 0), "sda");
        assert_eq!(formatted_disk_name("sd", 25), "sdz");
        assert_eq!(formatted_disk_name("sd", 26), "sdaa");
        assert_eq!(formatted_disk_name("sd", 27), "sdab");
        assert_eq!(formatted_cdrom_name(0), "sr0");
        assert_eq!(formatted_cdrom_name(12), "sr12");
    }

    #[ktest]
    fn scsi_plans_logical_block_io() {
        let block_512 = LogicalBlockSize::new(512).unwrap();
        assert_eq!(
            block_512.plan_read(3, 8).unwrap(),
            ScsiIoPlan {
                lba: 3,
                num_blocks: 8,
                data_len: 4096,
                byte_offset: 0,
                requested_bytes: 4096,
                uses_bounce_buffer: false,
            }
        );

        let block_2048 = LogicalBlockSize::new(2048).unwrap();
        assert_eq!(
            block_2048.plan_read(4, 8).unwrap(),
            ScsiIoPlan {
                lba: 1,
                num_blocks: 2,
                data_len: 4096,
                byte_offset: 0,
                requested_bytes: 4096,
                uses_bounce_buffer: false,
            }
        );
        assert_eq!(
            block_2048.plan_read(1, 1).unwrap(),
            ScsiIoPlan {
                lba: 0,
                num_blocks: 1,
                data_len: 2048,
                byte_offset: 512,
                requested_bytes: 512,
                uses_bounce_buffer: true,
            }
        );
        assert!(block_2048.plan_write(1, 1).is_none());

        let block_4096 = LogicalBlockSize::new(4096).unwrap();
        assert_eq!(block_4096.plan_read(8, 8).unwrap().lba, 1);
        assert!(LogicalBlockSize::new(768).is_none());
        assert!(LogicalBlockSize::new(8192).is_none());
    }

    #[ktest]
    fn scsi_chooses_bounded_queue_size() {
        assert_eq!(bounded_queue_size(64, 1024), Some(64));
        assert_eq!(bounded_queue_size(64, 32), Some(32));
        assert_eq!(bounded_queue_size(64, 48), Some(32));
        assert_eq!(bounded_queue_size(64, 0), None);
    }
}
