// SPDX-License-Identifier: MPL-2.0

pub mod device;

use core::mem::offset_of;

use aster_block::SECTOR_SIZE;
use aster_util::safe_ptr::SafePtr;
use bitflags::bitflags;
use int_to_c_enum::TryFromInt;
use ostd_pod::FromZeros;

use crate::transport::{ConfigManager, VirtioTransport};

pub const DEVICE_NAME: &str = "Virtio-Block";

bitflags! {
    /// features for virtio block device
    struct BlockFeatures : u64 {
        const BARRIER       = 1 << 0;
        const SIZE_MAX      = 1 << 1;
        const SEG_MAX       = 1 << 2;
        const GEOMETRY      = 1 << 4;
        const RO            = 1 << 5;
        const BLK_SIZE      = 1 << 6;
        const SCSI          = 1 << 7;
        const FLUSH         = 1 << 9;
        const TOPOLOGY      = 1 << 10;
        const CONFIG_WCE    = 1 << 11;
        const MQ            = 1 << 12;
        const DISCARD       = 1 << 13;
        const WRITE_ZEROES  = 1 << 14;
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, TryFromInt)]
enum ReqType {
    In = 0,
    Out = 1,
    Flush = 4,
    GetId = 8,
    Discard = 11,
    WriteZeroes = 13,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, TryFromInt)]
enum RespStatus {
    /// Ok.
    Ok = 0,
    /// IoErr.
    IoErr = 1,
    /// Unsupported yet.
    Unsupported = 2,
    /// Not ready.
    _NotReady = 3,
}

#[padding_struct]
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
struct VirtioBlockConfig {
    /// The number of 512-byte sectors.
    capacity: u64,
    /// The maximum segment size.
    size_max: u32,
    /// The maximum number of segments.
    seg_max: u32,
    /// The geometry of the device.
    geometry: VirtioBlockGeometry,
    /// The block size. If `logical_block_size` is not given in qemu cmdline,
    /// `blk_size` will be set to sector size (512 bytes) by default.
    blk_size: u32,
    /// The topology of the device.
    topology: VirtioBlockTopology,
    /// Writeback mode.
    writeback: u8,
    unused0: u8,
    /// The number of virtqueues.
    num_queues: u16,
    /// The maximum discard sectors for one segment.
    max_discard_sectors: u32,
    /// The maximum number of discard segments in a discard command.
    max_discard_seg: u32,
    /// Discard commands must be aligned to this number of sectors.
    discard_sector_alignment: u32,
    /// The maximum number of write zeroes sectors in one segment.
    max_write_zeroes_sectors: u32,
    /// The maximum number of segments in a write zeroes command.
    max_write_zeroes_seg: u32,
    /// Set if a write zeroes command may result in the
    /// deallocation of one or more of the sectors.
    write_zeros_may_unmap: u8,
    unused1: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
struct VirtioBlockGeometry {
    cylinders: u16,
    heads: u8,
    sectors: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
struct VirtioBlockTopology {
    /// Exponent for physical block per logical block.
    physical_block_exp: u8,
    /// Alignment offset in logical blocks.
    alignment_offset: u8,
    /// Minimum I/O size without performance penalty in logical blocks.
    min_io_size: u16,
    /// Optimal sustained I/O size in logical blocks.
    opt_io_size: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct VirtioBlockFeature {
    support_flush: bool,
    support_size_max: bool,
    support_seg_max: bool,
    support_geometry: bool,
    support_blk_size: bool,
    support_topology: bool,
    support_config_wce: bool,
    support_mq: bool,
    support_discard: bool,
    support_write_zeroes: bool,
}

impl VirtioBlockConfig {
    pub(self) fn new_manager(transport: &dyn VirtioTransport) -> ConfigManager<Self> {
        let safe_ptr = transport
            .device_config_mem()
            .map(|mem| SafePtr::new(mem, 0));
        let bar_space = transport.device_config_bar();

        ConfigManager::new(safe_ptr, bar_space)
    }

    pub(self) const fn sector_size() -> usize {
        SECTOR_SIZE
    }
}

impl ConfigManager<VirtioBlockConfig> {
    pub(self) fn read_config(&self, features: VirtioBlockFeature) -> VirtioBlockConfig {
        let mut blk_config = VirtioBlockConfig::new_zeroed();
        // `capacity` always exists in both legacy and modern interfaces.
        let cap_low = self
            .read_once::<u32>(offset_of!(VirtioBlockConfig, capacity))
            .unwrap() as u64;
        let cap_high = self
            .read_once::<u32>(offset_of!(VirtioBlockConfig, capacity) + 4)
            .unwrap() as u64;
        blk_config.capacity = (cap_high << 32) | cap_low;

        if features.support_size_max {
            blk_config.size_max = self
                .read_once::<u32>(offset_of!(VirtioBlockConfig, size_max))
                .unwrap();
        }
        if features.support_seg_max {
            blk_config.seg_max = self
                .read_once::<u32>(offset_of!(VirtioBlockConfig, seg_max))
                .unwrap();
        }
        if features.support_geometry {
            blk_config.geometry.cylinders = self
                .read_once::<u16>(
                    offset_of!(VirtioBlockConfig, geometry)
                        + offset_of!(VirtioBlockGeometry, cylinders),
                )
                .unwrap();
            blk_config.geometry.heads = self
                .read_once::<u8>(
                    offset_of!(VirtioBlockConfig, geometry)
                        + offset_of!(VirtioBlockGeometry, heads),
                )
                .unwrap();
            blk_config.geometry.sectors = self
                .read_once::<u8>(
                    offset_of!(VirtioBlockConfig, geometry)
                        + offset_of!(VirtioBlockGeometry, sectors),
                )
                .unwrap();
        }
        if features.support_blk_size {
            blk_config.blk_size = self
                .read_once::<u32>(offset_of!(VirtioBlockConfig, blk_size))
                .unwrap();
        } else {
            blk_config.blk_size = VirtioBlockConfig::sector_size() as u32;
        }

        if self.is_modern() && features.support_topology {
            blk_config.topology.physical_block_exp = self
                .read_once::<u8>(
                    offset_of!(VirtioBlockConfig, topology)
                        + offset_of!(VirtioBlockTopology, physical_block_exp),
                )
                .unwrap();
            blk_config.topology.alignment_offset = self
                .read_once::<u8>(
                    offset_of!(VirtioBlockConfig, topology)
                        + offset_of!(VirtioBlockTopology, alignment_offset),
                )
                .unwrap();
            blk_config.topology.min_io_size = self
                .read_once::<u16>(
                    offset_of!(VirtioBlockConfig, topology)
                        + offset_of!(VirtioBlockTopology, min_io_size),
                )
                .unwrap();
            blk_config.topology.opt_io_size = self
                .read_once::<u32>(
                    offset_of!(VirtioBlockConfig, topology)
                        + offset_of!(VirtioBlockTopology, opt_io_size),
                )
                .unwrap();
        }
        if self.is_modern() && features.support_config_wce {
            blk_config.writeback = self
                .read_once::<u8>(offset_of!(VirtioBlockConfig, writeback))
                .unwrap();
        }
        if self.is_modern() && features.support_mq {
            blk_config.num_queues = self
                .read_once::<u16>(offset_of!(VirtioBlockConfig, num_queues))
                .unwrap();
        }
        if self.is_modern() && features.support_discard {
            blk_config.max_discard_sectors = self
                .read_once::<u32>(offset_of!(VirtioBlockConfig, max_discard_sectors))
                .unwrap();
            blk_config.max_discard_seg = self
                .read_once::<u32>(offset_of!(VirtioBlockConfig, max_discard_seg))
                .unwrap();
            blk_config.discard_sector_alignment = self
                .read_once::<u32>(offset_of!(VirtioBlockConfig, discard_sector_alignment))
                .unwrap();
        }
        if self.is_modern() && features.support_write_zeroes {
            blk_config.max_write_zeroes_sectors = self
                .read_once::<u32>(offset_of!(VirtioBlockConfig, max_write_zeroes_sectors))
                .unwrap();
            blk_config.max_write_zeroes_seg = self
                .read_once::<u32>(offset_of!(VirtioBlockConfig, max_write_zeroes_seg))
                .unwrap();
            blk_config.write_zeros_may_unmap = self
                .read_once::<u8>(offset_of!(VirtioBlockConfig, write_zeros_may_unmap))
                .unwrap();
        }

        blk_config
    }

    pub(self) fn capacity_sectors(&self) -> usize {
        let cap_low = self
            .read_once::<u32>(offset_of!(VirtioBlockConfig, capacity))
            .unwrap() as usize;
        let cap_high = self
            .read_once::<u32>(offset_of!(VirtioBlockConfig, capacity) + 4)
            .unwrap() as usize;

        (cap_high << 32) | cap_low
    }
}

impl VirtioBlockFeature {
    pub(self) fn new(transport: &dyn VirtioTransport) -> Self {
        let features = BlockFeatures::from_bits_truncate(transport.read_device_features());
        Self {
            support_flush: features.contains(BlockFeatures::FLUSH),
            support_size_max: features.contains(BlockFeatures::SIZE_MAX),
            support_seg_max: features.contains(BlockFeatures::SEG_MAX),
            support_geometry: features.contains(BlockFeatures::GEOMETRY),
            support_blk_size: features.contains(BlockFeatures::BLK_SIZE),
            support_topology: features.contains(BlockFeatures::TOPOLOGY),
            support_config_wce: features.contains(BlockFeatures::CONFIG_WCE),
            support_mq: features.contains(BlockFeatures::MQ),
            support_discard: features.contains(BlockFeatures::DISCARD),
            support_write_zeroes: features.contains(BlockFeatures::WRITE_ZEROES),
        }
    }
}
