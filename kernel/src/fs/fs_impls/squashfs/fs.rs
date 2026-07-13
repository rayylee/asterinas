// SPDX-License-Identifier: MPL-2.0

//! Core Squashfs filesystem structure and mount logic.
//!
//! The `SquashFs` struct holds all in-memory state for a mounted
//! Squashfs image: the superblock, all parsed inodes, all directory
//! entries, the fragment table, and the decompression context.
//!
//! Mounting is done eagerly: all inode and directory metadata is
//! read and decompressed at mount time. File data is read on-demand
//! through the page cache.

use aster_block::BlockDevice;
use device_id::DeviceId;

use super::{
    SquashfsError,
    compressor::DecompressContext,
    dir::{self, SquashDirEntry},
    fragment::RawFragment,
    impl_for_vfs::inode::SquashFsInode,
    inode::{self, InodeBody, ParsedInode},
    metadata,
    super_block::SuperBlock,
};
use crate::{
    fs::{
        fs_impls::pseudofs::AnonDeviceId,
        vfs::{file_system::FsEventSubscriberStats, inode::Inode},
    },
    prelude::*,
};

/// Indicates that an optional table (xattr, fragment, or export) is not
/// present in the filesystem image. When a superblock field equals this
/// value, the corresponding table is omitted and must not be read.
///
/// Reference:
/// <https://dr-emann.github.io/squashfs/squashfs.html#_the_superblock>
/// <https://elixir.bootlin.com/linux/v7.0/source/fs/squashfs/squashfs_fs.h#L40>
const INVALID_BLK: u64 = 0xffffffffffffffff;

/// In-memory representation of a mounted Squashfs filesystem.
///
/// All inode and directory metadata is eagerly loaded into `inodes`
/// and `dir_entries` at mount time. File data is read on-demand.
pub(crate) struct SquashFs {
    pub(super) device: Arc<dyn BlockDevice>,
    pub(super) super_block: SuperBlock,
    pub(super) inodes: BTreeMap<u32, ParsedInode>,
    pub(super) dir_entries: BTreeMap<u32, Vec<SquashDirEntry>>,
    pub(super) fragments: Vec<RawFragment>,
    root_inode_num: u32,
    pub(super) decompress: DecompressContext,
    anon_device_id: AnonDeviceId,
    self_ref: Weak<SquashFs>,
    pub(super) fs_event_subscriber_stats: FsEventSubscriberStats,
}

impl SquashFs {
    /// Opens a Squashfs image from a block device.
    ///
    /// The mount sequence:
    /// 1. Read and validate the superblock
    /// 2. Read the UID/GID lookup table
    /// 3. Read and decompress all inode metadata blocks
    /// 4. Parse all inodes
    /// 5. Locate the root inode
    /// 6. Read and decompress all directory metadata blocks
    /// 7. Parse all directory entries
    /// 8. Read the fragment table (if present)
    pub(super) fn open(device: Arc<dyn BlockDevice>) -> Result<Arc<Self>> {
        let super_block = SuperBlock::read(&device, 0)?;
        let decompress = DecompressContext::new(super_block.compressor);

        let ids = metadata::read_id_table(
            &device,
            super_block.id_table,
            super_block.id_count,
            &decompress,
        )?;

        let (inode_offset_map, inode_data) = metadata::read_all_metadata_blocks(
            &device,
            super_block.inode_table,
            super_block.dir_table,
            &decompress,
        )?;

        let inodes = inode::parse_all_inodes(&inode_data, super_block.block_size, &ids)?;

        let root_inode_num = {
            let root_block = super_block.root_inode >> 16;
            let root_offset = (super_block.root_inode & 0xffff) as usize;
            let data_off = inode_offset_map
                .get(&root_block)
                .copied()
                .ok_or(SquashfsError::CorruptedImage("root inode block not found"))?
                as usize;
            let (root_parsed, _) = inode::parse_single_inode(
                &inode_data,
                data_off + root_offset,
                super_block.block_size,
                &ids,
            )?;
            root_parsed.meta.ino
        };

        let dir_end = if super_block.frag_table != INVALID_BLK {
            super_block.frag_table
        } else if super_block.export_table != INVALID_BLK {
            super_block.export_table
        } else {
            super_block.id_table
        };

        let (dir_offset_map, dir_data) = metadata::read_all_metadata_blocks(
            &device,
            super_block.dir_table,
            dir_end,
            &decompress,
        )?;

        let fragments = if super_block.frag_count > 0 && super_block.frag_table != INVALID_BLK {
            metadata::read_fragment_table(
                &device,
                super_block.frag_table,
                super_block.frag_count,
                &decompress,
            )?
        } else {
            Vec::new()
        };

        let mut dir_entries: BTreeMap<u32, Vec<SquashDirEntry>> = BTreeMap::new();
        for (&ino, parsed) in &inodes {
            if let InodeBody::Dir {
                block_index,
                file_size,
                block_offset,
            } = &parsed.body
                && let Some(dir) = dir::parse_dirs(
                    &dir_offset_map,
                    &dir_data,
                    *block_index as u64,
                    *file_size,
                    *block_offset,
                )?
            {
                dir_entries.insert(ino, dir.entries);
            }
        }

        let anon_device_id = AnonDeviceId::acquire()
            .ok_or_else(|| Error::with_message(Errno::ENOMEM, "no device ID available"))?;

        info!(
            "SquashFS: {} inodes, {} dirs, {} fragments, block_size={}",
            inodes.len(),
            dir_entries.len(),
            fragments.len(),
            super_block.block_size,
        );

        let fs = Arc::new_cyclic(|weak_self| SquashFs {
            device,
            super_block,
            inodes,
            dir_entries,
            fragments,
            root_inode_num,
            decompress,
            anon_device_id,
            self_ref: weak_self.clone(),
            fs_event_subscriber_stats: FsEventSubscriberStats::new(),
        });

        Ok(fs)
    }

    /// Returns the device ID assigned to this filesystem instance.
    pub(super) fn container_device_id(&self) -> DeviceId {
        self.anon_device_id.id()
    }

    /// Returns the root inode of the filesystem.
    pub(super) fn root_inode(&self) -> core::result::Result<Arc<dyn Inode>, Error> {
        let parsed = self
            .inodes
            .get(&self.root_inode_num)
            .ok_or_else(|| Error::with_message(Errno::EIO, "root inode not found"))?;
        Ok(SquashFsInode::new_inode(
            parsed.meta.ino,
            parsed.body.clone(),
            parsed.meta.clone(),
            self.self_ref.clone(),
            self.container_device_id(),
        ))
    }
}

impl Debug for SquashFs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SquashFs")
            .field("sb", &self.super_block)
            .field("inodes", &self.inodes.len())
            .field("dirs", &self.dir_entries.len())
            .finish()
    }
}
