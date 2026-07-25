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

use core::num::NonZeroUsize;

use aster_block::BlockDevice;
use device_id::DeviceId;
use lru::LruCache;
use spin::Once;

use super::{
    SquashfsError,
    compressor::DecompressContext,
    dir::{self, SquashDirEntry},
    fragment::{self, FragmentEntry},
    impl_for_vfs::inode::{SquashFsInode, decompress_raw_block_data, decompress_raw_fragment_data},
    inode::{self, BlockSizeInfo, InodeBody, ParsedInode},
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
///
/// The global `block_cache` holds recently decompressed data blocks
/// and fragment blocks, shared across all file inodes. This avoids
/// per-inode duplication and provides a system-wide memory bound.
pub(crate) struct SquashFs {
    device: Arc<dyn BlockDevice>,
    pub(super) super_block: SuperBlock,
    pub(super) inodes: BTreeMap<u32, ParsedInode>,
    pub(super) dir_entries: BTreeMap<u32, Vec<SquashDirEntry>>,
    pub(super) fragments: Vec<FragmentEntry>,
    root_inode_num: u32,
    decompress: DecompressContext,
    anon_device_id: AnonDeviceId,
    root_inode: Once<Arc<dyn Inode>>,
    inode_cache: RwMutex<BTreeMap<u32, Weak<dyn Inode>>>,
    block_cache: Mutex<LruCache<BlockCacheKey, Arc<Vec<u8>>>>,
    pub(super) fs_event_subscriber_stats: FsEventSubscriberStats,
}

/// Maximum number of decompressed blocks cached globally across all files.
///
/// Each entry holds up to one squashfs block (typically 128 KB).
/// With 8 entries the worst-case memory bound is ~1 MB.
const BLOCK_CACHE_CAPACITY: usize = 8;

/// Key for the global decompressed-block LRU cache.
///
/// Data blocks are unique per (inode, block-index) pair because
/// each file stores its data blocks at different on-disk locations.
/// Fragment blocks are unique per `frag_index` — multiple files may
/// share the same fragment block, so caching by `frag_index` avoids
/// redundant decompression across files.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(super) enum BlockCacheKey {
    /// A regular data block within a file.
    DataBlock {
        /// Inode number (identifies the file).
        ino: u32,
        /// Block index within that file (0-based).
        block_idx: usize,
    },
    /// A fragment block, identified by its fragment-table index.
    FragmentBlock {
        /// Index into the fragment table.
        frag_index: u32,
    },
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
            let raw = metadata::read_lookup_table_raw(
                &device,
                super_block.frag_table,
                size_of::<fragment::RawFragment>(),
                super_block.frag_count as u64,
                &decompress,
            )?;
            fragment::parse_fragment_table(&raw)?
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

        let fs = Arc::new(SquashFs {
            device,
            super_block,
            inodes,
            dir_entries,
            fragments,
            root_inode_num,
            decompress,
            anon_device_id,
            root_inode: Once::new(),
            inode_cache: RwMutex::new(BTreeMap::new()),
            block_cache: Mutex::new(LruCache::new(
                NonZeroUsize::new(BLOCK_CACHE_CAPACITY).unwrap(),
            )),
            fs_event_subscriber_stats: FsEventSubscriberStats::new(),
        });

        let root = fs.get_or_create_inode(fs.root_inode_num)?;
        fs.root_inode.call_once(|| root);

        Ok(fs)
    }

    /// Returns the device ID assigned to this filesystem instance.
    pub(super) fn container_device_id(&self) -> DeviceId {
        self.anon_device_id.id()
    }

    /// Returns the root inode of the filesystem.
    ///
    /// The root inode is eagerly created at mount time, so this always
    /// returns a clone of the cached `Arc` without fallible operations.
    pub(super) fn root_inode(&self) -> Arc<dyn Inode> {
        self.root_inode
            .get()
            .expect("root inode must be initialised at mount time")
            .clone()
    }

    /// Returns a cached inode, creating one if it is not already in the cache
    /// or the previous instance has been dropped.
    pub(super) fn get_or_create_inode(
        self: &Arc<SquashFs>,
        ino: u32,
    ) -> core::result::Result<Arc<dyn Inode>, Error> {
        if let Some(inode) = self.inode_cache.read().get(&ino).and_then(Weak::upgrade) {
            return Ok(inode);
        }

        let mut cache = self.inode_cache.write();
        if let Some(inode) = cache.get(&ino).and_then(Weak::upgrade) {
            return Ok(inode);
        }

        let parsed = self
            .inodes
            .get(&ino)
            .ok_or_else(|| Error::with_message(Errno::ENOENT, "inode not found"))?;
        let inode = SquashFsInode::new_inode(
            parsed.meta.ino,
            parsed.body.clone(),
            parsed.meta.clone(),
            Arc::downgrade(self),
            self.container_device_id(),
        );
        cache.insert(ino, Arc::downgrade(&inode));
        Ok(inode)
    }

    /// Returns a decompressed data block from the global cache,
    /// decompressing it on demand if not already cached.
    ///
    /// The block is keyed by `(ino, block_idx)` so different files'
    /// blocks are cached independently.
    pub(super) fn get_or_decompress_data_block(
        &self,
        ino: u32,
        block_idx: usize,
        blocks_start: u64,
        block_sizes: &[BlockSizeInfo],
        file_size: usize,
    ) -> Result<Arc<Vec<u8>>> {
        let cache_key = BlockCacheKey::DataBlock { ino, block_idx };

        {
            let mut cache = self.block_cache.lock();
            if let Some(data) = cache.get(&cache_key) {
                return Ok(data.clone());
            }
        }

        let disk_pos = blocks_start
            + block_sizes[..block_idx]
                .iter()
                .map(|b| b.size as u64)
                .sum::<u64>();

        let data = Arc::new(decompress_raw_block_data(
            &*self.device,
            &self.decompress,
            disk_pos,
            block_sizes,
            self.super_block.block_size,
            file_size,
            block_idx,
        )?);

        let mut cache = self.block_cache.lock();
        cache.put(cache_key, data.clone());
        Ok(data)
    }

    /// Returns a decompressed fragment block from the global cache,
    /// decompressing it on demand if not already cached.
    ///
    /// Fragment blocks are keyed by `frag_index` only, because
    /// multiple files may share the same fragment block. This avoids
    /// redundant decompression when several small files reference
    /// the same fragment.
    pub(super) fn get_or_decompress_fragment_block(&self, frag_index: u32) -> Result<Arc<Vec<u8>>> {
        let cache_key = BlockCacheKey::FragmentBlock { frag_index };

        {
            let mut cache = self.block_cache.lock();
            if let Some(data) = cache.get(&cache_key) {
                return Ok(data.clone());
            }
        }

        let data = Arc::new(decompress_raw_fragment_data(
            &*self.device,
            &self.decompress,
            &self.fragments,
            frag_index,
        )?);

        let mut cache = self.block_cache.lock();
        cache.put(cache_key, data.clone());
        Ok(data)
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
