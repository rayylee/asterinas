// SPDX-License-Identifier: MPL-2.0

//! VFS inode trait implementations for Squashfs.
//!
//! Wires the Squashfs inode into the VFS layer by implementing
//! [`FileOps`], [`Inode`], and [`PageCacheBackend`] traits.
//!
//! # File data reading
//!
//! Regular file data is read via the [`FileReader`] struct, which handles:
//! - Reading and decompressing individual data blocks
//! - Reading tail-end fragment blocks
//! - Sparse block handling (zero-fill for blocks with size 0)
//!
//! The page cache uses [`SquashFsPageCacheBackend`] for on-demand page filling.

use core::{num::NonZeroUsize, ops::Deref, time::Duration};

use aster_block::BlockDevice;
use device_id::DeviceId;
use io_util::batch::IoBatch;
use lru::LruCache;
use ostd::mm::{Segment, VmIo};
use spin::Once;

use super::super::{
    SquashFs,
    compressor::DecompressContext,
    fragment::RawFragment,
    inode::{BlockSizeInfo, INVALID_FRAG, InodeBody, InodeId, InodeMeta},
};
use crate::{
    device,
    fs::{
        file::{AccessMode, InodeMode, InodeType, PerOpenFileOps, StatusFlags},
        utils::DirentVisitor,
        vfs::{
            file_system::FileSystem,
            inode::{
                Extension, FallocMode, FileOps, Inode, Metadata, MknodType, RenameMode,
                SymbolicLink,
            },
        },
    },
    prelude::*,
    process::{Gid, Uid},
    vm::page_cache::{LockedCachePage, PageCache, PageCacheBackend},
};

/// VFS-level inode representing a single entry in a Squashfs filesystem.
///
/// Holds the parsed inode body, metadata, and a weak reference to the
/// owning [`SquashFs`] filesystem. The page cache is lazily initialised on first access.
pub(crate) struct SquashFsInode {
    ino: u32,
    body: InodeBody,
    meta: InodeMeta,
    fs: Weak<SquashFs>,
    extension: Extension,
    container_dev_id: DeviceId,
    /// Lazily-created page cache for regular files.
    page_cache: Once<Option<PageCache>>,
    /// Lazily-created page cache backend for regular files.
    page_cache_backend: Once<Option<Arc<dyn PageCacheBackend>>>,
}

impl SquashFsInode {
    pub(crate) fn new_inode(
        ino: u32,
        body: InodeBody,
        meta: InodeMeta,
        fs: Weak<SquashFs>,
        container_dev_id: DeviceId,
    ) -> Arc<dyn Inode> {
        Arc::new(Self {
            ino,
            body,
            meta,
            fs,
            extension: Extension::new(),
            container_dev_id,
            page_cache: Once::new(),
            page_cache_backend: Once::new(),
        })
    }

    fn fs(&self) -> Result<Arc<SquashFs>> {
        self.fs
            .upgrade()
            .ok_or_else(|| Error::with_message(Errno::EIO, "filesystem is unmounted"))
    }

    fn inode_type(&self) -> InodeType {
        match &self.body {
            InodeBody::Dir { .. } => InodeType::Dir,
            InodeBody::File { .. } => InodeType::File,
            InodeBody::Symlink { .. } => InodeType::SymLink,
            InodeBody::BlockDevice { .. } => InodeType::BlockDevice,
            InodeBody::CharDevice { .. } => InodeType::CharDevice,
            InodeBody::NamedPipe => InodeType::NamedPipe,
            InodeBody::Socket => InodeType::Socket,
        }
    }
}

impl Debug for SquashFsInode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SquashFsInode")
            .field("ino", &self.ino)
            .field("type", &self.inode_type())
            .finish()
    }
}

impl FileOps for SquashFsInode {
    fn read_at(
        &self,
        offset: usize,
        writer: &mut VmWriter,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        let size = self.body.file_size() as usize;
        if offset >= size {
            return Ok(0);
        }

        let read_len = writer.avail().min(size - offset);
        if read_len == 0 {
            return Ok(0);
        }

        let fs = self.fs()?;

        match &self.body {
            InodeBody::File {
                blocks_start,
                frag_index,
                block_offset,
                file_size: _,
                block_sizes,
            } => {
                let reader = FileReader {
                    device: &fs.device,
                    decompress: &fs.decompress,
                    blocks_start: *blocks_start,
                    frag_index: *frag_index,
                    block_offset: *block_offset,
                    block_size: fs.super_block.block_size,
                    block_sizes,
                    fragments: &fs.fragments,
                    file_size: size,
                };
                reader.read(offset, read_len, writer)
            }
            _ => Ok(0),
        }
    }

    fn write_at(
        &self,
        _offset: usize,
        _reader: &mut VmReader,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        return_errno_with_message!(Errno::EROFS, "SquashFS is read-only")
    }

    fn readdir_at(&self, offset: usize, visitor: &mut dyn DirentVisitor) -> Result<usize> {
        if !self.body.is_dir() {
            return_errno_with_message!(Errno::ENOTDIR, "not a directory")
        }

        let fs = self.fs()?;
        let entries = fs.dir_entries.get(&self.ino);

        let Some(entries) = entries else {
            return Ok(0);
        };

        if offset >= entries.len() {
            return Ok(0);
        }

        let mut count = 0;
        for (i, entry) in entries.iter().enumerate().skip(offset) {
            let child_type = squash_inodeid_to_vfs_type(entry.inode_type);
            let name = core::str::from_utf8(&entry.name).unwrap_or("");
            visitor.visit(name, entry.inode_num as u64, child_type, i + 1)?;
            count += 1;
        }

        Ok(count)
    }
}

impl Inode for SquashFsInode {
    fn size(&self) -> usize {
        self.body.file_size() as usize
    }

    fn resize(&self, _new_size: usize) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "SquashFS is read-only")
    }

    fn metadata(&self) -> Metadata {
        let self_dev_id = match self.inode_type() {
            InodeType::BlockDevice | InodeType::CharDevice => {
                let device_number = match &self.body {
                    InodeBody::BlockDevice { device_number }
                    | InodeBody::CharDevice { device_number } => *device_number,
                    _ => unreachable!(),
                };
                DeviceId::from_encoded_u64(device_number as u64)
            }
            _ => None,
        };
        Metadata {
            ino: self.ino as u64,
            size: self.size(),
            optimal_block_size: self
                .fs
                .upgrade()
                .map_or(4096, |fs| fs.super_block.block_size as usize),
            nr_sectors_allocated: self.size().div_ceil(512),
            last_access_at: Duration::from_secs(self.meta.mtime as u64),
            last_modify_at: Duration::from_secs(self.meta.mtime as u64),
            last_meta_change_at: Duration::from_secs(self.meta.mtime as u64),
            type_: self.inode_type(),
            mode: InodeMode::from_bits_truncate(self.meta.permissions),
            nr_hard_links: match self.inode_type() {
                InodeType::Dir => 2,
                _ => 1,
            },
            uid: Uid::new(self.meta.uid),
            gid: Gid::new(self.meta.gid),
            container_dev_id: self.container_dev_id,
            self_dev_id,
            birth_at: None,
        }
    }

    fn ino(&self) -> u64 {
        self.ino as u64
    }

    fn type_(&self) -> InodeType {
        self.inode_type()
    }

    fn mode(&self) -> Result<InodeMode> {
        Ok(InodeMode::from_bits_truncate(self.meta.permissions))
    }

    fn set_mode(&self, _mode: InodeMode) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "SquashFS is read-only")
    }

    fn owner(&self) -> Result<Uid> {
        Ok(Uid::new(self.meta.uid))
    }

    fn set_owner(&self, _uid: Uid) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "SquashFS is read-only")
    }

    fn group(&self) -> Result<Gid> {
        Ok(Gid::new(self.meta.gid))
    }

    fn set_group(&self, _gid: Gid) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "SquashFS is read-only")
    }

    fn atime(&self) -> Duration {
        Duration::from_secs(self.meta.mtime as u64)
    }

    fn set_atime(&self, _time: Duration) {}

    fn mtime(&self) -> Duration {
        Duration::from_secs(self.meta.mtime as u64)
    }

    fn set_mtime(&self, _time: Duration) {}

    fn ctime(&self) -> Duration {
        Duration::from_secs(self.meta.mtime as u64)
    }

    fn set_ctime(&self, _time: Duration) {}

    fn page_cache(&self) -> Option<PageCache> {
        let InodeBody::File {
            blocks_start,
            frag_index,
            block_offset,
            file_size,
            block_sizes,
        } = &self.body
        else {
            return None;
        };
        if *file_size == 0 {
            return None;
        }

        let backend_opt = self.page_cache_backend.call_once(|| {
            let fs = self.fs().ok()?;
            Some(Arc::new(SquashFsPageCacheBackend {
                device: fs.device.clone(),
                decompress: fs.decompress,
                blocks_start: *blocks_start,
                frag_index: *frag_index,
                block_offset: *block_offset,
                block_size: fs.super_block.block_size,
                block_sizes: block_sizes.clone(),
                fragments: fs.fragments.clone(),
                file_size: *file_size as usize,
                block_cache: Mutex::new(LruCache::new(
                    NonZeroUsize::new(BLOCK_CACHE_CAPACITY).unwrap(),
                )),
            }) as Arc<dyn PageCacheBackend>)
        });
        // Bail out early if the page cache backend hasn't been initialised.
        let _backend = backend_opt.as_ref()?;

        let pg_cache_opt = self.page_cache.call_once(|| {
            let backend = self.page_cache_backend.get().unwrap().as_ref()?;
            PageCache::new_with_backend(*file_size as usize, Arc::downgrade(backend)).ok()
        });
        pg_cache_opt.clone()
    }

    fn open(
        &self,
        _access_mode: AccessMode,
        _status_flags: StatusFlags,
    ) -> Option<Result<Box<dyn PerOpenFileOps>>> {
        match self.inode_type() {
            inode_type @ (InodeType::BlockDevice | InodeType::CharDevice) => {
                let device_id = match &self.body {
                    InodeBody::BlockDevice { device_number }
                    | InodeBody::CharDevice { device_number } => *device_number,
                    _ => return None,
                };
                let device_id = DeviceId::from_encoded_u64(device_id as u64)?;
                let device_type = inode_type
                    .device_type()
                    .expect("BlockDevice and CharDevice always have a device type");
                let dev = device::lookup(device_type, device_id)?;
                Some(dev.open())
            }
            _ => None,
        }
    }

    fn create(&self, _name: &str, _type_: InodeType, _mode: InodeMode) -> Result<Arc<dyn Inode>> {
        return_errno_with_message!(Errno::EROFS, "SquashFS is read-only")
    }

    fn mknod(&self, _name: &str, _mode: InodeMode, _type_: MknodType) -> Result<Arc<dyn Inode>> {
        return_errno_with_message!(Errno::EROFS, "SquashFS is read-only")
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>> {
        if !self.body.is_dir() {
            return_errno_with_message!(Errno::ENOTDIR, "not a directory")
        }

        let fs = self.fs()?;
        let entries = fs
            .dir_entries
            .get(&self.ino)
            .ok_or_else(|| Error::with_message(Errno::ENOENT, "directory not found"))?;

        let target_entry = entries
            .iter()
            .find(|e| {
                if let Ok(n) = core::str::from_utf8(&e.name) {
                    n == name
                } else {
                    false
                }
            })
            .ok_or_else(|| Error::with_message(Errno::ENOENT, "entry not found"))?;

        fs.get_or_create_inode(target_entry.inode_num)
    }

    fn link(&self, _old: &Arc<dyn Inode>, _name: &str) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "SquashFS is read-only")
    }

    fn unlink(&self, _name: &str) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "SquashFS is read-only")
    }

    fn rmdir(&self, _name: &str) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "SquashFS is read-only")
    }

    fn rename(
        &self,
        _old_name: &str,
        _target: &Arc<dyn Inode>,
        _new_name: &str,
        _mode: RenameMode,
    ) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "SquashFS is read-only")
    }

    fn read_link(&self) -> Result<SymbolicLink> {
        match &self.body {
            InodeBody::Symlink { target } => {
                let target = core::str::from_utf8(target)
                    .map_err(|_| Error::with_message(Errno::EIO, "invalid symlink target"))?;
                Ok(SymbolicLink::Plain(target.to_string()))
            }
            _ => return_errno_with_message!(Errno::EINVAL, "not a symlink"),
        }
    }

    fn write_link(&self, _target: &str) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "SquashFS is read-only")
    }

    fn sync_all(&self) -> Result<()> {
        Ok(())
    }

    fn sync_data(&self) -> Result<()> {
        Ok(())
    }

    fn fallocate(&self, _mode: FallocMode, _offset: usize, _len: usize) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "SquashFS is read-only")
    }

    fn fs(&self) -> Arc<dyn FileSystem> {
        // Safe: inodes are only reachable while the filesystem is mounted,
        // which keeps the `Arc<SquashFs>` alive.
        self.fs().unwrap()
    }

    fn extension(&self) -> &Extension {
        &self.extension
    }
}

/// Convert a Squashfs inode type to the VFS inode type.
fn squash_inodeid_to_vfs_type(id: InodeId) -> InodeType {
    match id {
        InodeId::BasicDirectory | InodeId::ExtendedDirectory => InodeType::Dir,
        InodeId::BasicFile | InodeId::ExtendedFile => InodeType::File,
        InodeId::BasicSymlink => InodeType::SymLink,
        InodeId::BasicBlockDevice => InodeType::BlockDevice,
        InodeId::BasicCharacterDevice => InodeType::CharDevice,
        InodeId::BasicNamedPipe => InodeType::NamedPipe,
        InodeId::BasicSocket => InodeType::Socket,
    }
}

/// Holds all file metadata needed to read data blocks from a Squashfs file.
///
/// Regular files in Squashfs consist of a sequence of contiguous compressed
/// blocks on disk, optionally followed by a tail-end fragment. Data blocks
/// may be sparse (size 0 bytes, meaning the block is all zeroes).
struct FileReader<'a> {
    device: &'a Arc<dyn BlockDevice>,
    decompress: &'a DecompressContext,
    /// On-disk offset of the first data block.
    blocks_start: u64,
    /// Index into the fragment table, or `INVALID_FRAG` if no fragment.
    frag_index: u32,
    /// Byte offset of this file's data within the fragment block.
    block_offset: u32,
    /// Data block size in bytes.
    block_size: u32,
    /// Per-block size and compression info.
    block_sizes: &'a [BlockSizeInfo],
    /// Fragment table entries.
    fragments: &'a [RawFragment],
    /// Uncompressed file size in bytes.
    file_size: usize,
}

impl FileReader<'_> {
    /// Reads a range of bytes from the file into the writer.
    ///
    /// Handles:
    /// - Sparse blocks (size 0): fills with zeroes
    /// - Compressed blocks: reads from disk and decompresses
    /// - Uncompressed blocks: reads raw data from disk
    /// - Fragment blocks: reads and optionally decompresses the tail-end fragment
    fn read(&self, offset: usize, read_len: usize, writer: &mut VmWriter) -> Result<usize> {
        let bs = self.block_size as usize;
        let start_block = offset / bs;
        let end_byte = offset + read_len;
        let end_block = end_byte.div_ceil(bs);
        let nblocks = self.block_sizes.len();

        let mut total_written = 0;

        let mut disk_pos = self.blocks_start
            + self.block_sizes[..start_block]
                .iter()
                .map(|b| b.size as u64)
                .sum::<u64>();

        for block_idx in start_block..end_block.min(nblocks) {
            let block_start_byte = block_idx * bs;
            let info = &self.block_sizes[block_idx];
            let compressed_size = info.size as usize;

            // A block with on-disk size 0 is a sparse block (all zeros).
            // SquashFS omits such blocks entirely to save disk space.
            if compressed_size == 0 {
                let remain = writer.avail();
                let file_bytes_left = self.file_size.saturating_sub(block_start_byte);
                let valid_block_len = bs.min(file_bytes_left);
                let block_off = offset.saturating_sub(block_start_byte);
                let to_copy = valid_block_len.saturating_sub(block_off).min(remain);
                let copied = writer.fill_zeros(to_copy).unwrap_or_else(|(_, n)| n);
                total_written += copied;
                continue;
            }

            let mut compressed = vec![0u8; compressed_size];
            self.device
                .read_bytes(disk_pos as usize, &mut compressed)
                .map_err(|_| Error::with_message(Errno::EIO, "failed to read block"))?;
            disk_pos += compressed_size as u64;

            let block_data = if info.compressed {
                let mut out = Vec::with_capacity(bs);
                self.decompress
                    .decompress(&compressed, &mut out)
                    .map_err(|_| Error::with_message(Errno::EIO, "decompression failed"))?;
                out.truncate(bs);
                out
            } else {
                compressed
            };

            let remain = writer.avail();
            let file_bytes_left = self.file_size.saturating_sub(block_start_byte);
            let valid_block_len = block_data.len().min(file_bytes_left);
            let block_off = offset.saturating_sub(block_start_byte);
            let start = block_off.min(valid_block_len);
            let to_copy = valid_block_len.saturating_sub(start).min(remain);
            if to_copy > 0 {
                let mut reader = VmReader::from(&block_data[start..start + to_copy]);
                let copied = writer
                    .write_fallible(&mut reader)
                    .unwrap_or_else(|(_, n)| n);
                total_written += copied;
            }
        }

        if end_block > nblocks
            && self.frag_index != INVALID_FRAG
            && self.frag_index < self.fragments.len() as u32
        {
            let frag = &self.fragments[self.frag_index as usize];
            let frag_size = frag.size() as usize;

            let frag_compressed = if frag_size > 0 {
                let mut buf = vec![0u8; frag_size];
                self.device
                    .read_bytes(frag.start() as usize, &mut buf)
                    .map_err(|_| Error::with_message(Errno::EIO, "failed to read fragment"))?;
                buf
            } else {
                Vec::new()
            };

            let full_frag_data = if frag.is_compressed() {
                let mut out = Vec::new();
                self.decompress
                    .decompress(&frag_compressed, &mut out)
                    .map_err(|_| {
                        Error::with_message(Errno::EIO, "fragment decompression failed")
                    })?;
                out
            } else {
                frag_compressed
            };

            let bytes_before_frag = nblocks * bs;
            let bo = self.block_offset as usize;
            let file_frag_len = if bo < full_frag_data.len() {
                full_frag_data
                    .len()
                    .saturating_sub(bo)
                    .min(self.file_size.saturating_sub(bytes_before_frag))
            } else {
                0
            };
            let frag_read_offset = offset.saturating_sub(bytes_before_frag);
            let remain = writer.avail();
            let to_copy = file_frag_len.saturating_sub(frag_read_offset).min(remain);
            if to_copy > 0 {
                let start = bo + frag_read_offset.min(file_frag_len);
                if start + to_copy <= full_frag_data.len() {
                    let mut reader = VmReader::from(&full_frag_data[start..start + to_copy]);
                    let copied = writer
                        .write_fallible(&mut reader)
                        .unwrap_or_else(|(_, n)| n);
                    total_written += copied;
                }
            }
        }

        Ok(total_written)
    }
}

/// Page cache backend for regular files in Squashfs.
///
/// Maintains an LRU cache of decompressed data blocks so that multiple
/// 4 KB pages covered by the same compressed block (typically 128 KB)
/// share a single disk-read + decompression. Writes are rejected (read-only).
struct SquashFsPageCacheBackend {
    device: Arc<dyn BlockDevice>,
    decompress: DecompressContext,
    blocks_start: u64,
    frag_index: u32,
    block_offset: u32,
    block_size: u32,
    block_sizes: Vec<BlockSizeInfo>,
    fragments: Vec<RawFragment>,
    file_size: usize,
    /// LRU cache of decompressed blocks keyed by block index.
    /// `usize::MAX` is reserved for the fragment block.
    block_cache: Mutex<LruCache<usize, Arc<Vec<u8>>>>,
}

const BLOCK_CACHE_CAPACITY: usize = 8;
const FRAGMENT_CACHE_KEY: usize = usize::MAX;

impl SquashFsPageCacheBackend {
    fn decompress_block(&self, block_idx: usize) -> Result<Arc<Vec<u8>>> {
        let info = &self.block_sizes[block_idx];
        let compressed_size = info.size as usize;

        if compressed_size == 0 {
            let bs = self.block_size as usize;
            let file_bytes_left = self.file_size.saturating_sub(block_idx * bs);
            return Ok(Arc::new(vec![0u8; bs.min(file_bytes_left)]));
        }

        let disk_pos = self.blocks_start
            + self.block_sizes[..block_idx]
                .iter()
                .map(|b| b.size as u64)
                .sum::<u64>();

        let mut compressed = vec![0u8; compressed_size];
        self.device
            .read_bytes(disk_pos as usize, &mut compressed)
            .map_err(|_| Error::with_message(Errno::EIO, "failed to read block"))?;

        let data = if info.compressed {
            let bs = self.block_size as usize;
            let mut out = Vec::with_capacity(bs);
            self.decompress
                .decompress(&compressed, &mut out)
                .map_err(|_| Error::with_message(Errno::EIO, "decompression failed"))?;
            out.truncate(bs);
            out
        } else {
            compressed
        };
        Ok(Arc::new(data))
    }

    fn decompress_fragment(&self) -> Result<Arc<Vec<u8>>> {
        let frag = &self.fragments[self.frag_index as usize];
        let frag_size = frag.size() as usize;

        if frag_size == 0 {
            return Ok(Arc::new(Vec::new()));
        }

        let mut raw = vec![0u8; frag_size];
        self.device
            .read_bytes(frag.start() as usize, &mut raw)
            .map_err(|_| Error::with_message(Errno::EIO, "failed to read fragment"))?;

        let data = if frag.is_compressed() {
            let mut out = Vec::new();
            self.decompress
                .decompress(&raw, &mut out)
                .map_err(|_| Error::with_message(Errno::EIO, "fragment decompression failed"))?;
            out
        } else {
            raw
        };
        Ok(Arc::new(data))
    }

    fn get_or_decompress(&self, cache_key: usize) -> Result<Arc<Vec<u8>>> {
        {
            let mut cache = self.block_cache.lock();
            if let Some(data) = cache.get(&cache_key) {
                return Ok(data.clone());
            }
        }

        let data = if cache_key == FRAGMENT_CACHE_KEY {
            self.decompress_fragment()?
        } else {
            self.decompress_block(cache_key)?
        };

        let mut cache = self.block_cache.lock();
        cache.put(cache_key, data.clone());
        Ok(data)
    }
}

impl PageCacheBackend for SquashFsPageCacheBackend {
    // TODO: Synchronous — `io_batch` unused. The page cache read path
    // waits per-page anyway; async gains require batched readahead.
    fn read_page_async(
        &self,
        idx: usize,
        locked_page: LockedCachePage,
        _io_batch: &mut IoBatch,
    ) -> Result<()> {
        let offset = idx
            .checked_mul(PAGE_SIZE)
            .ok_or_else(|| Error::with_message(Errno::EINVAL, "page index out of bounds"))?;
        if offset >= self.file_size {
            return Err(Error::with_message(
                Errno::EINVAL,
                "page index out of bounds",
            ));
        }

        let read_len = PAGE_SIZE.min(self.file_size - offset);
        let bs = self.block_size as usize;
        let nblocks = self.block_sizes.len();

        let mut buf = vec![0u8; PAGE_SIZE];
        let mut buf_pos = 0;
        let mut file_pos = offset;

        while buf_pos < read_len {
            let cur_block = file_pos / bs;
            let in_fragment = cur_block >= nblocks;

            if in_fragment {
                if self.frag_index == INVALID_FRAG
                    || self.frag_index >= self.fragments.len() as u32
                {
                    break;
                }
                let frag_data = self.get_or_decompress(FRAGMENT_CACHE_KEY)?;
                let bytes_before_frag = nblocks * bs;
                let bo = self.block_offset as usize;
                let frag_file_offset = file_pos - bytes_before_frag;
                let src_start = bo + frag_file_offset;
                let frag_avail = frag_data.len().saturating_sub(src_start);
                let file_avail = self.file_size.saturating_sub(file_pos);
                let to_copy = (read_len - buf_pos).min(frag_avail).min(file_avail);
                if to_copy > 0 && src_start + to_copy <= frag_data.len() {
                    buf[buf_pos..buf_pos + to_copy]
                        .copy_from_slice(&frag_data[src_start..src_start + to_copy]);
                }
                buf_pos += to_copy;
                break;
            }

            let block_data = self.get_or_decompress(cur_block)?;
            let block_start_byte = cur_block * bs;
            let in_block_off = file_pos - block_start_byte;
            let file_avail = self.file_size.saturating_sub(file_pos);
            let block_avail = block_data.len().saturating_sub(in_block_off);
            let to_copy = (read_len - buf_pos).min(block_avail).min(file_avail);
            if to_copy > 0 {
                buf[buf_pos..buf_pos + to_copy]
                    .copy_from_slice(&block_data[in_block_off..in_block_off + to_copy]);
            }
            buf_pos += to_copy;
            file_pos += to_copy;
        }

        if buf_pos != read_len {
            return_errno_with_message!(Errno::EIO, "short read from SquashFS file data");
        }

        let seg = Segment::from(locked_page.deref().clone());
        seg.write_bytes(0, &buf)
            .map_err(|_| Error::with_message(Errno::EIO, "failed to write page"))?;

        locked_page.set_up_to_date();
        Ok(())
    }

    fn write_page_async(
        &self,
        _idx: usize,
        _locked_page: LockedCachePage,
        _io_batch: &mut IoBatch,
    ) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "SquashFS is read-only")
    }
}
