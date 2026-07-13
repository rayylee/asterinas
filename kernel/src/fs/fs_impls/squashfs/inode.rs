// SPDX-License-Identifier: MPL-2.0

//! Inode parsing for Squashfs.
//!
//! Squashfs inodes are stored in compressed metadata blocks.
//! Each inode is identified by a 48-bit reference: upper 16 bits
//! for the metadata block, lower 16 bits for the byte offset
//! within that block after decompression.

use ostd::const_assert;

use super::{SquashfsError, types};
use crate::prelude::*;

/// On-disk inode type identifier.
///
/// Squashfs defines 14 inode types: 7 basic types and 7 extended types.
/// The extended types add xattr support, 64-bit fields, and nlink counts.
/// This implementation supports the 9 most common types.
///
/// Reference:
/// <https://dr-emann.github.io/squashfs/squashfs.html#_common_inode_header>
/// <https://elixir.bootlin.com/linux/v7.0/source/fs/squashfs/squashfs_fs.h#L78>
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InodeId {
    /// Directory inode (basic).
    BasicDirectory = 1,
    /// Regular file inode (basic).
    BasicFile = 2,
    /// Symbolic link inode (basic).
    BasicSymlink = 3,
    /// Block device inode.
    BasicBlockDevice = 4,
    /// Character device inode.
    BasicCharacterDevice = 5,
    /// Named pipe (FIFO) inode.
    BasicNamedPipe = 6,
    /// Unix domain socket inode.
    BasicSocket = 7,
    /// Directory inode with extended attributes and 64-bit fields.
    ExtendedDirectory = 8,
    /// Regular file inode with extended attributes and 64-bit fields.
    ExtendedFile = 9,
}

impl TryFrom<u16> for InodeId {
    type Error = SquashfsError;

    fn try_from(v: u16) -> Result<Self, SquashfsError> {
        match v {
            1 => Ok(Self::BasicDirectory),
            2 => Ok(Self::BasicFile),
            3 => Ok(Self::BasicSymlink),
            4 => Ok(Self::BasicBlockDevice),
            5 => Ok(Self::BasicCharacterDevice),
            6 => Ok(Self::BasicNamedPipe),
            7 => Ok(Self::BasicSocket),
            8 => Ok(Self::ExtendedDirectory),
            9 => Ok(Self::ExtendedFile),
            _ => Err(SquashfsError::CorruptedImage("unknown inode id")),
        }
    }
}

/// A fully parsed inode with its metadata and type-specific body.
#[derive(Clone)]
pub(super) struct ParsedInode {
    pub(super) meta: InodeMeta,
    pub(super) body: InodeBody,
}

/// Common metadata shared by all inode types.
///
/// Every Squashfs inode begins with a `RawBaseInode` header
/// containing: inode_type, mode, uid, gid, mtime, and inode_number.
#[derive(Clone)]
pub(super) struct InodeMeta {
    pub(super) permissions: u16,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) mtime: u32,
    pub(super) ino: u32,
}

/// Type-specific inode data.
///
/// The format varies by inode type. For example, regular files store
/// block list info and fragment reference; directories store the
/// location of the directory metadata block.
#[derive(Clone)]
pub(super) enum InodeBody {
    /// Regular file data.
    File {
        /// On-disk offset of the first data block.
        blocks_start: u64,
        /// Index into the fragment table, or `INVALID_FRAG` if no fragment.
        frag_index: u32,
        /// Byte offset of this file's data within the fragment block.
        block_offset: u32,
        /// Uncompressed file size in bytes.
        file_size: u64,
        /// Per-block size and compression info.
        block_sizes: Vec<BlockSizeInfo>,
    },
    /// Directory data.
    Dir {
        /// Metadata block index containing the directory entries.
        block_index: u32,
        /// Size of the directory data (+3 for padding).
        file_size: u32,
        /// Byte offset within the metadata block.
        block_offset: u16,
    },
    /// Symbolic link target.
    Symlink {
        /// Raw target path bytes.
        target: Vec<u8>,
    },
    /// Block device node.
    BlockDevice {
        /// Encoded device number (major << 20 | minor).
        device_number: u32,
    },
    /// Character device node.
    CharDevice {
        /// Encoded device number (major << 20 | minor).
        device_number: u32,
    },
    /// Named pipe (FIFO).
    NamedPipe,
    /// Unix domain socket.
    Socket,
}

impl InodeBody {
    /// Returns the logical size of this inode in bytes.
    pub(super) fn file_size(&self) -> u64 {
        match self {
            InodeBody::File { file_size, .. } => *file_size,
            InodeBody::Dir { file_size, .. } => *file_size as u64,
            InodeBody::Symlink { target } => target.len() as u64,
            _ => 0,
        }
    }

    /// Returns true if this is a directory inode.
    pub(super) fn is_dir(&self) -> bool {
        matches!(self, InodeBody::Dir { .. })
    }
}

/// Compressed size and compression flag for a single data block.
///
/// The on-disk format uses bit 24 of the 32-bit size field to indicate
/// whether the block is compressed.
#[derive(Clone, Copy, Debug)]
pub(super) struct BlockSizeInfo {
    pub(super) size: u32,
    pub(super) compressed: bool,
}

/// Bit 24 of the block size: set = uncompressed, not set = compressed.
///
/// Reference:
/// <https://dr-emann.github.io/squashfs/squashfs.html#_data_and_fragment_blocks>
/// <https://elixir.bootlin.com/linux/v7.0/source/fs/squashfs/squashfs_fs.h#L113>
pub(super) const COMPRESSED_BIT_BLOCK: u32 = 1 << 24;

impl BlockSizeInfo {
    /// Parses a raw 32-bit block size from the on-disk block list.
    /// The upper 8 bits encode the compression flag; lower 24 bits are the size.
    fn from_raw(raw: u32) -> Self {
        Self {
            size: raw & !COMPRESSED_BIT_BLOCK,
            compressed: raw & COMPRESSED_BIT_BLOCK == 0,
        }
    }
}

/// Sentinel value indicating no fragment is attached to this inode.
///
/// Reference:
/// <https://dr-emann.github.io/squashfs/squashfs.html#_file_inodes>
/// <https://elixir.bootlin.com/linux/v7.0/source/fs/squashfs/squashfs_fs.h#L38>
pub(super) const INVALID_FRAG: u32 = 0xffffffff;

/// On-disk common inode header.
///
/// Reference:
/// <https://dr-emann.github.io/squashfs/squashfs.html#_inode_table>
/// <https://elixir.bootlin.com/linux/v7.0/source/fs/squashfs/squashfs_fs.h#L270>
#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct RawBaseInode {
    inode_type: u16,
    permissions: u16,
    uid_idx: u16,
    gid_idx: u16,
    mtime: u32,
    inode_number: u32,
}

const_assert!(size_of::<RawBaseInode>() == 16);

/// On-disk basic directory inode .
#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct RawBasicDir {
    block_index: u32,
    nlink: u32,
    file_size: u16,
    block_offset: u16,
    parent_inode: u32,
}

const_assert!(size_of::<RawBasicDir>() == 16);

/// On-disk extended directory inode header .
#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct RawExtendedDir {
    nlink: u32,
    file_size: u32,
    block_index: u32,
    parent_inode: u32,
    index_count: u16,
    block_offset: u16,
    xattr_index: u32,
}

const_assert!(size_of::<RawExtendedDir>() == 24);

/// On-disk basic file inode header.
#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct RawBasicFile {
    blocks_start: u32,
    frag_index: u32,
    block_offset: u32,
    file_size: u32,
}

const_assert!(size_of::<RawBasicFile>() == 16);

/// On-disk extended file inode header.
#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct RawExtendedFile {
    blocks_start: u64,
    file_size: u64,
    sparse: u64,
    nlink: u32,
    frag_index: u32,
    block_offset: u32,
    xattr_index: u32,
}

const_assert!(size_of::<RawExtendedFile>() == 40);

/// On-disk symlink inode header.
#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct RawSymlink {
    nlink: u32,
    target_size: u32,
}

const_assert!(size_of::<RawSymlink>() == 8);

/// On-disk device inode header.
#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct RawDevice {
    nlink: u32,
    device_number: u32,
}

const_assert!(size_of::<RawDevice>() == 8);

/// On-disk IPC inode header — used for FIFOs and sockets.
#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct RawIpc {
    nlink: u32,
}

const_assert!(size_of::<RawIpc>() == 4);

/// Parses all inodes from the uncompressed inode table data.
///
/// Each inode is parsed sequentially until the data is exhausted.
/// Returns a map from inode number to parsed inode.
pub(super) fn parse_all_inodes(
    data: &[u8],
    block_size: u32,
    id_table: &[u32],
) -> Result<BTreeMap<u32, ParsedInode>, SquashfsError> {
    let mut inodes = BTreeMap::new();
    let len = data.len();
    let mut offset = 0;

    while offset < len {
        let (parsed, consumed) = parse_single_inode(data, offset, block_size, id_table)?;
        if consumed == 0 {
            break;
        }
        inodes.insert(parsed.meta.ino, parsed);
        offset += consumed;
    }

    Ok(inodes)
}

/// Parses a single inode at the given offset in the uncompressed data.
///
/// Returns the parsed inode and the number of bytes consumed.
/// The common header (16 bytes) is read via [`RawBaseInode`],
/// then type-specific data is read via the corresponding Pod struct.
pub(super) fn parse_single_inode(
    data: &[u8],
    start: usize,
    block_size: u32,
    id_table: &[u32],
) -> Result<(ParsedInode, usize), SquashfsError> {
    let mut offset = start;

    let (base, _) = RawBaseInode::read_from_prefix(&data[offset..])
        .map_err(|_| SquashfsError::CorruptedImage("truncated inode header"))?;
    offset += size_of::<RawBaseInode>();

    let id = InodeId::try_from(base.inode_type)?;

    let uid = id_table.get(base.uid_idx as usize).copied().unwrap_or(0);
    let gid = id_table.get(base.gid_idx as usize).copied().unwrap_or(0);

    let meta = InodeMeta {
        permissions: base.permissions,
        uid,
        gid,
        mtime: base.mtime,
        ino: base.inode_number,
    };

    let body = match id {
        InodeId::BasicDirectory => {
            let (raw, _) = RawBasicDir::read_from_prefix(&data[offset..])
                .map_err(|_| SquashfsError::CorruptedImage("truncated dir inode"))?;
            offset += size_of::<RawBasicDir>();
            InodeBody::Dir {
                block_index: raw.block_index,
                file_size: raw.file_size as u32,
                block_offset: raw.block_offset,
            }
        }
        InodeId::ExtendedDirectory => {
            let (raw, _) = RawExtendedDir::read_from_prefix(&data[offset..])
                .map_err(|_| SquashfsError::CorruptedImage("truncated ext dir inode"))?;
            offset += size_of::<RawExtendedDir>();
            for _ in 0..raw.index_count {
                let _index = types::read_u32(data, &mut offset)?;
                let _start = types::read_u32(data, &mut offset)?;
                let name_size = types::read_u32(data, &mut offset)?;
                offset += (name_size + 1) as usize;
            }
            InodeBody::Dir {
                block_index: raw.block_index,
                file_size: raw.file_size,
                block_offset: raw.block_offset,
            }
        }
        InodeId::BasicFile => {
            let (raw, _) = RawBasicFile::read_from_prefix(&data[offset..])
                .map_err(|_| SquashfsError::CorruptedImage("truncated file inode"))?;
            offset += size_of::<RawBasicFile>();
            let nblocks =
                file_block_count(block_size, raw.frag_index, raw.file_size as u64) as usize;
            let mut block_sizes = Vec::with_capacity(nblocks);
            for _ in 0..nblocks {
                let raw_size = types::read_u32(data, &mut offset)?;
                block_sizes.push(BlockSizeInfo::from_raw(raw_size));
            }
            InodeBody::File {
                blocks_start: raw.blocks_start as u64,
                frag_index: raw.frag_index,
                block_offset: raw.block_offset,
                file_size: raw.file_size as u64,
                block_sizes,
            }
        }
        InodeId::ExtendedFile => {
            let (raw, _) = RawExtendedFile::read_from_prefix(&data[offset..])
                .map_err(|_| SquashfsError::CorruptedImage("truncated ext file inode"))?;
            offset += size_of::<RawExtendedFile>();
            let nblocks = file_block_count(block_size, raw.frag_index, raw.file_size) as usize;
            let mut block_sizes = Vec::with_capacity(nblocks);
            for _ in 0..nblocks {
                let raw_size = types::read_u32(data, &mut offset)?;
                block_sizes.push(BlockSizeInfo::from_raw(raw_size));
            }
            InodeBody::File {
                blocks_start: raw.blocks_start,
                frag_index: raw.frag_index,
                block_offset: raw.block_offset,
                file_size: raw.file_size,
                block_sizes,
            }
        }
        InodeId::BasicSymlink => {
            let (raw, _) = RawSymlink::read_from_prefix(&data[offset..])
                .map_err(|_| SquashfsError::CorruptedImage("truncated symlink inode"))?;
            offset += size_of::<RawSymlink>();
            let target_size = raw.target_size as usize;
            if offset + target_size > data.len() {
                return Err(SquashfsError::CorruptedImage("symlink target truncated"));
            }
            let target = data[offset..offset + target_size].to_vec();
            offset += target_size;
            InodeBody::Symlink { target }
        }
        InodeId::BasicBlockDevice => {
            let (raw, _) = RawDevice::read_from_prefix(&data[offset..])
                .map_err(|_| SquashfsError::CorruptedImage("truncated device inode"))?;
            offset += size_of::<RawDevice>();
            InodeBody::BlockDevice {
                device_number: raw.device_number,
            }
        }
        InodeId::BasicCharacterDevice => {
            let (raw, _) = RawDevice::read_from_prefix(&data[offset..])
                .map_err(|_| SquashfsError::CorruptedImage("truncated device inode"))?;
            offset += size_of::<RawDevice>();
            InodeBody::CharDevice {
                device_number: raw.device_number,
            }
        }
        InodeId::BasicNamedPipe => {
            let (_raw, _) = RawIpc::read_from_prefix(&data[offset..])
                .map_err(|_| SquashfsError::CorruptedImage("truncated ipc inode"))?;
            offset += size_of::<RawIpc>();
            InodeBody::NamedPipe
        }
        InodeId::BasicSocket => {
            let (_raw, _) = RawIpc::read_from_prefix(&data[offset..])
                .map_err(|_| SquashfsError::CorruptedImage("truncated ipc inode"))?;
            offset += size_of::<RawIpc>();
            InodeBody::Socket
        }
    };

    Ok((ParsedInode { meta, body }, offset - start))
}

/// Computes the number of data blocks for a file.
///
/// If the file has a fragment, the last partial block is stored in the
/// fragment, so the block count is `file_size / block_size`.
/// Otherwise, the block count is rounded up to cover the full file size.
fn file_block_count(block_size: u32, fragment: u32, file_size: u64) -> u64 {
    let block_size = u64::from(block_size);
    if fragment == INVALID_FRAG {
        file_size.div_ceil(block_size)
    } else {
        file_size / block_size
    }
}
