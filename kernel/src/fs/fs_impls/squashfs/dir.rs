// SPDX-License-Identifier: MPL-2.0

//! Directory entry parsing for Squashfs.
//!
//! Squashfs directories are stored in compressed metadata blocks.
//! Each directory consists of a header (count, start_block, inode_number)
//! followed by a sequence of directory entries. Directory entries
//! use relative inode offsets to maximise compression, since most
//! files in a directory are stored in the same metadata block.
//!
//! The directory size stored in the inode includes 3 bytes of
//! padding at the end, which is subtracted during parsing.
//!

use ostd::const_assert;

use super::{SquashfsError, inode::InodeId};
use crate::prelude::*;

/// Maximum number of entries per directory header.
///
/// Reference:
/// <https://elixir.bootlin.com/linux/v7.0/source/fs/squashfs/squashfs_fs.h#L36>
const DIR_HEADER_MAX_COUNT: u32 = 256;

/// The inode's `file_size` overcounts the directory data by 3 bytes.
/// The kernel uses offsets 0 and 1 for synthesized "." and ".." entries,
/// so the real listing starts at offset 3. This value is subtracted from
/// `file_size` during parsing to get the actual data length.
///
/// Reference:
/// <https://dr-emann.github.io/squashfs/squashfs.html#_directory_table>
const DIR_TAIL_PADDING: usize = 3;

/// On-disk directory header.
///
/// Reference:
/// <https://dr-emann.github.io/squashfs/squashfs.html#_directory_table>
/// <https://elixir.bootlin.com/linux/v7.0/source/fs/squashfs/squashfs_fs.h#L418>
#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct RawDirHeader {
    count: u32,
    start_block: u32,
    inode_number: u32,
}
const_assert!(size_of::<RawDirHeader>() == 12);

/// On-disk directory entry (fixed part, 8 bytes).
///
/// Reference:
/// <https://dr-emann.github.io/squashfs/squashfs.html#_directory_table>
/// <https://elixir.bootlin.com/linux/v7.0/source/fs/squashfs/squashfs_fs.h#L410>
#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct RawDirEntry {
    offset: u16,
    inode_offset: u16,
    type_: u16,
    /// One less than the name length. On-disk: `size + 1` bytes including
    /// the trailing null terminator.
    size: u16,
}
const_assert!(size_of::<RawDirEntry>() == 8);

/// Parsed directory containing a list of directory entries.
#[derive(Debug, Clone)]
pub(super) struct SquashDir {
    pub(super) entries: Vec<SquashDirEntry>,
}

/// A single directory entry in a Squashfs directory.
///
/// Directory entries are stored in a compact format:
/// the inode number is computed as `header_inode_num + inode_offset`,
/// allowing entries to share the same metadata block.
#[derive(Debug, Clone)]
pub(super) struct SquashDirEntry {
    /// Absolute inode number of the referenced file/directory.
    pub(super) inode_num: u32,
    /// Type of the referenced inode.
    pub(super) inode_type: InodeId,
    /// Filename including null terminator byte.
    pub(super) name: Vec<u8>,
}

pub(super) fn parse_dirs(
    dir_offset_map: &BTreeMap<u64, u64>,
    data: &[u8],
    block_index: u64,
    file_size: u32,
    block_offset: u16,
) -> Result<Option<SquashDir>, SquashfsError> {
    // `file_size` includes `DIR_TAIL_PADDING` bytes of padding.
    // If `file_size` is at most that padding, the actual directory data is empty.
    if file_size as usize <= DIR_TAIL_PADDING {
        return Ok(None);
    }

    let start_offset = dir_offset_map
        .get(&block_index)
        .copied()
        .ok_or(SquashfsError::CorruptedImage("directory block not found"))?;

    let start = start_offset as usize + block_offset as usize;
    let end = start + file_size as usize - DIR_TAIL_PADDING;
    if end > data.len() {
        return Err(SquashfsError::CorruptedImage("directory block truncated"));
    }

    let mut entries = Vec::new();
    let mut pos = start;

    while pos + size_of::<RawDirHeader>() <= end {
        let (header, _) = RawDirHeader::read_from_prefix(&data[pos..])
            .map_err(|_| SquashfsError::CorruptedImage("truncated dir header"))?;
        pos += size_of::<RawDirHeader>();

        if header.count > DIR_HEADER_MAX_COUNT {
            return Err(SquashfsError::CorruptedImage("directory entry count > 256"));
        }

        for _ in 0..=header.count {
            if pos + size_of::<RawDirEntry>() > end {
                break;
            }
            let (entry, _) = RawDirEntry::read_from_prefix(&data[pos..])
                .map_err(|_| SquashfsError::CorruptedImage("truncated dir entry"))?;
            pos += size_of::<RawDirEntry>();

            let entry_inode = (header.inode_number as i32 + entry.inode_offset as i32) as u32;
            let inode_type = InodeId::try_from(entry.type_)?;

            let name_len = (entry.size + 1) as usize;
            if pos + name_len > end {
                return Err(SquashfsError::CorruptedImage("directory name truncated"));
            }
            let name = data[pos..pos + name_len].to_vec();
            pos += name_len;

            entries.push(SquashDirEntry {
                inode_num: entry_inode,
                inode_type,
                name,
            });
        }
    }

    Ok(Some(SquashDir { entries }))
}
