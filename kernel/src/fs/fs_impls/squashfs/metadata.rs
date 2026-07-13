// SPDX-License-Identifier: MPL-2.0

//! Metadata block reading and lookup table parsing.
//!
//! Squashfs stores inode, directory, and lookup table data in
//! compressed metadata blocks. Each metadata block has a 2-byte
//! header: bit 15 indicates whether the block is uncompressed,
//! and the lower 15 bits encode the compressed data size.
//!
//! Lookup tables (ID table, fragment table, export table) use
//! a two-level structure: an 8-byte pointer at the table start
//! address, followed by metadata blocks containing the actual data.

use aster_block::BlockDevice;
use ostd::mm::VmIo;

use super::{SquashfsError, compressor::DecompressContext, fragment::RawFragment, types};
use crate::prelude::*;

/// Bit 15 of the metadata header: 1 = uncompressed, 0 = compressed.
///
/// Reference:
/// <https://dr-emann.github.io/squashfs/squashfs.html#_packing_metadata>
/// <https://elixir.bootlin.com/linux/v7.0/source/fs/squashfs/squashfs_fs.h#L104>
const METADATA_COMPRESSED_BIT: u16 = 1 << 15;

/// Maximum uncompressed size of a metadata block.
///
/// Reference:
/// <https://dr-emann.github.io/squashfs/squashfs.html#_packing_metadata>
/// <https://elixir.bootlin.com/linux/v7.0/source/fs/squashfs/squashfs_fs.h#L19>
const METADATA_MAX_SIZE: usize = 0x2000;

/// Reads multiple consecutive metadata blocks from the block device,
/// starting at `start_pos` and ending at `end_pos`.
///
/// # Returns
/// `(offset_map, concatenated_uncompressed_data)`
///
/// The offset map maps block index (relative to start_pos) to byte offset
/// in the concatenated data. This is used to locate individual inodes
/// and directories within the decompressed data.
pub(super) fn read_all_metadata_blocks(
    device: &Arc<dyn BlockDevice>,
    start_pos: u64,
    end_pos: u64,
    decompress: &DecompressContext,
) -> Result<(BTreeMap<u64, u64>, Vec<u8>), SquashfsError> {
    let mut offset_map = BTreeMap::new();
    let mut all_data = Vec::new();
    let mut pos = start_pos;

    while pos < end_pos {
        let block_start = pos - start_pos;
        offset_map.insert(block_start, all_data.len() as u64);

        let (mut block_data, consumed) = read_single_metadata_block(device, pos, decompress)?;
        all_data.append(&mut block_data);
        pos += consumed as u64;
    }

    Ok((offset_map, all_data))
}

/// Reads a single metadata block from the block device.
///
/// Each metadata block is laid out as:
/// | Offset | Size | Content          |
/// |--------|------|------------------|
/// | 0      | 2    | header (u16 LE)  |
/// | 2      | N    | compressed data  |
fn read_single_metadata_block(
    device: &Arc<dyn BlockDevice>,
    pos: u64,
    decompress: &DecompressContext,
) -> Result<(Vec<u8>, usize), SquashfsError> {
    let mut header_buf = [0u8; 2];
    device
        .read_bytes(pos as usize, &mut header_buf)
        .map_err(|_| SquashfsError::IoError)?;

    let header = u16::from_le_bytes(header_buf);
    let compressed = header & METADATA_COMPRESSED_BIT == 0;
    let data_len = (header & !METADATA_COMPRESSED_BIT) as usize;

    if data_len == 0 {
        return Ok((Vec::new(), 2));
    }

    let mut data_buf = vec![0u8; data_len];
    device
        .read_bytes(pos as usize + 2, &mut data_buf)
        .map_err(|_| SquashfsError::IoError)?;

    let bytes = if compressed {
        let mut output = Vec::with_capacity(METADATA_MAX_SIZE);
        decompress.decompress(&data_buf, &mut output)?;
        output
    } else {
        data_buf
    };

    Ok((bytes, 2 + data_len))
}

/// Reads the UID/GID lookup table.
///
/// Each entry is a 4-byte little-endian u32 representing a UID or GID.
/// Inodes store 16-bit indexes into this table rather than raw UIDs/GIDs,
/// allowing space-efficient storage of user/group ownership.
pub(super) fn read_id_table(
    device: &Arc<dyn BlockDevice>,
    table_pos: u64,
    id_count: u16,
    decompress: &DecompressContext,
) -> Result<Vec<u32>, SquashfsError> {
    const ENTRY_SIZE: usize = size_of::<u32>();
    let ids = read_lookup_table::<u32>(
        device,
        table_pos,
        ENTRY_SIZE,
        id_count as u64,
        decompress,
        |data| {
            let mut ids = Vec::with_capacity(data.len() / ENTRY_SIZE);
            let mut offset = 0;
            while offset + ENTRY_SIZE <= data.len() {
                let id = types::read_u32(data, &mut offset)?;
                ids.push(id);
            }
            Ok(ids)
        },
    )?;
    Ok(ids)
}

/// Reads the fragment table.
///
/// Each entry is a 16-byte on-disk `RawFragment` describing
/// the location and size of a tail-end packed fragment block.
pub(super) fn read_fragment_table(
    device: &Arc<dyn BlockDevice>,
    table_pos: u64,
    frag_count: u32,
    decompress: &DecompressContext,
) -> Result<Vec<RawFragment>, SquashfsError> {
    RawFragment::from_raw_bytes(&read_lookup_table_raw(
        device,
        table_pos,
        16,
        frag_count as u64,
        decompress,
    )?)
}

/// Reads a lookup table (ID, fragment, or export table).
///
/// A lookup table consists of an 8-byte pointer at `table_pos`,
/// followed by metadata blocks containing the actual table data.
/// The `parse_fn` is called with the raw decompressed bytes to produce the final typed entries.
fn read_lookup_table<T>(
    device: &Arc<dyn BlockDevice>,
    table_pos: u64,
    entry_size: usize,
    entry_count: u64,
    decompress: &DecompressContext,
    parse_fn: fn(&[u8]) -> Result<Vec<T>, SquashfsError>,
) -> Result<Vec<T>, SquashfsError> {
    let mut ptr_buf = [0u8; 8];
    device
        .read_bytes(table_pos as usize, &mut ptr_buf)
        .map_err(|_| SquashfsError::IoError)?;
    let ptr = u64::from_le_bytes(ptr_buf);

    let total_size = entry_size * entry_count as usize;
    let block_count = total_size.div_ceil(METADATA_MAX_SIZE) as u64;

    let mut all_data = Vec::with_capacity(total_size);
    let mut pos = ptr;

    for _ in 0..block_count {
        let (mut block_data, consumed) = read_single_metadata_block(device, pos, decompress)?;
        all_data.append(&mut block_data);
        pos += consumed as u64;
    }

    all_data.truncate(total_size);
    parse_fn(&all_data)
}

/// Read a lookup table and return the raw decompressed bytes without parsing.
fn read_lookup_table_raw(
    device: &Arc<dyn BlockDevice>,
    table_pos: u64,
    entry_size: usize,
    entry_count: u64,
    decompress: &DecompressContext,
) -> Result<Vec<u8>, SquashfsError> {
    let mut ptr_buf = [0u8; 8];
    device
        .read_bytes(table_pos as usize, &mut ptr_buf)
        .map_err(|_| SquashfsError::IoError)?;
    let ptr = u64::from_le_bytes(ptr_buf);

    let total_size = entry_size * entry_count as usize;
    let block_count = total_size.div_ceil(METADATA_MAX_SIZE) as u64;

    let mut all_data = Vec::with_capacity(total_size);
    let mut pos = ptr;

    for _ in 0..block_count {
        let (mut block_data, consumed) = read_single_metadata_block(device, pos, decompress)?;
        all_data.append(&mut block_data);
        pos += consumed as u64;
    }

    all_data.truncate(total_size);
    Ok(all_data)
}
