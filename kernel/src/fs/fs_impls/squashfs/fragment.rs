// SPDX-License-Identifier: MPL-2.0

//! Fragment table handling.
//!
//! Squashfs supports tail-end packing: the last partial block of a
//! file can be stored in a shared fragment block. The fragment table
//! maps fragment indexes to on-disk locations.
//!
//! Each fragment entry is 16 bytes on disk (`RawFragment`):
//! 8 bytes for start block, 4 bytes for size (bit 24 = uncompressed flag),
//! and 4 bytes of padding.

use super::{SquashfsError, inode::COMPRESSED_BIT_BLOCK};
use crate::prelude::*;

/// A single on-disk fragment table entry.
///
/// Describes the location of a tail-end packed fragment block on disk.
/// Fragment blocks can be shared by multiple small files whose last
/// partial block would otherwise waste space.
///
/// Reference: <https://dr-emann.github.io/squashfs/squashfs.html#_fragment_table>
#[repr(C)]
#[derive(Clone, Copy, Pod)]
pub(super) struct RawFragment {
    start: u64,
    /// Raw size field with bit 24 encoding the compression flag.
    size_raw: u32,
    /// Padding field (always present in the on-disk format, not used).
    unused: u32,
}

impl RawFragment {
    /// The starting block number of the fragment on disk.
    pub(super) fn start(&self) -> u64 {
        self.start
    }

    /// Size of the fragment on disk in bytes (lower 24 bits).
    pub(super) fn size(&self) -> u32 {
        self.size_raw & !COMPRESSED_BIT_BLOCK
    }

    /// Whether the fragment is stored compressed.
    pub(super) fn is_compressed(&self) -> bool {
        self.size_raw & COMPRESSED_BIT_BLOCK == 0
    }

    /// Parses a vector of fragment entries from raw decompressed bytes.
    pub(super) fn from_raw_bytes(data: &[u8]) -> Result<Vec<RawFragment>, SquashfsError> {
        let entry_size = size_of::<RawFragment>();
        if data.len() < entry_size {
            return Err(SquashfsError::CorruptedImage("fragment table too short"));
        }

        let mut fragments = Vec::with_capacity(data.len() / entry_size);
        let mut offset = 0;

        while offset + entry_size <= data.len() {
            let frag = RawFragment::from_first_bytes(&data[offset..]);
            fragments.push(frag);
            offset += entry_size;
        }

        Ok(fragments)
    }
}
