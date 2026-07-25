// SPDX-License-Identifier: MPL-2.0

//! Fragment table handling.
//!
//! Squashfs supports tail-end packing: the last partial block of a
//! file can be stored in a shared fragment block. The fragment table
//! maps fragment indexes to on-disk locations.
//!
//! Each fragment entry is 16 bytes on disk (`RawFragment`):
//! 8 bytes for start block, 4 bytes for size (bit 24 = uncompressed flag),
//! and 4 bytes of padding. The on-disk `RawFragment` is parsed into a
//! runtime `FragmentEntry` that decodes the bit fields and discards
//! the padding.

use ostd::const_assert;

use super::{SquashfsError, inode::COMPRESSED_BIT_BLOCK};
use crate::prelude::*;

/// A parsed fragment table entry for runtime use.
///
/// This is the in-memory representation after decoding the on-disk
/// `RawFragment`. The bit-packed `size_raw` field is split into
/// separate `size` and `compressed` fields, and the unused padding
/// is discarded.
#[derive(Clone, Debug)]
pub(super) struct FragmentEntry {
    /// Starting byte offset of the fragment block on disk.
    pub(super) start: u64,
    /// Size of the fragment block on disk in bytes.
    pub(super) size: u32,
    /// Whether the fragment block is stored compressed on disk.
    pub(super) compressed: bool,
}

/// A single on-disk fragment table entry.
///
/// This is the raw byte layout used **only** during parsing.
/// After reading from disk, each entry is immediately converted
/// into a [`FragmentEntry`] for runtime use.
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

const_assert!(size_of::<RawFragment>() == 16);

impl RawFragment {
    /// Converts this on-disk entry into a parsed runtime entry.
    fn into_entry(self) -> FragmentEntry {
        FragmentEntry {
            start: self.start,
            size: self.size_raw & !COMPRESSED_BIT_BLOCK,
            compressed: self.size_raw & COMPRESSED_BIT_BLOCK == 0,
        }
    }
}

/// Converts raw decompressed bytes into a vector of [`FragmentEntry`]s.
///
/// Each on-disk `RawFragment` is immediately converted to a [`FragmentEntry`];
/// the raw layout is not retained beyond this function.
pub(super) fn parse_fragment_table(data: &[u8]) -> Result<Vec<FragmentEntry>, SquashfsError> {
    let entry_size = size_of::<RawFragment>();
    if data.len() < entry_size {
        return Err(SquashfsError::CorruptedImage("fragment table too short"));
    }

    let mut fragments = Vec::with_capacity(data.len() / entry_size);
    let mut offset = 0;

    while offset + entry_size <= data.len() {
        let raw = RawFragment::from_first_bytes(&data[offset..]);
        fragments.push(raw.into_entry());
        offset += entry_size;
    }

    Ok(fragments)
}
