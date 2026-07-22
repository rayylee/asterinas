// SPDX-License-Identifier: MPL-2.0

//! Streaming reader helpers for Squashfs on-disk parsing.
//!
//! All supported architectures are little-endian, so on-disk values
//! are read directly as native integers.

use super::SquashfsError;

/// Reads a u32 from `data` at `offset`, advancing the offset.
pub(super) fn read_u32(data: &[u8], offset: &mut usize) -> Result<u32, SquashfsError> {
    if *offset + 4 > data.len() {
        return Err(SquashfsError::CorruptedImage("short read"));
    }
    let v = u32::from_le_bytes(data[*offset..*offset + 4].try_into().unwrap());
    *offset += 4;
    Ok(v)
}
