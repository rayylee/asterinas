// SPDX-License-Identifier: MPL-2.0

//! Compression and decompression support.
//!
//! Squashfs supports multiple compression algorithms. Each data block
//! and metadata block can be individually compressed or stored uncompressed.
//! Currently supported: uncompressed, gzip (zlib), and zstd.

use ruzstd::{decoding::StreamingDecoder, io::Read as _};
use zune_inflate::DeflateDecoder;

use super::SquashfsError;
use crate::prelude::*;

/// Supported compression algorithms.
///
/// Reference:
/// <https://dr-emann.github.io/squashfs/squashfs.html#_the_superblock>
/// <https://elixir.bootlin.com/linux/v7.0/source/fs/squashfs/squashfs_fs.h#L231>
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Compressor {
    Uncompressed = 0,
    Gzip = 1,
    Lzma = 2,
    Lzo = 3,
    Xz = 4,
    Lz4 = 5,
    Zstd = 6,
}

impl TryFrom<u16> for Compressor {
    type Error = SquashfsError;

    fn try_from(v: u16) -> Result<Self, SquashfsError> {
        match v {
            0 => Ok(Self::Uncompressed),
            1 => Ok(Self::Gzip),
            2 => Ok(Self::Lzma),
            3 => Ok(Self::Lzo),
            4 => Ok(Self::Xz),
            5 => Ok(Self::Lz4),
            6 => Ok(Self::Zstd),
            _ => Err(SquashfsError::UnsupportedCompression(v)),
        }
    }
}

/// Context for decompressing blocks.
///
/// The `decompress` method dispatches to the appropriate algorithm.
#[derive(Debug, Clone, Copy)]
pub(super) struct DecompressContext {
    compressor: Compressor,
}

impl DecompressContext {
    pub(super) fn new(compressor: Compressor) -> Self {
        Self { compressor }
    }

    /// Decompresses `input` into `output` using the configured algorithm.
    ///
    /// If the compressor is `Uncompressed`, the input is copied directly.
    /// Only gzip (zlib format) and zstd are currently implemented;
    /// other algorithms return an error.
    pub(super) fn decompress(
        &self,
        input: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<(), SquashfsError> {
        match self.compressor {
            Compressor::Uncompressed => {
                output.extend_from_slice(input);
                Ok(())
            }
            Compressor::Gzip => {
                let mut decoder = DeflateDecoder::new(input);
                let decompressed = decoder
                    .decode_zlib()
                    .map_err(|_| SquashfsError::DecompressError)?;
                *output = decompressed;
                Ok(())
            }
            Compressor::Zstd => {
                let mut reader = CompressedDataReader {
                    data: input,
                    pos: 0,
                };
                let mut decoder = StreamingDecoder::new(&mut reader)
                    .map_err(|_| SquashfsError::DecompressError)?;
                let mut buf = [0u8; 8192];
                loop {
                    let n = decoder
                        .read(&mut buf)
                        .map_err(|_| SquashfsError::DecompressError)?;
                    if n == 0 {
                        break;
                    }
                    output.extend_from_slice(&buf[..n]);
                }
                Ok(())
            }
            _ => Err(SquashfsError::UnsupportedCompression(
                self.compressor as u16,
            )),
        }
    }
}

struct CompressedDataReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl ruzstd::io::Read for CompressedDataReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> core::result::Result<usize, ruzstd::io::Error> {
        let remaining = self.data.len() - self.pos;
        let to_read = buf.len().min(remaining);
        if to_read > 0 {
            buf[..to_read].copy_from_slice(&self.data[self.pos..self.pos + to_read]);
            self.pos += to_read;
        }
        Ok(to_read)
    }
}
