// SPDX-License-Identifier: MPL-2.0

//! Squashfs filesystem implementation.
//!
//! Squashfs is a compressed read-only filesystem.
//! This module implements support for Squashfs 4.0 images with gzip and zstd compression.
//!
//! # Mount sequence
//!
//! 1. Read and validate the superblock (96 bytes at offset 0)
//! 2. Read the UID/GID lookup table
//! 3. Read and decompress all inode metadata blocks, parse each inode
//! 4. Read and decompress all directory metadata blocks, parse each directory
//! 5. Read the fragment table (if present)
//!
//! # Design notes
//!
//! Unlike the Linux kernel's lazy-loading approach, this implementation
//! eagerly loads all inodes and directory entries into memory at mount time.
//! File data blocks are read on-demand through the page cache.

use core::fmt;

use aster_systree::SysNode;

use crate::{
    fs::vfs::{
        file_system::FileSystem,
        registry::{FsCreationCtx, FsProperties, FsType},
    },
    prelude::*,
};

mod compressor;
mod dir;
mod fragment;
mod fs;
mod impl_for_vfs;
mod inode;
mod metadata;
mod super_block;
mod types;

pub(super) use fs::SquashFs;

/// Errors specific to Squashfs operations.
#[derive(Clone, Debug)]
pub(super) enum SquashfsError {
    IoError,
    InvalidMagic,
    UnsupportedVersion(u16, u16),
    InvalidBlockSize(u32),
    UnsupportedCompression(u16),
    DecompressError,
    CorruptedImage(&'static str),
}

impl fmt::Display for SquashfsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SquashfsError::IoError => write!(f, "i/o error"),
            SquashfsError::InvalidMagic => write!(f, "invalid magic"),
            SquashfsError::UnsupportedVersion(maj, min) => {
                write!(f, "unsupported version {}.{}", maj, min)
            }
            SquashfsError::InvalidBlockSize(sz) => write!(f, "invalid block size {}", sz),
            SquashfsError::UnsupportedCompression(c) => {
                write!(f, "unsupported compression {}", c)
            }
            SquashfsError::DecompressError => write!(f, "decompression error"),
            SquashfsError::CorruptedImage(msg) => write!(f, "corrupted image: {}", msg),
        }
    }
}

impl From<SquashfsError> for Error {
    fn from(e: SquashfsError) -> Self {
        let (errno, msg) = match e {
            SquashfsError::IoError => (Errno::EIO, "I/O error"),
            SquashfsError::InvalidMagic => (Errno::EINVAL, "invalid magic"),
            SquashfsError::UnsupportedVersion(_, _) => {
                (Errno::EINVAL, "unsupported version")
            }
            SquashfsError::InvalidBlockSize(_) => (Errno::EINVAL, "invalid block size"),
            SquashfsError::UnsupportedCompression(_) => {
                (Errno::EINVAL, "unsupported compression")
            }
            SquashfsError::DecompressError => (Errno::EIO, "decompression error"),
            SquashfsError::CorruptedImage(detail) => (Errno::EIO, detail),
        };
        Error::with_message(errno, msg)
    }
}

struct SquashFsType;

impl FsType for SquashFsType {
    fn name(&self) -> &'static str {
        "squashfs"
    }

    fn properties(&self) -> FsProperties {
        FsProperties::NEED_DISK
    }

    fn create(&self, fs_creation_ctx: &FsCreationCtx) -> Result<Arc<dyn FileSystem>> {
        let disk = fs_creation_ctx.resolve_block_device()?;
        SquashFs::open(disk).map(|fs| fs as Arc<dyn FileSystem>)
    }

    fn sysnode(&self) -> Option<Arc<dyn SysNode>> {
        None
    }
}

pub(super) fn init() {
    crate::fs::vfs::registry::register(&SquashFsType).unwrap();
}
