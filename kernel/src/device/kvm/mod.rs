// SPDX-License-Identifier: MPL-2.0

//! KVM-compatible hypervisor device module.
//!
//! Implements `/dev/kvm` and the associated VM and vCPU file descriptors,
//! providing a Linux KVM-compatible user-space API for hardware virtualization.

mod ioctl;
mod vcpu;
mod vm;

use device_id::{DeviceId, MajorId, MinorId};
use spin::Once;

use crate::{
    device::{
        Device, DeviceType, DevtmpfsInodeMeta,
        registry::char::{self, MajorIdOwner, acquire_major},
    },
    events::IoEvents,
    fs::{
        file::{PerOpenFileOps, StatusFlags},
        vfs::inode::FileOps,
    },
    prelude::*,
    process::signal::{PollHandle, Pollable},
    util::ioctl::{RawIoctl, dispatch_ioctl},
};

/// KVM API version (matches Linux).
const KVM_API_VERSION: i32 = 12;

/// Minor number for `/dev/kvm` (matches Linux).
const KVM_MINOR: u32 = 232;

/// `/dev/kvm` device.
#[derive(Debug)]
struct KvmDevice {
    id: DeviceId,
}

impl KvmDevice {
    fn new(major_id: MajorId) -> Arc<Self> {
        let minor = MinorId::new(KVM_MINOR);
        let id = DeviceId::new(major_id, minor);
        Arc::new(Self { id })
    }
}

impl Device for KvmDevice {
    fn type_(&self) -> DeviceType {
        DeviceType::Char
    }

    fn id(&self) -> DeviceId {
        self.id
    }

    fn devtmpfs_meta(&self) -> Option<DevtmpfsInodeMeta<'_>> {
        Some(DevtmpfsInodeMeta::new("kvm"))
    }

    fn open(&self) -> Result<Box<dyn PerOpenFileOps>> {
        Ok(Box::new(KvmFile))
    }
}

/// A file handle opened from `/dev/kvm`.
struct KvmFile;

impl Pollable for KvmFile {
    fn poll(&self, mask: IoEvents, _poller: Option<&mut PollHandle>) -> IoEvents {
        mask & (IoEvents::IN | IoEvents::OUT)
    }
}

impl FileOps for KvmFile {
    fn read_at(
        &self,
        _offset: usize,
        _writer: &mut VmWriter,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        return_errno_with_message!(Errno::EINVAL, "KVM device is not readable")
    }

    fn write_at(
        &self,
        _offset: usize,
        _reader: &mut VmReader,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        return_errno_with_message!(Errno::EINVAL, "KVM device is not writable")
    }
}

impl PerOpenFileOps for KvmFile {
    fn check_seekable(&self) -> Result<()> {
        return_errno_with_message!(Errno::ESPIPE, "KVM device is not seekable")
    }

    fn is_offset_aware(&self) -> bool {
        false
    }

    fn ioctl(&self, raw_ioctl: RawIoctl) -> Result<i32> {
        use ioctl::*;

        dispatch_ioctl!(match raw_ioctl {
            _cmd @ GetApiVersion => {
                Ok(KVM_API_VERSION)
            }
            _cmd @ CreateVm => {
                println!("KVM: CREATE_VM");
                ensure_capabilities_detected()?;
                let vm = vm::KvmVm::new()?;
                let fd = vm.register_fd()?;
                Ok(fd as i32)
            }
            cmd @ CheckExtension => {
                let capability = cmd.get();
                Ok(check_extension(capability))
            }
            _cmd @ GetVcpuMmapSize => {
                println!("KVM: GET_VCPU_MMAP_SIZE");
                Ok(vcpu::KVM_RUN_SIZE as i32)
            }
            _ => return_errno_with_message!(Errno::ENOTTY, "unknown KVM ioctl"),
        })
    }
}

/// Checks a KVM capability.
fn check_extension(capability: i32) -> i32 {
    use ioctl::*;
    match capability {
        KVM_CAP_HLT => 1,
        KVM_CAP_USER_MEMORY => 1,
        KVM_CAP_SET_TSS_ADDR => 1,
        KVM_CAP_EXT_CPUID => 1,
        KVM_CAP_NR_VCPUS => 1,
        KVM_CAP_NR_MEMSLOTS => 8,
        _ => 0,
    }
}

/// Initializes the KVM device module.
///
/// Registers `/dev/kvm` as a character device with major number 232.
/// Hardware virtualization capabilities are detected lazily when
/// a VM is first created.
pub fn init() -> Result<()> {
    KVM_MAJOR.call_once(|| acquire_major(MajorId::new(232)).unwrap());
    let major_id = KVM_MAJOR.get().unwrap().get();
    let device = KvmDevice::new(major_id);
    char::register(device)?;
    Ok(())
}

/// Ensures hardware virtualization capabilities have been detected.
///
/// Called on first KVM_CREATE_VM to detect VMX/SVM capabilities.
/// Returns an error if hardware virtualization is not available.
fn ensure_capabilities_detected() -> Result<()> {
    static DETECTED: spin::Once<()> = spin::Once::new();
    if DETECTED.is_completed() {
        return Ok(());
    }

    // Try to detect capabilities. We must try both paths since
    // is_amd_cpu() may succeed on AMD even if SVM is locked.
    let result = if ostd::guest::is_amd_cpu() {
        println!("KVM: AMD CPU detected, detecting SVM capabilities");
        ostd::guest::detect_svm_capabilities()
    } else {
        println!("KVM: Intel CPU detected, detecting VMX capabilities");
        ostd::guest::detect_vmx_capabilities()
    };

    match result {
        Ok(()) => {
            println!("KVM: Capabilities detected successfully");
        }
        Err(e) => {
            println!("KVM: Capability detection failed: {:?}", e);
            return Err(Error::new(Errno::ENODEV));
        }
    }

    DETECTED.call_once(|| {});
    Ok(())
}

static KVM_MAJOR: Once<MajorIdOwner> = Once::new();
