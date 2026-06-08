// SPDX-License-Identifier: MPL-2.0

use alloc::{boxed::Box, collections::vec_deque::VecDeque, sync::Arc};

use aster_pci::{
    bus::{PciDevice, PciDriver},
    common_device::PciCommonDevice,
};
use ostd::{bus::BusProbeError, sync::SpinLock, warn};

use super::device::VirtioPciModernTransport;
use crate::transport::{
    VirtioTransport,
    pci::{device::VirtioPciDevice, legacy::VirtioPciLegacyTransport},
};

#[derive(Debug)]
pub struct VirtioPciDriver {
    devices: SpinLock<VecDeque<Box<dyn VirtioTransport>>>,
}

impl VirtioPciDriver {
    pub fn pop_device_transport(&self) -> Option<Box<dyn VirtioTransport>> {
        self.devices.lock().pop_front()
    }

    pub(super) fn new() -> Self {
        VirtioPciDriver {
            devices: SpinLock::new(VecDeque::new()),
        }
    }
}

impl PciDriver for VirtioPciDriver {
    fn probe(
        &self,
        device: PciCommonDevice,
    ) -> Result<Arc<dyn PciDevice>, (BusProbeError, PciCommonDevice)> {
        const VIRTIO_DEVICE_VENDOR_ID: u16 = 0x1af4;
        if device.device_id().vendor_id != VIRTIO_DEVICE_VENDOR_ID {
            return Err((BusProbeError::DeviceNotMatch, device));
        }

        let has_vendor_cap = device.iter_vndr_capability().next().is_some();
        let device_id = *device.device_id();
        let transport: Box<dyn VirtioTransport> = match device_id.device_id {
            0x1000..0x1040 if (device.device_id().revision_id == 0) => {
                if has_vendor_cap {
                    // Transitional device: try the modern transport first.
                    // If it fails (e.g., vendor capabilities use I/O BARs),
                    // fall back to the legacy transport.
                    match VirtioPciModernTransport::new(device) {
                        Ok(modern) => Box::new(modern),
                        Err((_, dev)) => {
                            warn!(
                                "Modern virtio transport init failed, \
                                 falling back to legacy for device {:x}",
                                device_id.device_id
                            );
                            let legacy = VirtioPciLegacyTransport::new(dev)?;
                            Box::new(legacy)
                        }
                    }
                } else {
                    let legacy = VirtioPciLegacyTransport::new(device)?;
                    Box::new(legacy)
                }
            }
            0x1040..0x107f => {
                if !has_vendor_cap {
                    return Err((BusProbeError::DeviceNotMatch, device));
                }
                let modern = VirtioPciModernTransport::new(device)?;
                Box::new(modern)
            }
            _ => return Err((BusProbeError::DeviceNotMatch, device)),
        };
        self.devices.lock().push_back(transport);

        Ok(Arc::new(VirtioPciDevice::new(device_id)))
    }
}
