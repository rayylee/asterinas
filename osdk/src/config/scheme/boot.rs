// SPDX-License-Identifier: MPL-2.0

use clap::ValueEnum;

use std::path::PathBuf;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct BootScheme {
    /// Command line arguments for the guest kernel
    #[serde(default)]
    pub kcmd_args: Vec<String>,
    /// Command line arguments for the guest init process
    #[serde(default)]
    pub init_args: Vec<String>,
    /// The path of initramfs
    pub initramfs: Option<PathBuf>,
    /// The method used to boot the guest.
    pub method: Option<BootMethod>,
    /// The boot protocol or entry ABI used by the boot image.
    pub protocol: Option<BootProtocol>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum BootMethod {
    /// Build a bootable ELF image.
    #[default]
    Elf,
    /// Build a Linux bzImage-compatible image.
    #[serde(rename = "bzimage")]
    BzImage,
    /// Build a GRUB rescue CD image.
    GrubRescueIso,
    /// Build a qcow2 image with GRUB as the bootloader.
    GrubQcow2,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum BootProtocol {
    Linux,
    LinuxLegacy32,
    LinuxEfiPe64,
    LinuxEfiHandover64,
    Multiboot,
    #[default]
    Multiboot2,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Boot {
    pub kcmdline: Vec<String>,
    pub initramfs: Option<PathBuf>,
    pub method: BootMethod,
    pub protocol: BootProtocol,
}

impl BootScheme {
    pub fn inherit(&mut self, from: &Self) {
        self.kcmd_args = {
            let mut kcmd_args = from.kcmd_args.clone();
            kcmd_args.extend(self.kcmd_args.clone());
            kcmd_args
        };
        self.init_args = {
            let mut init_args = from.init_args.clone();
            init_args.extend(self.init_args.clone());
            init_args
        };
        if self.initramfs.is_none() {
            self.initramfs.clone_from(&from.initramfs);
        }
        if self.method.is_none() {
            self.method = from.method;
        }
        if self.protocol.is_none() {
            self.protocol = from.protocol;
        }
    }

    pub fn finalize(self, fallback_protocol: BootProtocol) -> Boot {
        let mut kcmdline = self.kcmd_args;
        kcmdline.push("--".to_owned());
        kcmdline.extend(self.init_args);

        let protocol = self.protocol.unwrap_or(fallback_protocol);
        let method = self.method.unwrap_or_default();

        Boot {
            kcmdline,
            initramfs: self.initramfs,
            method,
            protocol,
        }
    }
}

impl BootProtocol {
    pub fn is_linux(self) -> bool {
        matches!(
            self,
            BootProtocol::Linux
                | BootProtocol::LinuxLegacy32
                | BootProtocol::LinuxEfiPe64
                | BootProtocol::LinuxEfiHandover64
        )
    }

    pub fn is_linux_legacy32(self) -> bool {
        matches!(self, BootProtocol::LinuxLegacy32)
    }
}
