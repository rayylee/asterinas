// SPDX-License-Identifier: MPL-2.0

use std::fs::{self, File};

use super::*;

#[test]
fn deserialize_toml_manifest() {
    let content = include_str!("OSDK.toml.full");
    let toml_manifest: manifest::TomlManifest = toml::from_str(content).unwrap();
    let type_ = toml_manifest.project_type.unwrap();
    assert!(type_ == manifest::ProjectType::Kernel);
}

#[test]
fn conditional_manifest() {
    let tmp_file = "/tmp/osdk_test_file";
    File::create(tmp_file).unwrap();

    let toml_manifest: manifest::TomlManifest = {
        let content = include_str!("OSDK.toml.full");
        toml::from_str(content).unwrap()
    };

    // Default scheme
    let scheme = toml_manifest.get_scheme(None::<String>);
    assert_eq!(
        scheme.boot.as_ref().unwrap().method,
        Some(scheme::BootMethod::GrubRescueIso)
    );
    assert_eq!(
        scheme.boot.as_ref().unwrap().protocol,
        Some(scheme::BootProtocol::Multiboot2)
    );
    assert!(
        scheme
            .qemu
            .as_ref()
            .unwrap()
            .args
            .as_ref()
            .unwrap()
            .contains(&String::from("-machine q35",))
    );

    // Iommu
    let scheme = toml_manifest.get_scheme(Some("iommu".to_owned()));
    assert!(
        scheme
            .qemu
            .as_ref()
            .unwrap()
            .args
            .as_ref()
            .unwrap()
            .contains(&String::from("-device ioh3420,id=pcie.0,chassis=1",))
    );

    // Tdx
    let scheme = toml_manifest.get_scheme(Some("tdx".to_owned()));
    assert_eq!(
        scheme.boot.as_ref().unwrap().method,
        Some(scheme::BootMethod::GrubQcow2)
    );
    assert_eq!(
        scheme.boot.as_ref().unwrap().protocol,
        Some(scheme::BootProtocol::LinuxEfiHandover64)
    );
    assert_eq!(
        scheme
            .grub
            .as_ref()
            .unwrap()
            .grub_mkrescue
            .as_ref()
            .unwrap(),
        &PathBuf::from(tmp_file)
    );
    assert_eq!(
        scheme.qemu.as_ref().unwrap().path.as_ref().unwrap(),
        &PathBuf::from(tmp_file)
    );

    fs::remove_file(tmp_file).unwrap();
}
