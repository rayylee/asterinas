# SPDX-License-Identifier: MPL-2.0

TARGET_ARCH ?= x86_64
SMP ?= 1
VERBOSE ?= 1
ENABLE_CONFORMANCE_TEST ?= false
CONFORMANCE_TEST_SUITE ?= ltp
CONFORMANCE_TEST_WORKDIR ?= /tmp
ENABLE_REGRESSION_TEST ?= false
# Specify platform macros when building regression tests (supported: asterinas, linux).
# - asterinas: Define both `__asterinas__` and `__linux__`. Tests may fail in Linux.
# - linux: Define only `__linux__`. Tests may fail in Asterinas.
REGRESSION_TEST_PLATFORM ?= asterinas
DNS_SERVER ?= none
# Set Nix's cached tarballs to be live for a longer period of time (30 days) to avoid network traffics.
# Nix's default value is rather small (1 hour or 3600 seconds).
NIXPKGS_CACHE_TTL := 2592000 # In seconds
MKFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
CUR_DIR := $(patsubst %/,%,$(dir $(MKFILE_PATH)))
BUILD_DIR := $(CUR_DIR)/build
INITRAMFS := $(BUILD_DIR)/initramfs
INITRAMFS_SKIP_GZIP ?= 0
ifeq ($(INITRAMFS_SKIP_GZIP),1)
INITRAMFS_IMAGE := $(BUILD_DIR)/initramfs.cpio
INITRAMFS_COMPRESSED := false
else
INITRAMFS_IMAGE := $(BUILD_DIR)/initramfs.cpio.gz
INITRAMFS_COMPRESSED := true
endif
EXT2_IMAGE := $(BUILD_DIR)/ext2.img
EXFAT_IMAGE := $(BUILD_DIR)/exfat.img
SQUASHFS_IMAGE := $(BUILD_DIR)/squashfs.img
LTP_DEV_IMAGE := $(BUILD_DIR)/ltp_dev.img
SSD_IMAGE := $(BUILD_DIR)/nvme0n1.img
XFSTESTS_TEST_IMAGE := $(BUILD_DIR)/xfstests_test.img
XFSTESTS_SCRATCH_IMAGE := $(BUILD_DIR)/xfstests_scratch.img
XFSTESTS_DISK_SIZE ?= 12G

# Include benchmark, if BENCHMARK is set.
ifeq ($(BENCHMARK), none)
ENABLE_BENCHMARK_TEST = false
else
ENABLE_BENCHMARK_TEST = true
endif

BUILD_XFSTESTS_IMAGES = false
ifeq ($(ENABLE_CONFORMANCE_TEST), true)
ifeq ($(CONFORMANCE_TEST_SUITE), xfstests)
BUILD_XFSTESTS_IMAGES = true
endif
endif

# Decreases the level of verbosity of diagnostic messages from Nix.
ifeq ($(VERBOSE), 0)
NIX_QUIET = --quiet -Q
endif

.PHONY: all
all: build

.PHONY: build
ifeq ($(TARGET_ARCH), loongarch64)
build: $(EXT2_IMAGE) $(EXFAT_IMAGE)
	@echo "For loongarch, we generate a fake initramfs to successfully test or build."
	@touch $(INITRAMFS_IMAGE)
else ifeq ($(BUILD_XFSTESTS_IMAGES), true)
build: $(INITRAMFS_IMAGE) $(EXT2_IMAGE) $(EXFAT_IMAGE) $(LTP_DEV_IMAGE) $(SSD_IMAGE) $(XFSTESTS_TEST_IMAGE) $(XFSTESTS_SCRATCH_IMAGE)
else
build: $(INITRAMFS_IMAGE) $(EXT2_IMAGE) $(EXFAT_IMAGE) $(SQUASHFS_IMAGE) $(LTP_DEV_IMAGE) $(SSD_IMAGE)
endif

.PHONY: $(INITRAMFS_IMAGE)
$(INITRAMFS_IMAGE): $(INITRAMFS)
	@nix-build \
		--tarball-ttl $(NIXPKGS_CACHE_TTL) \
		--argstr target $(TARGET_ARCH) \
		--arg enableBenchmarkTest $(ENABLE_BENCHMARK_TEST) \
		--arg enableConformanceTest $(ENABLE_CONFORMANCE_TEST) \
		--arg enableRegressionTest $(ENABLE_REGRESSION_TEST) \
		--argstr conformanceTestSuite $(CONFORMANCE_TEST_SUITE) \
		--argstr conformanceTestWorkDir $(CONFORMANCE_TEST_WORKDIR) \
		--argstr regressionTestPlatform $(REGRESSION_TEST_PLATFORM) \
		--argstr dnsServer ${DNS_SERVER} \
		--arg initramfsCompressed $(INITRAMFS_COMPRESSED) \
		--arg smp $(SMP) \
		--out-link $@ \
		nix -A initramfs-image

.PHONY: $(INITRAMFS)
$(INITRAMFS):
	@nix-build \
		--tarball-ttl $(NIXPKGS_CACHE_TTL) \
		--argstr target $(TARGET_ARCH) \
		--arg enableBenchmarkTest $(ENABLE_BENCHMARK_TEST) \
		--arg enableConformanceTest $(ENABLE_CONFORMANCE_TEST) \
		--arg enableRegressionTest $(ENABLE_REGRESSION_TEST) \
		--argstr conformanceTestSuite $(CONFORMANCE_TEST_SUITE) \
		--argstr conformanceTestWorkDir $(CONFORMANCE_TEST_WORKDIR) \
		--argstr regressionTestPlatform $(REGRESSION_TEST_PLATFORM) \
		--argstr dnsServer ${DNS_SERVER} \
		--arg smp $(SMP) \
		--out-link $@ \
		nix -A initramfs

# Prebuild x86_64 packages
x86_64_pkgs:
	@nix-build \
		nix/default.nix \
		--tarball-ttl $(NIXPKGS_CACHE_TTL) \
		$(NIX_QUIET) \
		--argstr target x86_64 \
		--arg enableBenchmarkTest true \
		--arg enableConformanceTest true \
		--out-link /nix/var/nix/gcroots/auto/x86_64-pkgs \
		-A busybox \
		-A benchmark.fio \
		-A benchmark.hackbench \
		-A benchmark.iperf3 \
		-A benchmark.lmbench \
		-A benchmark.memcached \
		-A benchmark.nginx \
		-A benchmark.redis \
		-A benchmark.schbench \
		-A benchmark.sqlite-speedtest1 \
		-A benchmark.sysbench \
		-A conformance.ltp \
		-A conformance.kselftest \
		-A regression.package

# Prebuild riscv64 packages
# Note: This may cause GitHub Runner ResourceExhausted errors when publish nix docker image.
# If such errors occur, try building each package individually and clear the build cache.
riscv64_pkgs:
	@nix-build \
		nix/default.nix \
		--tarball-ttl $(NIXPKGS_CACHE_TTL) \
		$(NIX_QUIET) \
		--argstr target riscv64 \
		--arg enableBenchmarkTest false \
		--arg enableConformanceTest true \
		--out-link /nix/var/nix/gcroots/auto/riscv64-pkgs \
		-A busybox \
		-A conformance.ltp \
		-A regression.package

install_host_pkgs:
	@nix-env \
		--file nix/default.nix \
		--tarball-ttl $(NIXPKGS_CACHE_TTL) \
		--install \
		-A apacheHttpd \
		-A iperf3 \
		-A libmemcached \
		-A lmbench \
		-A redis

nix_gc:
	@nix-collect-garbage -d

# This target is used to accelerate CI workflows, e.g., `benchmark_x86` and `benchmark_x86_tdx`.
initramfs_pkgs:
	@nix-build \
		nix/default.nix \
		--tarball-ttl $(NIXPKGS_CACHE_TTL) \
		$(NIX_QUIET) \
		--argstr target x86_64 \
		--arg enableBenchmarkTest true \
		--out-link /nix/var/nix/gcroots/auto/x86_64-initramfs-with-benchmark \
		-A initramfs-image

$(EXT2_IMAGE):
	@mkdir -p $(BUILD_DIR)
	@dd if=/dev/zero of=$(EXT2_IMAGE) bs=2G count=1
	@mke2fs $(EXT2_IMAGE)

$(EXFAT_IMAGE):
	@mkdir -p $(BUILD_DIR)
	@fallocate -l 512M $(EXFAT_IMAGE)
	@mkfs.exfat $(EXFAT_IMAGE)

SQUASHFS_ROOT := $(BUILD_DIR)/squashfs_root
SQUASHFS_LONG_NAME := $(shell printf 'long_filename_%0200d.txt' 0)

$(SQUASHFS_IMAGE):
	@mkdir -p $(BUILD_DIR)
	@rm -rf $(SQUASHFS_ROOT)
	@mkdir -p $(SQUASHFS_ROOT)
	@# Small file
	@printf 'hello squashfs\n' > $(SQUASHFS_ROOT)/small.txt
	@# Empty file
	@touch $(SQUASHFS_ROOT)/empty.txt
	@# Exact block-size file (4096 bytes of 'A')
	@dd if=/dev/zero bs=4096 count=1 2>/dev/null | tr '\0' 'A' > $(SQUASHFS_ROOT)/exact_block.bin
	@# Large file (128KB, each byte = offset % 256)
	@python3 -c "import sys; sys.stdout.buffer.write(bytes([i%256 for i in range(131072)]))" > $(SQUASHFS_ROOT)/large.bin
	@# Fragment file (100 bytes, content "fragment_test" repeated)
	@printf 'fragment_test\n' > $(SQUASHFS_ROOT)/fragment.txt
	@# Symlink
	@ln -s small.txt $(SQUASHFS_ROOT)/link.txt
	@# Deep directory (8 levels)
	@mkdir -p $(SQUASHFS_ROOT)/a/b/c/d/e/f/g/h
	@printf 'deep file\n' > $(SQUASHFS_ROOT)/a/b/c/d/e/f/g/h/deep.txt
	@# Long target symlink (> 60 chars to trigger extended symlink)
	@ln -s a/b/c/d/e/f/g/h/deep.txt $(SQUASHFS_ROOT)/long_target_link
	@# Many entries directory (200 files)
	@mkdir -p $(SQUASHFS_ROOT)/many_entries
	@for i in $$(seq -w 0 199); do touch $(SQUASHFS_ROOT)/many_entries/file_$$i; done
	@# Long filename (255 bytes)
	@touch "$(SQUASHFS_ROOT)/$(SQUASHFS_LONG_NAME)"
	@# Permission variants
	@mkdir -p $(SQUASHFS_ROOT)/permissions
	@touch $(SQUASHFS_ROOT)/permissions/readonly.txt
	@chmod 0444 $(SQUASHFS_ROOT)/permissions/readonly.txt
	@touch $(SQUASHFS_ROOT)/permissions/executable.sh
	@chmod 0755 $(SQUASHFS_ROOT)/permissions/executable.sh
	@touch $(SQUASHFS_ROOT)/permissions/noperm.txt
	@chmod 0000 $(SQUASHFS_ROOT)/permissions/noperm.txt
	@# Mixed types directory
	@mkdir -p $(SQUASHFS_ROOT)/mixed_types/subdir
	@printf 'regular\n' > $(SQUASHFS_ROOT)/mixed_types/regular.txt
	@ln -s regular.txt $(SQUASHFS_ROOT)/mixed_types/symlink
	@mksquashfs $(SQUASHFS_ROOT) $(SQUASHFS_IMAGE) -noappend -comp zstd
	@rm -rf $(SQUASHFS_ROOT)

$(LTP_DEV_IMAGE):
	@mkdir -p $(BUILD_DIR)
	@dd if=/dev/zero of=$(LTP_DEV_IMAGE) bs=512M count=1
	@mke2fs -t ext2 -F $(LTP_DEV_IMAGE)

$(SSD_IMAGE):
	@mkdir -p $(BUILD_DIR)
	@dd if=/dev/zero of=$(SSD_IMAGE) bs=256M count=1
	@mke2fs -t ext2 -F $(SSD_IMAGE)

$(XFSTESTS_TEST_IMAGE):
	@mkdir -p $(BUILD_DIR)
	@truncate -s $(XFSTESTS_DISK_SIZE) $(XFSTESTS_TEST_IMAGE)
	@mkfs.ext2 $(XFSTESTS_TEST_IMAGE)

$(XFSTESTS_SCRATCH_IMAGE):
	@mkdir -p $(BUILD_DIR)
	@truncate -s $(XFSTESTS_DISK_SIZE) $(XFSTESTS_SCRATCH_IMAGE)
	@mkfs.ext2 $(XFSTESTS_SCRATCH_IMAGE)

.PHONY: format
format:
	@$(MAKE) --no-print-directory -C src/regression format
	@nixfmt nix

.PHONY: check
check:
	@$(MAKE) --no-print-directory -C src/regression check
	@nixfmt --check nix

.PHONY: clean
clean:
	@rm -rf $(BUILD_DIR)
