// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/loop.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "../common/test.h"

#define BACKING_PATH "/tmp/loop-device-backing"
#define LOOP_OFFSET 4096
#define LOOP_SIZE 4096

static int backing_fd = -1;
static int loop_fd = -1;
static int loop_index = -1;
static char loop_path[64];

static uint8_t write_buf[LOOP_SIZE];
static uint8_t read_buf[LOOP_SIZE];
static uint8_t backing_buf[LOOP_SIZE];

FN_SETUP(bind_loop_device)
{
	struct stat stat_buf;

	CHECK_WITH(stat("/dev/loop-control", &stat_buf),
		   _ret == 0 && S_ISCHR(stat_buf.st_mode) &&
			   stat_buf.st_rdev == makedev(10, 237));

	int control_fd = CHECK(open("/dev/loop-control", O_RDWR));
	loop_index = CHECK(ioctl(control_fd, LOOP_CTL_GET_FREE));
	CHECK_WITH(loop_index, _ret >= 0 && _ret < 8);
	CHECK_WITH(snprintf(loop_path, sizeof(loop_path), "/dev/loop%d",
			    loop_index),
		   _ret > 0 && (size_t)_ret < sizeof(loop_path));

	CHECK_WITH(stat(loop_path, &stat_buf),
		   _ret == 0 && S_ISBLK(stat_buf.st_mode) &&
			   stat_buf.st_rdev == makedev(7, loop_index));

	backing_fd =
		CHECK(open(BACKING_PATH, O_CREAT | O_RDWR | O_TRUNC, 0644));
	CHECK(ftruncate(backing_fd, LOOP_OFFSET + LOOP_SIZE));

	loop_fd = CHECK(open(loop_path, O_RDWR));
	CHECK(ioctl(loop_fd, LOOP_SET_FD, backing_fd));

	struct loop_info64 info;
	memset(&info, 0, sizeof(info));
	info.lo_offset = LOOP_OFFSET;
	info.lo_sizelimit = LOOP_SIZE;
	strncpy((char *)info.lo_file_name, "loop-device-regression",
		LO_NAME_SIZE - 1);

	CHECK(ioctl(loop_fd, LOOP_SET_STATUS64, &info));
	CHECK(close(control_fd));
}
END_SETUP()

FN_TEST(status_and_capacity)
{
	uint64_t capacity = 0;
	struct loop_info64 info;

	memset(&info, 0, sizeof(info));

	TEST_RES(ioctl(loop_fd, BLKGETSIZE64, &capacity),
		 _ret == 0 && capacity == LOOP_SIZE);
	TEST_RES(lseek(loop_fd, 0, SEEK_END), _ret == LOOP_SIZE);
	TEST_RES(lseek(loop_fd, 0, SEEK_SET), _ret == 0);
	TEST_RES(ioctl(loop_fd, LOOP_GET_STATUS64, &info),
		 _ret == 0 && info.lo_number == (uint32_t)loop_index &&
			 info.lo_offset == LOOP_OFFSET &&
			 info.lo_sizelimit == LOOP_SIZE);
}
END_TEST()

FN_TEST(read_write_backing_file)
{
	for (size_t i = 0; i < sizeof(write_buf); i++) {
		write_buf[i] = (uint8_t)(i ^ 0xa5);
	}

	memset(read_buf, 0, sizeof(read_buf));
	memset(backing_buf, 0, sizeof(backing_buf));

	TEST_RES(pwrite(loop_fd, write_buf, sizeof(write_buf), 0),
		 _ret == (ssize_t)sizeof(write_buf));
	TEST_RES(pread(loop_fd, read_buf, sizeof(read_buf), 0),
		 _ret == (ssize_t)sizeof(read_buf));
	TEST_RES(memcmp(read_buf, write_buf, sizeof(read_buf)), _ret == 0);

	TEST_RES(pread(backing_fd, backing_buf, sizeof(backing_buf),
		       LOOP_OFFSET),
		 _ret == (ssize_t)sizeof(backing_buf));
	TEST_RES(memcmp(backing_buf, write_buf, sizeof(backing_buf)),
		 _ret == 0);
}
END_TEST()

FN_TEST(unaligned_read_write)
{
	const off_t offset = 123;
	uint8_t unaligned_write_buf[37];
	uint8_t unaligned_read_buf[sizeof(unaligned_write_buf)];

	for (size_t i = 0; i < sizeof(unaligned_write_buf); i++) {
		unaligned_write_buf[i] = (uint8_t)(0x5a ^ i);
	}

	memset(unaligned_read_buf, 0, sizeof(unaligned_read_buf));

	TEST_RES(pwrite(loop_fd, unaligned_write_buf,
			sizeof(unaligned_write_buf), offset),
		 _ret == (ssize_t)sizeof(unaligned_write_buf));
	TEST_RES(pread(loop_fd, unaligned_read_buf, sizeof(unaligned_read_buf),
		       offset),
		 _ret == (ssize_t)sizeof(unaligned_read_buf));
	TEST_RES(memcmp(unaligned_read_buf, unaligned_write_buf,
			sizeof(unaligned_read_buf)),
		 _ret == 0);
}
END_TEST()

FN_SETUP(cleanup_loop_device)
{
	if (loop_fd >= 0) {
		CHECK(ioctl(loop_fd, LOOP_CLR_FD));
		CHECK(close(loop_fd));
		loop_fd = -1;
	}

	if (backing_fd >= 0) {
		CHECK(close(backing_fd));
		backing_fd = -1;
	}

	CHECK(unlink(BACKING_PATH));
}
END_SETUP()
