// SPDX-License-Identifier: MPL-2.0

#include <stdint.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/fcntl.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#include "../../common/test.h"

#ifndef SYS_io_setup
#error "SYS_io_setup is not defined by the target libc"
#endif

#define IOCB_CMD_PREAD 0
#define IOCB_CMD_PWRITE 1
#define IOCB_CMD_PREADV 7
#define IOCB_CMD_PWRITEV 8
#define IOCB_FLAG_RESFD (1U << 0)
#define AIO_RING_MAGIC 0xa10a10a1

typedef uint64_t aio_context_t;

struct aio_iocb {
	uint64_t aio_data;
	uint32_t aio_key;
	int32_t aio_rw_flags;
	uint16_t aio_lio_opcode;
	int16_t aio_reqprio;
	uint32_t aio_fildes;
	uint64_t aio_buf;
	uint64_t aio_nbytes;
	int64_t aio_offset;
	uint64_t aio_reserved2;
	uint32_t aio_flags;
	uint32_t aio_resfd;
};

struct aio_event {
	uint64_t data;
	uint64_t obj;
	int64_t res;
	int64_t res2;
};

struct aio_ring {
	uint32_t id;
	uint32_t nr;
	uint32_t head;
	uint32_t tail;
	uint32_t magic;
	uint32_t compat_features;
	uint32_t incompat_features;
	uint32_t header_length;
	struct aio_event io_events[];
};

static long raw_io_setup(unsigned nr_events, aio_context_t *ctxp)
{
	return syscall(SYS_io_setup, nr_events, ctxp);
}

static long raw_io_destroy(aio_context_t ctx)
{
	return syscall(SYS_io_destroy, ctx);
}

static long raw_io_submit(aio_context_t ctx, long nr, struct aio_iocb **iocbs)
{
	return syscall(SYS_io_submit, ctx, nr, iocbs);
}

static long raw_io_getevents(aio_context_t ctx, long min_nr, long nr,
			     struct aio_event *events, void *timeout)
{
	return syscall(SYS_io_getevents, ctx, min_nr, nr, events, timeout);
}

static long raw_io_pgetevents(aio_context_t ctx, long min_nr, long nr,
			      struct aio_event *events, void *timeout,
			      void *sigmask)
{
	return syscall(SYS_io_pgetevents, ctx, min_nr, nr, events, timeout,
		       sigmask);
}

static long raw_io_cancel(aio_context_t ctx, struct aio_iocb *iocb,
			  struct aio_event *event)
{
	return syscall(SYS_io_cancel, ctx, iocb, event);
}

static int open_test_file(const char *path)
{
	return open(path, O_CREAT | O_RDWR | O_TRUNC, 0600);
}

static int wait_ring_event(struct aio_ring *ring)
{
	for (int i = 0; i < 100000; i++) {
		if (ring->head != ring->tail)
			return 0;
		usleep(100);
	}

	errno = ETIMEDOUT;
	return -1;
}

#define SUBMIT_ONE_AND_WAIT(ctx, iocb, event)                                  \
	({                                                                     \
		struct aio_iocb *iocbs[] = { iocb };                           \
		TEST_RES(raw_io_submit(ctx, 1, iocbs), _ret == 1);             \
		TEST_RES(raw_io_getevents(ctx, 1, 1, event, NULL), _ret == 1); \
		TEST_RES((event)->obj, _ret == (uint64_t)(uintptr_t)(iocb));   \
		TEST_RES((event)->res2, _ret == 0);                            \
	})

FN_TEST(setup_destroy_errors)
{
	aio_context_t ctx = 0;
	struct aio_iocb iocb = { 0 };
	struct aio_event event;

	TEST_ERRNO(raw_io_setup(0, &ctx), EINVAL);
	TEST_ERRNO(raw_io_destroy(0), EINVAL);
	TEST_ERRNO(raw_io_cancel(0, &iocb, &event), EINVAL);

	TEST_RES(raw_io_setup(2, &ctx), _ret == 0 && ctx != 0);
	TEST_ERRNO(raw_io_getevents(ctx, 2, 1, &event, NULL), EINVAL);
	TEST_RES(raw_io_destroy(ctx), _ret == 0);
}
END_TEST()

FN_TEST(read_write)
{
	const char *path = "/tmp/aio_read_write";
	const char *message = "hello aio";
	char read_buf[32] = { 0 };
	aio_context_t ctx = 0;
	struct aio_iocb iocb;
	struct aio_event event;
	int fd;

	fd = TEST_SUCC(open_test_file(path));
	TEST_RES(raw_io_setup(4, &ctx), _ret == 0 && ctx != 0);

	memset(&iocb, 0, sizeof(iocb));
	iocb.aio_data = 0x101;
	iocb.aio_lio_opcode = IOCB_CMD_PWRITE;
	iocb.aio_fildes = fd;
	iocb.aio_buf = (uint64_t)(uintptr_t)message;
	iocb.aio_nbytes = strlen(message);
	SUBMIT_ONE_AND_WAIT(ctx, &iocb, &event);
	TEST_RES(event.data, _ret == 0x101);
	TEST_RES(event.res, _ret == (int64_t)strlen(message));

	memset(&iocb, 0, sizeof(iocb));
	iocb.aio_data = 0x202;
	iocb.aio_lio_opcode = IOCB_CMD_PREAD;
	iocb.aio_fildes = fd;
	iocb.aio_buf = (uint64_t)(uintptr_t)read_buf;
	iocb.aio_nbytes = strlen(message);
	SUBMIT_ONE_AND_WAIT(ctx, &iocb, &event);
	TEST_RES(event.data, _ret == 0x202);
	TEST_RES(event.res, _ret == (int64_t)strlen(message));
	TEST_RES(memcmp(read_buf, message, strlen(message)), _ret == 0);

	TEST_RES(raw_io_destroy(ctx), _ret == 0);
	TEST_SUCC(close(fd));
	TEST_SUCC(unlink(path));
}
END_TEST()

FN_TEST(userspace_ring_reap)
{
	const char *path = "/tmp/aio_ring_reap";
	const char payload[] = "ring";
	aio_context_t ctx = 0;
	struct aio_iocb iocb;
	struct aio_iocb *iocbs[] = { &iocb };
	struct aio_event event;
	struct aio_ring *ring;
	uint32_t head;
	int fd;

	fd = TEST_SUCC(open_test_file(path));
	TEST_RES(raw_io_setup(2, &ctx), _ret == 0 && ctx != 0);
	ring = (struct aio_ring *)(uintptr_t)ctx;
	TEST_RES(ring->magic, _ret == AIO_RING_MAGIC);
	TEST_RES(ring->nr, _ret >= 3);
	TEST_RES(ring->header_length, _ret == sizeof(struct aio_ring));

	memset(&iocb, 0, sizeof(iocb));
	iocb.aio_data = 0x303;
	iocb.aio_lio_opcode = IOCB_CMD_PWRITE;
	iocb.aio_fildes = fd;
	iocb.aio_buf = (uint64_t)(uintptr_t)payload;
	iocb.aio_nbytes = sizeof(payload);
	TEST_RES(raw_io_submit(ctx, 1, iocbs), _ret == 1);

	TEST_RES(wait_ring_event(ring), _ret == 0);
	head = ring->head;
	event = ring->io_events[head];
	ring->head = (head + 1) % ring->nr;

	TEST_RES(event.data, _ret == 0x303);
	TEST_RES(event.obj, _ret == (uint64_t)(uintptr_t)&iocb);
	TEST_RES(event.res, _ret == (int64_t)sizeof(payload));
	TEST_RES(event.res2, _ret == 0);
	TEST_RES(raw_io_getevents(ctx, 0, 1, &event, NULL), _ret == 0);

	TEST_RES(raw_io_destroy(ctx), _ret == 0);
	TEST_SUCC(close(fd));
	TEST_SUCC(unlink(path));
}
END_TEST()

FN_TEST(eventfd_completion)
{
	const char *path = "/tmp/aio_eventfd";
	const char payload[] = "eventfd";
	aio_context_t ctx = 0;
	struct aio_iocb iocb;
	struct aio_event event;
	uint64_t counter = 0;
	int fd;
	int efd;

	fd = TEST_SUCC(open_test_file(path));
	efd = TEST_SUCC(eventfd(0, 0));
	TEST_RES(raw_io_setup(2, &ctx), _ret == 0 && ctx != 0);

	memset(&iocb, 0, sizeof(iocb));
	iocb.aio_lio_opcode = IOCB_CMD_PWRITE;
	iocb.aio_fildes = fd;
	iocb.aio_buf = (uint64_t)(uintptr_t)payload;
	iocb.aio_nbytes = sizeof(payload);
	iocb.aio_flags = IOCB_FLAG_RESFD;
	iocb.aio_resfd = efd;
	SUBMIT_ONE_AND_WAIT(ctx, &iocb, &event);
	TEST_RES(event.res, _ret == (int64_t)sizeof(payload));
	TEST_RES(read(efd, &counter, sizeof(counter)),
		 _ret == (ssize_t)sizeof(counter));
	TEST_RES(counter, _ret == 1);

	TEST_RES(raw_io_destroy(ctx), _ret == 0);
	TEST_SUCC(close(efd));
	TEST_SUCC(close(fd));
	TEST_SUCC(unlink(path));
}
END_TEST()

FN_TEST(pgetevents)
{
	const char *path = "/tmp/aio_pgetevents";
	const char payload[] = "pgetevents";
	aio_context_t ctx = 0;
	struct aio_iocb iocb;
	struct aio_iocb *iocbs[] = { &iocb };
	struct aio_event event;
	int fd;

	fd = TEST_SUCC(open_test_file(path));
	TEST_RES(raw_io_setup(2, &ctx), _ret == 0 && ctx != 0);

	memset(&iocb, 0, sizeof(iocb));
	iocb.aio_lio_opcode = IOCB_CMD_PWRITE;
	iocb.aio_fildes = fd;
	iocb.aio_buf = (uint64_t)(uintptr_t)payload;
	iocb.aio_nbytes = sizeof(payload);
	TEST_RES(raw_io_submit(ctx, 1, iocbs), _ret == 1);
	TEST_RES(raw_io_pgetevents(ctx, 1, 1, &event, NULL, NULL), _ret == 1);
	TEST_RES(event.res, _ret == (int64_t)sizeof(payload));

	TEST_RES(raw_io_destroy(ctx), _ret == 0);
	TEST_SUCC(close(fd));
	TEST_SUCC(unlink(path));
}
END_TEST()

FN_TEST(vectored_io)
{
	const char *path = "/tmp/aio_vectored";
	char first[8] = { 0 };
	char second[8] = { 0 };
	aio_context_t ctx = 0;
	struct iovec write_iov[] = {
		{ .iov_base = "vec-", .iov_len = 4 },
		{ .iov_base = "aio", .iov_len = 3 },
	};
	struct iovec read_iov[] = {
		{ .iov_base = first, .iov_len = 4 },
		{ .iov_base = second, .iov_len = 3 },
	};
	struct aio_iocb iocb;
	struct aio_event event;
	int fd;

	fd = TEST_SUCC(open_test_file(path));
	TEST_RES(raw_io_setup(4, &ctx), _ret == 0 && ctx != 0);

	memset(&iocb, 0, sizeof(iocb));
	iocb.aio_lio_opcode = IOCB_CMD_PWRITEV;
	iocb.aio_fildes = fd;
	iocb.aio_buf = (uint64_t)(uintptr_t)write_iov;
	iocb.aio_nbytes = sizeof(write_iov) / sizeof(write_iov[0]);
	SUBMIT_ONE_AND_WAIT(ctx, &iocb, &event);
	TEST_RES(event.res, _ret == 7);

	memset(&iocb, 0, sizeof(iocb));
	iocb.aio_lio_opcode = IOCB_CMD_PREADV;
	iocb.aio_fildes = fd;
	iocb.aio_buf = (uint64_t)(uintptr_t)read_iov;
	iocb.aio_nbytes = sizeof(read_iov) / sizeof(read_iov[0]);
	SUBMIT_ONE_AND_WAIT(ctx, &iocb, &event);
	TEST_RES(event.res, _ret == 7);
	TEST_RES(memcmp(first, "vec-", 4), _ret == 0);
	TEST_RES(memcmp(second, "aio", 3), _ret == 0);

	TEST_RES(raw_io_destroy(ctx), _ret == 0);
	TEST_SUCC(close(fd));
	TEST_SUCC(unlink(path));
}
END_TEST()
