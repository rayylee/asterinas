// SPDX-License-Identifier: MPL-2.0
//
// Regression tests for Linux AIO syscalls:
//   io_setup / io_destroy / io_submit / io_getevents / io_cancel
//
// Tests are organized in three groups:
//   1. Error-path tests  — invalid arguments return correct errno
//   2. Basic functional  — single pread/pwrite, data integrity, event.data
//   3. Batch             — multiple iocbs submitted at once, context reuse

#define _GNU_SOURCE

#include "../../common/test.h"
#include <fcntl.h>
#include <linux/aio_abi.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

// ============================================================================
// Syscall wrappers
// ============================================================================

static inline int io_setup(unsigned nr, aio_context_t *ctx)
{
	return syscall(SYS_io_setup, nr, ctx);
}

static inline int io_destroy(aio_context_t ctx)
{
	return syscall(SYS_io_destroy, ctx);
}

static inline int io_submit(aio_context_t ctx, long nr, struct iocb **iocbpp)
{
	return syscall(SYS_io_submit, ctx, nr, iocbpp);
}

static inline int io_getevents(aio_context_t ctx, long min_nr, long nr,
			       struct io_event *events,
			       struct timespec *timeout)
{
	return syscall(SYS_io_getevents, ctx, min_nr, nr, events, timeout);
}

static inline int io_cancel(aio_context_t ctx, struct iocb *iocb,
			    struct io_event *result)
{
	return syscall(SYS_io_cancel, ctx, iocb, result);
}

// ============================================================================
// Shared state
// ============================================================================

#define TEST_FILE "/tmp/aio_regression_data"
#define BUF_SIZE  4096
#define N_OPS     8

static int g_fd = -1;
static char g_wbuf[BUF_SIZE];
static char g_rbuf[BUF_SIZE];

static void fill_pattern(char *buf, size_t len, char base)
{
	for (size_t i = 0; i < len; i++)
		buf[i] = (char)(base + (i % 64));
}

FN_SETUP(prepare)
{
	fill_pattern(g_wbuf, BUF_SIZE, 'A');
	memset(g_rbuf, 0, BUF_SIZE);

	g_fd = CHECK(open(TEST_FILE, O_RDWR | O_CREAT | O_TRUNC, 0600));
	// Pre-allocate space for all tests (N_OPS * BUF_SIZE bytes).
	CHECK(ftruncate(g_fd, (off_t)N_OPS * BUF_SIZE));
	// Fill with known pattern so reads always see real data.
	for (int i = 0; i < N_OPS; i++) {
		char buf[BUF_SIZE];
		memset(buf, 'A' + i, BUF_SIZE);
		CHECK(pwrite(g_fd, buf, BUF_SIZE, (off_t)i * BUF_SIZE));
	}
}
END_SETUP()

// ============================================================================
// Group 1 — Error paths
// ============================================================================

FN_TEST(io_setup_zero_nr)
{
	aio_context_t ctx = 0;
	TEST_ERRNO(io_setup(0, &ctx), EINVAL);
}
END_TEST()

FN_TEST(io_setup_null_ctx)
{
	TEST_ERRNO(io_setup(1, NULL), EFAULT);
}
END_TEST()

FN_TEST(io_setup_nr_too_large)
{
	aio_context_t ctx = 0;
	// Linux returns EAGAIN when nr_events exceeds the system limit.
	TEST_ERRNO(io_setup(0x10001, &ctx), EAGAIN);
}
END_TEST()

FN_TEST(io_destroy_invalid_ctx)
{
	TEST_ERRNO(io_destroy((aio_context_t)0xdeadbeef), EINVAL);
}
END_TEST()

FN_TEST(io_destroy_zero_ctx)
{
	TEST_ERRNO(io_destroy(0), EINVAL);
}
END_TEST()

FN_TEST(io_destroy_double_destroy)
{
	aio_context_t ctx = 0;
	CHECK(io_setup(4, &ctx));
	CHECK(io_destroy(ctx));
	TEST_ERRNO(io_destroy(ctx), EINVAL);
}
END_TEST()

FN_TEST(io_submit_invalid_ctx)
{
	struct iocb cb = {};
	struct iocb *cbs[1] = { &cb };
	TEST_ERRNO(io_submit((aio_context_t)0xdeadbeef, 1, cbs), EINVAL);
}
END_TEST()

FN_TEST(io_submit_negative_nr)
{
	aio_context_t ctx = 0;
	CHECK(io_setup(4, &ctx));
	struct iocb cb = {};
	struct iocb *cbs[1] = { &cb };
	TEST_ERRNO(io_submit(ctx, -1, cbs), EINVAL);
	CHECK(io_destroy(ctx));
}
END_TEST()

FN_TEST(io_submit_null_iocb)
{
	aio_context_t ctx = 0;
	CHECK(io_setup(4, &ctx));
	struct iocb *cbs[1] = { NULL };
	// Linux returns EFAULT when the iocb pointer itself is NULL.
	TEST_ERRNO(io_submit(ctx, 1, cbs), EFAULT);
	CHECK(io_destroy(ctx));
}
END_TEST()

FN_TEST(io_submit_bad_opcode)
{
	aio_context_t ctx = 0;
	CHECK(io_setup(4, &ctx));
	char buf[BUF_SIZE];
	struct iocb cb = {};
	cb.aio_lio_opcode = 0xFF;
	cb.aio_fildes = g_fd;
	cb.aio_buf = (__u64)(uintptr_t)buf;
	cb.aio_nbytes = BUF_SIZE;
	struct iocb *cbs[1] = { &cb };
	TEST_ERRNO(io_submit(ctx, 1, cbs), EINVAL);
	CHECK(io_destroy(ctx));
}
END_TEST()

FN_TEST(io_getevents_invalid_ctx)
{
	struct io_event ev;
	struct timespec ts = {};
	TEST_ERRNO(io_getevents((aio_context_t)0xdeadbeef, 0, 1, &ev, &ts),
		   EINVAL);
}
END_TEST()

FN_TEST(io_getevents_negative_nr)
{
	aio_context_t ctx = 0;
	CHECK(io_setup(4, &ctx));
	struct io_event ev;
	struct timespec ts = {};
	TEST_ERRNO(io_getevents(ctx, -1, 1, &ev, &ts), EINVAL);
	TEST_ERRNO(io_getevents(ctx, 0, -1, &ev, &ts), EINVAL);
	CHECK(io_destroy(ctx));
}
END_TEST()

FN_TEST(io_getevents_min_gt_nr)
{
	aio_context_t ctx = 0;
	CHECK(io_setup(4, &ctx));
	struct io_event ev;
	struct timespec ts = {};
	TEST_ERRNO(io_getevents(ctx, 5, 4, &ev, &ts), EINVAL);
	CHECK(io_destroy(ctx));
}
END_TEST()

FN_TEST(io_cancel_invalid_ctx)
{
	struct iocb cb = {};
	struct io_event result;
	TEST_ERRNO(io_cancel((aio_context_t)0xdeadbeef, &cb, &result), EINVAL);
}
END_TEST()

FN_TEST(io_cancel_returns_einval)
{
	aio_context_t ctx = 0;
	CHECK(io_setup(4, &ctx));
	struct iocb cb = {};
	struct io_event result;
	// iocb not in the queue: Linux returns EINVAL.
	TEST_ERRNO(io_cancel(ctx, &cb, &result), EINVAL);
	CHECK(io_destroy(ctx));
}
END_TEST()

// ============================================================================
// Group 2 — Basic functional
// ============================================================================

FN_TEST(setup_and_destroy)
{
	aio_context_t ctx = 0;
	TEST_SUCC(io_setup(8, &ctx));
	TEST_RES(0, ctx != 0);
	TEST_SUCC(io_destroy(ctx));
}
END_TEST()

FN_TEST(setup_multiple_contexts)
{
	aio_context_t ctx1 = 0, ctx2 = 0, ctx3 = 0;
	TEST_SUCC(io_setup(4, &ctx1));
	TEST_SUCC(io_setup(4, &ctx2));
	TEST_SUCC(io_setup(4, &ctx3));
	TEST_RES(0, ctx1 != 0 && ctx2 != 0 && ctx3 != 0);
	TEST_RES(0, ctx1 != ctx2 && ctx2 != ctx3 && ctx1 != ctx3);
	TEST_SUCC(io_destroy(ctx1));
	TEST_SUCC(io_destroy(ctx2));
	TEST_SUCC(io_destroy(ctx3));
}
END_TEST()

FN_TEST(submit_zero)
{
	aio_context_t ctx = 0;
	CHECK(io_setup(8, &ctx));
	TEST_RES(io_submit(ctx, 0, NULL), _ret == 0);
	CHECK(io_destroy(ctx));
}
END_TEST()

FN_TEST(getevents_empty_zero_timeout)
{
	aio_context_t ctx = 0;
	CHECK(io_setup(8, &ctx));
	struct io_event evs[8];
	struct timespec ts = {};
	TEST_RES(io_getevents(ctx, 0, 8, evs, &ts), _ret == 0);
	CHECK(io_destroy(ctx));
}
END_TEST()

FN_TEST(single_pwrite)
{
	aio_context_t ctx = 0;
	CHECK(io_setup(8, &ctx));

	struct iocb cb = {};
	cb.aio_lio_opcode = IOCB_CMD_PWRITE;
	cb.aio_fildes = g_fd;
	cb.aio_buf = (__u64)(uintptr_t)g_wbuf;
	cb.aio_nbytes = BUF_SIZE;
	cb.aio_offset = 0;

	struct iocb *cbs[1] = { &cb };
	TEST_RES(io_submit(ctx, 1, cbs), _ret == 1);

	struct io_event ev;
	struct timespec ts = { .tv_sec = 2 };
	TEST_RES(io_getevents(ctx, 1, 1, &ev, &ts), _ret == 1);
	TEST_RES(0, (long long)ev.res == BUF_SIZE);

	CHECK(io_destroy(ctx));
}
END_TEST()

FN_TEST(single_pread)
{
	aio_context_t ctx = 0;
	CHECK(io_setup(8, &ctx));

	// Read from slot 1 (offset=BUF_SIZE), which single_pwrite does not touch.
	memset(g_rbuf, 0, BUF_SIZE);
	struct iocb cb = {};
	cb.aio_lio_opcode = IOCB_CMD_PREAD;
	cb.aio_fildes = g_fd;
	cb.aio_buf = (__u64)(uintptr_t)g_rbuf;
	cb.aio_nbytes = BUF_SIZE;
	cb.aio_offset = BUF_SIZE; // slot 1: setup filled with 'B'

	struct iocb *cbs[1] = { &cb };
	TEST_RES(io_submit(ctx, 1, cbs), _ret == 1);

	struct io_event ev;
	struct timespec ts = { .tv_sec = 2 };
	TEST_RES(io_getevents(ctx, 1, 1, &ev, &ts), _ret == 1);
	TEST_RES(0, (long long)ev.res == BUF_SIZE);

	// Data integrity: slot 1 was filled with 'B' in setup.
	char expected[BUF_SIZE];
	memset(expected, 'B', BUF_SIZE);
	TEST_RES(0, memcmp(g_rbuf, expected, BUF_SIZE) == 0);

	CHECK(io_destroy(ctx));
}
END_TEST()

FN_TEST(event_data_preserved)
{
	aio_context_t ctx = 0;
	CHECK(io_setup(8, &ctx));

	const __u64 sentinel = 0xCAFEBABEDEADBEEFULL;
	struct iocb cb = {};
	cb.aio_data = sentinel;
	cb.aio_lio_opcode = IOCB_CMD_PREAD;
	cb.aio_fildes = g_fd;
	cb.aio_buf = (__u64)(uintptr_t)g_rbuf;
	cb.aio_nbytes = BUF_SIZE;
	cb.aio_offset = 0;

	struct iocb *cbs[1] = { &cb };
	CHECK(io_submit(ctx, 1, cbs));

	struct io_event ev;
	struct timespec ts = { .tv_sec = 2 };
	TEST_RES(io_getevents(ctx, 1, 1, &ev, &ts), _ret == 1);
	TEST_RES(0, ev.data == sentinel);

	CHECK(io_destroy(ctx));
}
END_TEST()

FN_TEST(pwrite_pread_at_offset)
{
	const off_t offset = (off_t)BUF_SIZE * 2;
	char wbuf[BUF_SIZE], rbuf[BUF_SIZE];
	fill_pattern(wbuf, BUF_SIZE, 'Z');
	memset(rbuf, 0, BUF_SIZE);

	aio_context_t ctx = 0;
	CHECK(io_setup(8, &ctx));

	struct iocb wcb = {};
	wcb.aio_lio_opcode = IOCB_CMD_PWRITE;
	wcb.aio_fildes = g_fd;
	wcb.aio_buf = (__u64)(uintptr_t)wbuf;
	wcb.aio_nbytes = BUF_SIZE;
	wcb.aio_offset = offset;

	struct iocb *wcbs[1] = { &wcb };
	CHECK(io_submit(ctx, 1, wcbs));

	struct io_event wev;
	struct timespec ts = { .tv_sec = 2 };
	TEST_RES(io_getevents(ctx, 1, 1, &wev, &ts), _ret == 1);
	TEST_RES(0, (long long)wev.res == BUF_SIZE);

	struct iocb rcb = {};
	rcb.aio_lio_opcode = IOCB_CMD_PREAD;
	rcb.aio_fildes = g_fd;
	rcb.aio_buf = (__u64)(uintptr_t)rbuf;
	rcb.aio_nbytes = BUF_SIZE;
	rcb.aio_offset = offset;

	struct iocb *rcbs[1] = { &rcb };
	CHECK(io_submit(ctx, 1, rcbs));

	struct io_event rev;
	ts.tv_sec = 2;
	TEST_RES(io_getevents(ctx, 1, 1, &rev, &ts), _ret == 1);
	TEST_RES(0, (long long)rev.res == BUF_SIZE);
	TEST_RES(0, memcmp(rbuf, wbuf, BUF_SIZE) == 0);

	CHECK(io_destroy(ctx));
}
END_TEST()

FN_TEST(getevents_null_timeout)
{
	aio_context_t ctx = 0;
	CHECK(io_setup(8, &ctx));

	struct iocb cb = {};
	cb.aio_lio_opcode = IOCB_CMD_PREAD;
	cb.aio_fildes = g_fd;
	cb.aio_buf = (__u64)(uintptr_t)g_rbuf;
	cb.aio_nbytes = BUF_SIZE;
	cb.aio_offset = 0;

	struct iocb *cbs[1] = { &cb };
	CHECK(io_submit(ctx, 1, cbs));

	struct io_event ev;
	// NULL timeout: wait indefinitely until the read finishes.
	TEST_RES(io_getevents(ctx, 1, 1, &ev, NULL), _ret == 1);
	TEST_RES(0, (long long)ev.res == BUF_SIZE);

	CHECK(io_destroy(ctx));
}
END_TEST()

// ============================================================================
// Group 3 — Batch submit
// ============================================================================

FN_TEST(batch_pread)
{
	aio_context_t ctx = 0;
	CHECK(io_setup(N_OPS * 2, &ctx));

	// Write known data synchronously first so reads see predictable content.
	for (int i = 0; i < N_OPS; i++) {
		char wbuf[BUF_SIZE];
		memset(wbuf, 'A' + i, BUF_SIZE);
		CHECK(pwrite(g_fd, wbuf, BUF_SIZE, (off_t)i * BUF_SIZE));
	}

	char rbufs[N_OPS][BUF_SIZE];
	struct iocb cbs[N_OPS];
	struct iocb *cbps[N_OPS];

	memset(rbufs, 0, sizeof(rbufs));
	memset(cbs, 0, sizeof(cbs));

	for (int i = 0; i < N_OPS; i++) {
		cbs[i].aio_lio_opcode = IOCB_CMD_PREAD;
		cbs[i].aio_fildes = g_fd;
		cbs[i].aio_buf = (__u64)(uintptr_t)rbufs[i];
		cbs[i].aio_nbytes = BUF_SIZE;
		cbs[i].aio_offset = (off_t)i * BUF_SIZE;
		cbs[i].aio_data = (__u64)i;
		cbps[i] = &cbs[i];
	}

	TEST_RES(io_submit(ctx, N_OPS, cbps), _ret == N_OPS);

	struct io_event evs[N_OPS];
	struct timespec ts = { .tv_sec = 5 };
	int total = 0;
	while (total < N_OPS) {
		int n = io_getevents(ctx, 1, N_OPS - total, evs + total, &ts);
		if (n <= 0)
			break;
		total += n;
	}
	TEST_RES(0, total == N_OPS);

	// Use ev.data (stores index) to verify each buffer's content.
	int all_ok = 1;
	for (int i = 0; i < total; i++) {
		if ((long long)evs[i].res != BUF_SIZE) {
			all_ok = 0;
			continue;
		}
		int idx = (int)evs[i].data;
		if (idx < 0 || idx >= N_OPS) {
			all_ok = 0;
			continue;
		}
		char expected[BUF_SIZE];
		memset(expected, 'A' + idx, BUF_SIZE);
		if (memcmp(rbufs[idx], expected, BUF_SIZE) != 0)
			all_ok = 0;
	}
	TEST_RES(0, all_ok);

	CHECK(io_destroy(ctx));
}
END_TEST()

FN_TEST(batch_pwrite_then_verify)
{
	aio_context_t ctx = 0;
	CHECK(io_setup(N_OPS * 2, &ctx));

	char wbufs[N_OPS][BUF_SIZE];
	struct iocb cbs[N_OPS];
	struct iocb *cbps[N_OPS];

	for (int i = 0; i < N_OPS; i++) {
		memset(wbufs[i], 'a' + i, BUF_SIZE);
		memset(&cbs[i], 0, sizeof(cbs[i]));
		cbs[i].aio_lio_opcode = IOCB_CMD_PWRITE;
		cbs[i].aio_fildes = g_fd;
		cbs[i].aio_buf = (__u64)(uintptr_t)wbufs[i];
		cbs[i].aio_nbytes = BUF_SIZE;
		cbs[i].aio_offset = (off_t)i * BUF_SIZE;
		cbps[i] = &cbs[i];
	}

	TEST_RES(io_submit(ctx, N_OPS, cbps), _ret == N_OPS);

	struct io_event evs[N_OPS];
	struct timespec ts = { .tv_sec = 5 };
	int total = 0;
	while (total < N_OPS) {
		int n = io_getevents(ctx, 1, N_OPS - total, evs + total, &ts);
		if (n <= 0)
			break;
		total += n;
	}
	TEST_RES(0, total == N_OPS);

	// Synchronously read back and verify.
	int all_ok = 1;
	for (int i = 0; i < N_OPS; i++) {
		char rbuf[BUF_SIZE];
		memset(rbuf, 0, BUF_SIZE);
		if (pread(g_fd, rbuf, BUF_SIZE, (off_t)i * BUF_SIZE) != BUF_SIZE) {
			all_ok = 0;
			continue;
		}
		char expected[BUF_SIZE];
		memset(expected, 'a' + i, BUF_SIZE);
		if (memcmp(rbuf, expected, BUF_SIZE) != 0)
			all_ok = 0;
	}
	TEST_RES(0, all_ok);

	CHECK(io_destroy(ctx));
}
END_TEST()

FN_TEST(getevents_min_nr_zero)
{
	aio_context_t ctx = 0;
	CHECK(io_setup(N_OPS * 2, &ctx));

	struct iocb cbs[N_OPS];
	struct iocb *cbps[N_OPS];
	static char rbufs[N_OPS][BUF_SIZE];

	memset(cbs, 0, sizeof(cbs));
	for (int i = 0; i < N_OPS; i++) {
		cbs[i].aio_lio_opcode = IOCB_CMD_PREAD;
		cbs[i].aio_fildes = g_fd;
		cbs[i].aio_buf = (__u64)(uintptr_t)rbufs[i];
		cbs[i].aio_nbytes = BUF_SIZE;
		cbs[i].aio_offset = (off_t)i * BUF_SIZE;
		cbps[i] = &cbs[i];
	}
	CHECK(io_submit(ctx, N_OPS, cbps));

	// min_nr=0 with zero timeout: must not block, return >= 0.
	struct io_event evs[N_OPS];
	struct timespec ts = {};
	int first = io_getevents(ctx, 0, N_OPS, evs, &ts);
	TEST_RES(0, first >= 0);

	// Drain remaining events.
	int collected = first;
	while (collected < N_OPS) {
		struct timespec ts2 = { .tv_sec = 5 };
		int n = io_getevents(ctx, 1, N_OPS - collected,
				     evs + collected, &ts2);
		if (n <= 0)
			break;
		collected += n;
	}
	TEST_RES(0, collected == N_OPS);

	CHECK(io_destroy(ctx));
}
END_TEST()

FN_TEST(context_reuse)
{
	aio_context_t ctx = 0;
	CHECK(io_setup(8, &ctx));

	char buf[BUF_SIZE];
	for (int round = 0; round < 3; round++) {
		struct iocb cb = {};
		cb.aio_lio_opcode = IOCB_CMD_PREAD;
		cb.aio_fildes = g_fd;
		cb.aio_buf = (__u64)(uintptr_t)buf;
		cb.aio_nbytes = BUF_SIZE;
		cb.aio_offset = 0;
		cb.aio_data = (__u64)round;

		struct iocb *cbs[1] = { &cb };
		CHECK(io_submit(ctx, 1, cbs));

		struct io_event ev;
		struct timespec ts = { .tv_sec = 2 };
		TEST_RES(io_getevents(ctx, 1, 1, &ev, &ts), _ret == 1);
		TEST_RES(0, (long long)ev.res == BUF_SIZE);
		TEST_RES(0, ev.data == (__u64)round);
	}

	CHECK(io_destroy(ctx));
}
END_TEST()

// cleanup must be defined last so its constructor priority is highest,
// ensuring it runs after all FN_TEST functions have executed.
FN_SETUP(cleanup)
{
	if (g_fd >= 0) {
		close(g_fd);
		g_fd = -1;
	}
	unlink(TEST_FILE);
}
END_SETUP()
