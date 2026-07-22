/* SPDX-License-Identifier: MPL-2.0 */

#define _GNU_SOURCE

#include <unistd.h>
#include <sys/mman.h>
#include <sys/fcntl.h>
#include <sys/stat.h>

#include "../../common/test.h"

#define PAGE_SIZE 4096
/* The fixture /ext2/mmap_eof_tail.bin is baked into the ext2 image at build
 * time: it is filled with FILL_BYTE on disk and its recorded size is then
 * shrunk to FILE_SIZE (5000), so the on-disk last block still carries
 * non-zero data beyond EOF. A correct page-cache backend must zero-fill that
 * tail on a fresh mmap read; the bug exposes the stale FILL_BYTE bytes
 * instead.
 *
 * This cannot be reproduced by creating the file at runtime: ext2 zeroes every
 * newly allocated block (zero_new_blocks), so an in-guest file always has a
 * zero tail. Hence the fixture must be baked into the image. If the fixture is
 * missing the test fails loudly instead of silently passing. */
#define FILE_SIZE 5000
#define FILL_BYTE 'A'

#define TEST_FILE "/ext2/mmap_eof_tail.bin"

/* Returns 0 if the mapped region is correct: every in-file byte equals
 * FILL_BYTE and every EOF-tail byte (the part of the last page beyond FILE_SIZE)
 * equals 0. Otherwise returns the first offending byte offset as a negative
 * value, for diagnostics. */
static long verify_region(const unsigned char *p)
{
       size_t i;

       for (i = 0; i < FILE_SIZE; i++) {
               if (p[i] != FILL_BYTE)
                       return -(long)i;
       }
       for (i = FILE_SIZE; i < 2 * PAGE_SIZE; i++) {
               if (p[i] != 0)
                       return -(long)i;
       }
       return 0;
}

FN_TEST(mmap_eof_tail_must_be_zero)
{
       int fd;
       struct stat st;
       void *map;
       long res;

       fd = TEST_SUCC(open(TEST_FILE, O_RDONLY));
       TEST_SUCC(fstat(fd, &st));
       TEST_RES(st.st_size, _ret == FILE_SIZE);

       /* Map two pages (rounded up from FILE_SIZE). Bytes beyond FILE_SIZE but
        * still inside the last mapped page must read as zero, never the stale
        * on-disk content of the partial last block. */
       map = TEST_SUCC(mmap(NULL, 2 * PAGE_SIZE, PROT_READ, MAP_SHARED, fd, 0));

       res = verify_region((const unsigned char *)map);
       if (res != 0)
               fprintf(stderr,
                       "mmap_eof_tail: byte at offset %ld is not the expected value "
                       "(in-file bytes must be '%c'; the EOF tail must be 0)\n",
                       -res, FILL_BYTE);
       TEST_RES(res, _ret == 0);

       TEST_SUCC(munmap(map, 2 * PAGE_SIZE));
       TEST_SUCC(close(fd));
}
END_TEST()

