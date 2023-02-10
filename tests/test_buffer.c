#include "base/buffer.h"

#include <errno.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>

#include <cmocka.h>

#define TEST_STR   "foo"
#define TEST_SIZE  sizeof(TEST_STR)
#define TEST_STR2  "zyzzy"
#define TEST_SIZE2 sizeof(TEST_STR2)
#define TEST_STR3  "quux"
#define TEST_SIZE3 sizeof(TEST_STR3)

int test_fmt_add(int buf_size)
{
	int                r   = 0;
	struct sid_buffer *buf = NULL;
	char              *data;
	size_t             data_size;
	buf = sid_buffer_create(&((struct sid_buffer_spec) {.backend = SID_BUFFER_BACKEND_MALLOC,
	                                                    .type    = SID_BUFFER_TYPE_LINEAR,
	                                                    .mode    = SID_BUFFER_MODE_PLAIN}),
	                        &((struct sid_buffer_init) {.size = buf_size, .alloc_step = 1, .limit = 0}),
	                        NULL);
	assert_non_null(buf);
	assert_int_equal(sid_buffer_fmt_add(buf, NULL, NULL, TEST_STR), 0);
	assert_int_equal(sid_buffer_get_data(buf, (const void **) &data, &data_size), 0);
	assert_true(data_size == TEST_SIZE);
	sid_buffer_destroy(buf);
	return r;
}

static void test_realloc_fmt_add(void **state)
{
	test_fmt_add(0);
}

static void test_no_realloc_fmt_add(void **state)
{
	test_fmt_add(8);
}

static const void *do_rewind_test(struct sid_buffer *buf)
{
	const void *rewind_mem;

	assert_non_null(buf);
	assert_int_equal(sid_buffer_add(buf, TEST_STR, TEST_SIZE, NULL, NULL), 0);
	assert_int_equal(sid_buffer_add(buf, TEST_STR2, TEST_SIZE2, &rewind_mem, NULL), 0);
	assert_non_null(rewind_mem);
	assert_int_equal(sid_buffer_add(buf, TEST_STR3, TEST_SIZE3, NULL, NULL), -EBUSY);
	assert_int_equal(sid_buffer_rewind_mem(buf, rewind_mem), 0);
	return rewind_mem;
}

static void test_linear_rewind_mem(void **state)
{
	struct sid_buffer *buf;

	buf = sid_buffer_create(&((struct sid_buffer_spec) {.backend = SID_BUFFER_BACKEND_MALLOC,
	                                                    .type    = SID_BUFFER_TYPE_LINEAR,
	                                                    .mode    = SID_BUFFER_MODE_PLAIN}),
	                        &((struct sid_buffer_init) {.size = 0, .alloc_step = 1, .limit = 0}),
	                        NULL);

	do_rewind_test(buf);
	sid_buffer_destroy(buf);
}

static void test_vector_rewind_mem(void **state)
{
	struct sid_buffer *buf;

	buf = sid_buffer_create(&((struct sid_buffer_spec) {.backend = SID_BUFFER_BACKEND_MALLOC,
	                                                    .type    = SID_BUFFER_TYPE_VECTOR,
	                                                    .mode    = SID_BUFFER_MODE_PLAIN}),
	                        &((struct sid_buffer_init) {.size = 0, .alloc_step = 1, .limit = 0}),
	                        NULL);

	do_rewind_test(buf);
	sid_buffer_destroy(buf);
}

static void do_test_zero_add(sid_buffer_mode_t mode, sid_buffer_type_t type, sid_buffer_backend_t backend)
{
	struct sid_buffer *buf;
	const void        *rewind_mem, *tmp_mem_start;

	buf        = sid_buffer_create(&((struct sid_buffer_spec) {.backend = backend, .type = type, .mode = mode}),
                                &((struct sid_buffer_init) {.size = 0, .alloc_step = 1, .limit = 0}),
                                NULL);

	rewind_mem = do_rewind_test(buf);
	assert_int_equal(sid_buffer_add(buf, "", 0, &tmp_mem_start, NULL), 0);
	assert_ptr_equal(rewind_mem, tmp_mem_start);
	assert_int_equal(sid_buffer_add(buf, TEST_STR3, TEST_SIZE3, NULL, NULL), -EBUSY);
	assert_int_equal(sid_buffer_rewind_mem(buf, tmp_mem_start), 0);
	sid_buffer_destroy(buf);
}

static void test_linear_malloc_plain_zero_add(void **state)
{
	do_test_zero_add(SID_BUFFER_BACKEND_MALLOC, SID_BUFFER_TYPE_LINEAR, SID_BUFFER_MODE_PLAIN);
}

static void test_vector_malloc_plain_zero_add(void **state)
{
	do_test_zero_add(SID_BUFFER_BACKEND_MALLOC, SID_BUFFER_TYPE_VECTOR, SID_BUFFER_MODE_PLAIN);
}

static void test_linear_memfd_plain_zero_add(void **state)
{
	do_test_zero_add(SID_BUFFER_BACKEND_MEMFD, SID_BUFFER_TYPE_LINEAR, SID_BUFFER_MODE_PLAIN);
}

static void test_vector_memfd_plain_zero_add(void **state)
{
	do_test_zero_add(SID_BUFFER_BACKEND_MEMFD, SID_BUFFER_TYPE_VECTOR, SID_BUFFER_MODE_PLAIN);
}

static void test_linear_malloc_prefix_zero_add(void **state)
{
	do_test_zero_add(SID_BUFFER_BACKEND_MALLOC, SID_BUFFER_TYPE_LINEAR, SID_BUFFER_MODE_SIZE_PREFIX);
}

static void test_vector_malloc_prefix_zero_add(void **state)
{
	do_test_zero_add(SID_BUFFER_BACKEND_MALLOC, SID_BUFFER_TYPE_VECTOR, SID_BUFFER_MODE_SIZE_PREFIX);
}

static void test_linear_memfd_prefix_zero_add(void **state)
{
	do_test_zero_add(SID_BUFFER_BACKEND_MEMFD, SID_BUFFER_TYPE_LINEAR, SID_BUFFER_MODE_SIZE_PREFIX);
}

static void test_vector_memfd_prefix_zero_add(void **state)
{
	do_test_zero_add(SID_BUFFER_BACKEND_MEMFD, SID_BUFFER_TYPE_VECTOR, SID_BUFFER_MODE_SIZE_PREFIX);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_realloc_fmt_add),
		cmocka_unit_test(test_no_realloc_fmt_add),
		cmocka_unit_test(test_linear_rewind_mem),
		cmocka_unit_test(test_vector_rewind_mem),
		cmocka_unit_test(test_linear_malloc_plain_zero_add),
		cmocka_unit_test(test_vector_malloc_plain_zero_add),
		cmocka_unit_test(test_linear_memfd_plain_zero_add),
		cmocka_unit_test(test_vector_memfd_plain_zero_add),
		cmocka_unit_test(test_linear_malloc_prefix_zero_add),
		cmocka_unit_test(test_vector_malloc_prefix_zero_add),
		cmocka_unit_test(test_linear_memfd_prefix_zero_add),
		cmocka_unit_test(test_vector_memfd_prefix_zero_add),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
