#include "base/buffer.h"

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
	int            r   = 0;
	struct buffer *buf = NULL;
	char *         data;
	size_t         data_size;
	buf = sid_buffer_create(
		&((struct buffer_spec) {.backend = BUFFER_BACKEND_MALLOC, .type = BUFFER_TYPE_LINEAR, .mode = BUFFER_MODE_PLAIN}),
		&((struct buffer_init) {.size = buf_size, .alloc_step = 1, .limit = 0}),
		NULL);
	assert_non_null(buf);
	assert_non_null(sid_buffer_fmt_add(buf, NULL, TEST_STR));
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

static const void *do_rewind_test(struct buffer *buf)
{
	const void *rewind_mem;

	assert_non_null(buf);
	assert_non_null(sid_buffer_add(buf, TEST_STR, TEST_SIZE, NULL));
	rewind_mem = sid_buffer_add(buf, TEST_STR2, TEST_SIZE2, NULL);
	assert_non_null(rewind_mem);
	assert_non_null(sid_buffer_add(buf, TEST_STR3, TEST_SIZE3, NULL));
	assert_int_equal(sid_buffer_rewind_mem(buf, rewind_mem), 0);
	return rewind_mem;
}

static void test_linear_rewind_mem(void **state)
{
	struct buffer *buf;

	buf = sid_buffer_create(
		&((struct buffer_spec) {.backend = BUFFER_BACKEND_MALLOC, .type = BUFFER_TYPE_LINEAR, .mode = BUFFER_MODE_PLAIN}),
		&((struct buffer_init) {.size = 0, .alloc_step = 1, .limit = 0}),
		NULL);

	do_rewind_test(buf);
	sid_buffer_destroy(buf);
}

static void test_vector_rewind_mem(void **state)
{
	struct buffer *buf;

	buf = sid_buffer_create(
		&((struct buffer_spec) {.backend = BUFFER_BACKEND_MALLOC, .type = BUFFER_TYPE_VECTOR, .mode = BUFFER_MODE_PLAIN}),
		&((struct buffer_init) {.size = 0, .alloc_step = 1, .limit = 0}),
		NULL);

	do_rewind_test(buf);
	sid_buffer_destroy(buf);
}

static void do_test_zero_add(struct buffer *buf)
{
	const void *rewind_mem, *tmp_mem_start;

	rewind_mem    = do_rewind_test(buf);
	tmp_mem_start = sid_buffer_add(buf, "", 0, NULL);
	assert_ptr_equal(rewind_mem, tmp_mem_start);
	assert_non_null(sid_buffer_add(buf, TEST_STR3, TEST_SIZE3, NULL));
	assert_int_equal(sid_buffer_rewind_mem(buf, tmp_mem_start), 0);
	sid_buffer_destroy(buf);
}

static void test_linear_zero_add(void **state)
{
	struct buffer *buf;

	buf = sid_buffer_create(
		&((struct buffer_spec) {.backend = BUFFER_BACKEND_MALLOC, .type = BUFFER_TYPE_LINEAR, .mode = BUFFER_MODE_PLAIN}),
		&((struct buffer_init) {.size = 0, .alloc_step = 1, .limit = 0}),
		NULL);

	do_test_zero_add(buf);
}

static void test_vector_zero_add(void **state)
{
	struct buffer *buf;

	buf = sid_buffer_create(
		&((struct buffer_spec) {.backend = BUFFER_BACKEND_MALLOC, .type = BUFFER_TYPE_VECTOR, .mode = BUFFER_MODE_PLAIN}),
		&((struct buffer_init) {.size = 0, .alloc_step = 1, .limit = 0}),
		NULL);

	do_test_zero_add(buf);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_realloc_fmt_add),
		cmocka_unit_test(test_no_realloc_fmt_add),
		cmocka_unit_test(test_linear_rewind_mem),
		cmocka_unit_test(test_vector_rewind_mem),
		cmocka_unit_test(test_linear_zero_add),
		cmocka_unit_test(test_vector_zero_add),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
