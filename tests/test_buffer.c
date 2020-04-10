#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "buffer.h"

#define TEST_STR "foo"

int test_fmt_add(int buf_size)
{
	int r = 0;
	struct buffer *buf = NULL;
	char *data;
	size_t data_size, test_size = sizeof(TEST_STR);
	buf = buffer_create(BUFFER_TYPE_LINEAR, BUFFER_MODE_PLAIN, buf_size, 1);
	assert_non_null(buf);
	assert_non_null(buffer_fmt_add(buf, TEST_STR));
	assert_int_equal(buffer_get_data(buf, (const void **)&data, &data_size),			 0);
	assert_true(data_size == test_size);
	buffer_destroy(buf);
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

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_realloc_fmt_add),
		cmocka_unit_test(test_no_realloc_fmt_add),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
