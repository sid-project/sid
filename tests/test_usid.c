#define _GNU_SOURCE
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>
#define main orig_main
#include "../src/tools/usid/usid.c"
#undef main
#include "../src/base/util.c"

char *__wrap_getenv(const char *name)
{
	return mock_ptr_type(char *);
}
#define CHECKPOINT_NAME "checkpoint_name"
#define KEY             "KEY"
#define VALUE           "value"

char *test_argv[] = {"checkpoint", CHECKPOINT_NAME, KEY};

static void test_checkpoint_env(void **state)
{
	char *         data, *p;
	size_t         size;
	struct buffer *buf;
	struct args    args = {.argc = sizeof(test_argv) / sizeof(test_argv[0]), .argv = test_argv};

	buf = buffer_create(&((struct buffer_spec) {.backend = BUFFER_BACKEND_MALLOC,
	                                            .type    = BUFFER_TYPE_LINEAR,
	                                            .mode    = BUFFER_MODE_SIZE_PREFIX}),
	                    &((struct buffer_init) {.size = 0, .alloc_step = 1, .limit = 0}),
	                    NULL);

	assert_non_null(buf);
	will_return(__wrap_getenv, "8");
	will_return(__wrap_getenv, "0");
	will_return(__wrap_getenv, VALUE);
	assert_int_equal(_add_checkpoint_env_to_buf(buf, &args), 0);
	assert_int_equal(buffer_get_data(buf, (const void **) &data, &size), 0);
	p = data + sizeof(dev_t);
	assert_string_equal(p, CHECKPOINT_NAME);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_checkpoint_env),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
