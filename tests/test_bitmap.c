#include <errno.h>
#include <internal/bmp.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>

#include <cmocka.h>

static void test_invert_bmp(void **state)
{
	int         i, ret;
	struct bmp *bmp = bmp_create(32, true, &ret);
	assert_non_null(bmp);
	assert_int_equal(ret, 0);
	assert_int_equal(bmp_get_bit_count(bmp), bmp_get_bit_set_count(bmp));
	for (i = 0; i < 32; i++)
		assert_int_equal(bmp_unset_bit(bmp, i), 0);
	assert_int_equal(bmp_unset_bit(bmp, 32), -ERANGE);
	assert_int_equal(bmp_get_bit_set_count(bmp), 0);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_invert_bmp),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
