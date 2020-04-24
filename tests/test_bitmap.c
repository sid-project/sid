#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <bitmap.h>

static void test_invert_bitmap(void **state)
{
	int i;
	struct bitmap *bitmap = bitmap_create(32, true);
	assert_non_null(bitmap);
	assert_int_equal(bitmap_get_bit_count(bitmap),
	                 bitmap_get_bit_set_count(bitmap));
	for (i = 0; i < 32; i++)
		assert_int_equal(bitmap_bit_unset(bitmap, i), 0);
	assert_int_equal(bitmap_bit_unset(bitmap, 32), -1);
	assert_int_equal(bitmap_get_bit_set_count(bitmap), 0);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_invert_bitmap),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
