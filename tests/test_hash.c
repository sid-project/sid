#include "internal/hash.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#define KEY_COUNT 10

char *test_array[KEY_COUNT] = {
	"1",
	"2",
	"3",
	"4",
	"5",
	"6",
	"7",
	"8",
	"9",
	"10",
};

static void test_hash_add()
{
	unsigned           count = 0;
	struct hash_table *t     = hash_create(5);

	for (int i = 0; i < KEY_COUNT; i++)
		assert_int_equal(hash_insert(t, test_array[i], strlen(test_array[i]) + 1, test_array[i], strlen(test_array[i]) + 1),
		                 0);

	assert_int_equal(hash_get_num_entries(t), KEY_COUNT);

	hash_wipe(t);
	assert_int_equal(hash_get_num_entries(t), 0);

	for (int i = 0; i < KEY_COUNT; i++)
		assert_int_equal(hash_insert(t, test_array[i], strlen(test_array[i]) + 1, test_array[i], strlen(test_array[i]) + 1),
		                 0);

	for (int i = 0; i < KEY_COUNT; i++)
		assert_int_equal(hash_insert_allow_multiple(t,
		                                            test_array[i],
		                                            strlen(test_array[i]) + 1,
		                                            test_array[i],
		                                            strlen(test_array[i]) + 1),
		                 0);

	for (int i = 0; i < KEY_COUNT; i++) {
		assert_string_equal(hash_lookup_with_count(t, test_array[i], strlen(test_array[i]) + 1, NULL, &count),
		                    test_array[i]);
		assert_int_equal(count, 2);
	}

	assert_int_equal(hash_get_num_entries(t), KEY_COUNT * 2);

	hash_destroy(t);
}

static void test_hash_lookup()
{
	struct hash_table *t = hash_create(10);
	;

	for (int i = 0; i < KEY_COUNT; i++)
		assert_int_equal(hash_insert(t, test_array[i], strlen(test_array[i]) + 1, test_array[i], strlen(test_array[i]) + 1),
		                 0);

	for (int i = 0; i < KEY_COUNT; i++) {
		assert_string_equal(hash_lookup_with_data(t,
		                                          test_array[i],
		                                          strlen(test_array[i]) + 1,
		                                          test_array[i],
		                                          strlen(test_array[i]) + 1),
		                    test_array[i]);
	}

	hash_destroy(t);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_hash_add),
		cmocka_unit_test(test_hash_lookup),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
