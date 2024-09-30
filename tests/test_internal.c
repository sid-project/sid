/*
 * SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "internal/comp-attrs.h"

#include "internal/util.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>

#include <cmocka.h>

static void check_strv(char **output, char **goal)
{
	while (*output && *goal) {
		assert_string_equal(*output, *goal);
		output++;
		goal++;
	}
	assert_null(*output);
	assert_null(*goal);
}

static void do_mem_test(const char *prefix, const char *str, const char *suffix, char *goal[])
{
	char            buffer[128] __aligned_to(sizeof(char *));
	char          **output = (char **) buffer;
	struct util_mem mem    = {.base = buffer, .size = sizeof(buffer)};

	assert_ptr_equal(util_str_comb_to_strv(&mem, prefix, str, suffix, UTIL_STR_DEFAULT_DELIMS, UTIL_STR_DEFAULT_QUOTES),
	                 output);
	check_strv(output, goal);
}

static void fail_mem_test(const char *prefix, const char *str, const char *suffix)
{
	char            buffer[128] __aligned_to(sizeof(char *));
	struct util_mem mem = {.base = buffer, .size = sizeof(buffer)};

	assert_null(util_str_comb_to_strv(&mem, prefix, str, suffix, UTIL_STR_DEFAULT_DELIMS, UTIL_STR_DEFAULT_QUOTES));
}

static void comb_mem_test0(void **state)
{
	do_mem_test(NULL, NULL, NULL, (char *[]) {NULL});
}

static void comb_mem_test1(void **state)
{
	do_mem_test(NULL, "simple", NULL, (char *[]) {"simple", NULL});
}

static void comb_mem_test2(void **state)
{
	do_mem_test(NULL, "less simple", NULL, (char *[]) {"less", "simple", NULL});
}

static void comb_mem_test3(void **state)
{
	do_mem_test(NULL, "\n \tmany\t \t\tdelims\n here\t\n ", NULL, (char *[]) {"many", "delims", "here", NULL});
}

static void comb_mem_test4(void **state)
{
	do_mem_test(NULL, "\\we\\ignore\\ \\slashes\\", NULL, (char *[]) {"\\we\\ignore\\", "\\slashes\\", NULL});
}

static void comb_mem_test5(void **state)
{
	do_mem_test(NULL, "", NULL, (char *[]) {NULL});
}

static void comb_mem_test6(void **state)
{
	do_mem_test(NULL, "\f\n\t \v", NULL, (char *[]) {NULL});
}

static void comb_mem_test7(void **state)
{
	do_mem_test(" one two\n", "three", "four\tfive\n", (char *[]) {"one", "two", "three", "four", "five", NULL});
}

static void comb_mem_test8(void **state)
{
	do_mem_test(NULL, "\"simple quotes\"", NULL, (char *[]) {"simple quotes", NULL});
}

static void comb_mem_test9(void **state)
{
	do_mem_test(NULL, "'other quotes'", NULL, (char *[]) {"other quotes", NULL});
}

static void comb_mem_test10(void **state)
{
	do_mem_test("'\"quoted string\"'", NULL, NULL, (char *[]) {"\"quoted string\"", NULL});
}

static void comb_mem_test11(void **state)
{
	do_mem_test(NULL, NULL, "\"'other quoted string'\"", (char *[]) {"'other quoted string'", NULL});
}

static void comb_mem_test12(void **state)
{
	do_mem_test(NULL, NULL, "can't won't", (char *[]) {"cant wont", NULL});
}

static void comb_mem_test13(void **state)
{
	do_mem_test(NULL, NULL, "this' is' a f\"ront merge\"", (char *[]) {"this is", "a", "front merge", NULL});
}

static void comb_mem_test14(void **state)
{
	do_mem_test("'this 'is a", "\"back me\"rge", NULL, (char *[]) {"this is", "a", "back merge", NULL});
}

static void comb_mem_test15(void **state)
{
	do_mem_test("still' 'more' 'merging",
	            "fun\" \"with\" \"merging",
	            "mixed\" \"quote' 'merging",
	            (char *[]) {"still more merging", "fun with merging", "mixed quote merging", NULL});
}

static void comb_mem_test16(void **state)
{
	do_mem_test(NULL, NULL, "merging\" 'with' \"embedded quotes", (char *[]) {"merging 'with' embedded", "quotes", NULL});
}

static void comb_mem_test17(void **state)
{
	do_mem_test("\"Goonies don't say\"' \"Die\"'",
	            NULL,
	            "\"Actually, it's \"'\"Goonies never say'\" 'Die'\"'\"'",
	            (char *[]) {"Goonies don't say \"Die\"", "Actually, it's \"Goonies never say 'Die'\"", NULL});
}

static void bad_mem_test_missing1(void **state)
{
	fail_mem_test("only one 'quote", NULL, NULL);
}

static void bad_mem_test_missing2(void **state)
{
	fail_mem_test(NULL, "only one 'quote", NULL);
}

static void bad_mem_test_missing3(void **state)
{
	fail_mem_test(NULL, "\"only three\"\"quotes", NULL);
}

static void bad_mem_test_missing4(void **state)
{
	fail_mem_test(NULL, "\"two missmatched' quotes", NULL);
}

static void bad_mem_test_missing5(void **state)
{
	fail_mem_test(NULL, "'four missmatched\" \"quotes\"", NULL);
}

static void bad_mem_test_missing6(void **state)
{
	fail_mem_test("quotes don't", "match when they're \"in different sections\"", NULL);
}

static void bad_mem_test_small(void **state)
{
	char            buffer[16] __aligned_to(sizeof(char *));
	struct util_mem mem = {.base = buffer, .size = sizeof(buffer)};

	assert_null(util_str_comb_to_strv(&mem, "too", "many", "strings", UTIL_STR_DEFAULT_DELIMS, UTIL_STR_DEFAULT_QUOTES));
}

static void do_alloc_test(const char *prefix, const char *str, const char *suffix, char *goal[])
{
	char **output = util_str_comb_to_strv(NULL, prefix, str, suffix, UTIL_STR_DEFAULT_DELIMS, UTIL_STR_DEFAULT_QUOTES);
	assert_non_null(output);
	check_strv(output, goal);
	free(output);
}

static void comb_alloc_test0(void **state)
{
	do_alloc_test(NULL, NULL, NULL, (char *[]) {NULL});
}

static void comb_alloc_test1(void **state)
{
	do_alloc_test("prefix", "str", "suffix", (char *[]) {"prefix", "str", "suffix", NULL});
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(comb_mem_test0),        cmocka_unit_test(comb_mem_test1),
		cmocka_unit_test(comb_mem_test2),        cmocka_unit_test(comb_mem_test3),
		cmocka_unit_test(comb_mem_test4),        cmocka_unit_test(comb_mem_test5),
		cmocka_unit_test(comb_mem_test6),        cmocka_unit_test(comb_mem_test7),
		cmocka_unit_test(comb_mem_test8),        cmocka_unit_test(comb_mem_test9),
		cmocka_unit_test(comb_mem_test10),       cmocka_unit_test(comb_mem_test11),
		cmocka_unit_test(comb_mem_test12),       cmocka_unit_test(comb_mem_test13),
		cmocka_unit_test(comb_mem_test14),       cmocka_unit_test(comb_mem_test15),
		cmocka_unit_test(comb_mem_test16),       cmocka_unit_test(comb_mem_test17),
		cmocka_unit_test(bad_mem_test_small),    cmocka_unit_test(bad_mem_test_missing1),
		cmocka_unit_test(bad_mem_test_missing2), cmocka_unit_test(bad_mem_test_missing3),
		cmocka_unit_test(bad_mem_test_missing4), cmocka_unit_test(bad_mem_test_missing5),
		cmocka_unit_test(bad_mem_test_missing6), cmocka_unit_test(comb_alloc_test0),
		cmocka_unit_test(comb_alloc_test1),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
