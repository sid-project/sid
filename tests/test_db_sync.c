#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
/* define __USE_GNU for ucred definition */
#define __USE_GNU
#include "../src/internal/mem.c"
#include "../src/resource/kv-store.c"
#include "../src/resource/ubridge.c"
#include "ucmd-module.h"

#include <sys/socket.h>

#include <cmocka.h>

#define VALUE1 "baz"
#define VALUE2 "quux"
#define VALUE3 "xyzzy"
#define VALUE4 "foobar"

struct sid_ucmd_common_ctx *_create_common_ctx(void)
{
	struct sid_ucmd_common_ctx *common_ctx;

	assert_non_null(common_ctx = mem_zalloc(sizeof(struct sid_ucmd_common_ctx)));
	common_ctx->kv_store_res = sid_resource_create(SID_RESOURCE_NO_PARENT,
	                                               &sid_resource_type_kv_store,
	                                               SID_RESOURCE_RESTRICT_WALK_UP,
	                                               "testkvstore",
	                                               &main_kv_store_res_params,
	                                               SID_RESOURCE_PRIO_NORMAL,
	                                               SID_RESOURCE_NO_SERVICE_LINKS);
	assert_non_null(common_ctx->kv_store_res);
	common_ctx->gen_buf = sid_buffer_create(&((struct sid_buffer_spec) {.backend = SID_BUFFER_BACKEND_MALLOC,
	                                                                    .type    = SID_BUFFER_TYPE_LINEAR,
	                                                                    .mode    = SID_BUFFER_MODE_PLAIN}),
	                                        &((struct sid_buffer_init) {.size = 0, .alloc_step = PATH_MAX, .limit = 0}),
	                                        NULL);
	assert_non_null(common_ctx->gen_buf);
	common_ctx->gennum = 1;
	return common_ctx;
}

void _destroy_common_ctx(struct sid_ucmd_common_ctx *common_ctx)
{
	sid_resource_unref(common_ctx->kv_store_res);
	sid_buffer_destroy(common_ctx->gen_buf);
	free(common_ctx);
}

static int _init_fake_command(sid_resource_t *res, const void *kickstart_data, void **data)
{
	struct sid_ucmd_ctx *ucmd_ctx;

	assert_non_null(ucmd_ctx = mem_zalloc(sizeof(*ucmd_ctx)));
	*data            = ucmd_ctx;
	ucmd_ctx->common = _create_common_ctx();
	return 0;
}

static int _destroy_fake_command(sid_resource_t *res)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_resource_get_data(res);

	if (ucmd_ctx->exp_buf)
		sid_buffer_destroy(ucmd_ctx->exp_buf);
	_destroy_common_ctx(ucmd_ctx->common);
	free(ucmd_ctx);
	return 0;
}

const sid_resource_type_t sid_resource_type_fake_cmd = {
	.name        = "fake_command",
	.short_name  = "fake",
	.description = "Fake ubridge command resource",
	.init        = _init_fake_command,
	.destroy     = _destroy_fake_command,
};

sid_resource_t *_create_fake_cmd_res(void)
{
	sid_resource_t *res;

	res = sid_resource_create(SID_RESOURCE_NO_PARENT,
	                          &sid_resource_type_fake_cmd,
	                          SID_RESOURCE_NO_FLAGS,
	                          "fakecmd",
	                          SID_RESOURCE_NO_PARAMS,
	                          SID_RESOURCE_PRIO_NORMAL,
	                          SID_RESOURCE_NO_SERVICE_LINKS);
	assert_non_null(res);
	return res;
}

int _do_build_buffers(sid_resource_t *cmd_res)
{
	int                  fd;
	struct sid_ucmd_ctx *ucmd_ctx = sid_resource_get_data(cmd_res);
	struct cmd_reg       cmd_reg  = {.flags = CMD_KV_EXPBUF_TO_MAIN | CMD_KV_EXPORT_SID_TO_EXPBUF};

	assert_int_equal(_build_cmd_kv_buffers(cmd_res, &cmd_reg), 0);
	fd = sid_buffer_get_fd(ucmd_ctx->exp_buf);
	assert_true(fd >= 0);
	return fd;
}

struct kv_key_spec base_spec = {.extra_op = NULL,
                                .op       = KV_OP_SET,
                                .dom      = KV_KEY_DOM_USER,
                                .ns       = KV_NS_GLOBAL,
                                .ns_part  = ID_NULL,
                                .id_cat   = ID_NULL,
                                .id       = ID_NULL,
                                .core     = ID_NULL};

static void _check_missing_kv(struct sid_ucmd_ctx *ucmd_ctx, const char *core)
{
	struct kv_key_spec     key_spec = base_spec;
	char                  *key;
	kv_store_value_flags_t flags;
	size_t                 size;

	key_spec.core = core;
	assert_non_null(key = _compose_key(ucmd_ctx->common->gen_buf, &key_spec));
	assert_null(kv_store_get_value(ucmd_ctx->common->kv_store_res, key, &size, &flags));

	_destroy_key(ucmd_ctx->common->gen_buf, key);
}

static void _check_kv(struct sid_ucmd_ctx *ucmd_ctx, const char *core, char **data, size_t nr_data, bool vector)
{
	struct kv_key_spec     key_spec = base_spec;
	char                  *key;
	void                  *value;
	kv_vector_t            tmp_vvalue[VVALUE_SINGLE_CNT];
	kv_vector_t           *vvalue;
	kv_store_value_flags_t flags;
	size_t                 i, size;

	key_spec.core = core;
	assert_non_null(key = _compose_key(ucmd_ctx->common->gen_buf, &key_spec));

	assert_non_null(value = kv_store_get_value(ucmd_ctx->common->kv_store_res, key, &size, &flags));
	vvalue = _get_vvalue(flags, value, size, tmp_vvalue);
	if (flags & KV_STORE_VALUE_VECTOR) {
		assert_true(vector);
	} else {
		assert_false(vector);
		size = vvalue[VVALUE_IDX_DATA].iov_len ? VVALUE_SINGLE_CNT : VVALUE_HEADER_CNT;
	}
	assert_int_equal(nr_data, size - VVALUE_HEADER_CNT);

	for (i = 0; i < nr_data; i++) {
		if (!data[i])
			assert_null(vvalue[VVALUE_IDX_DATA + i].iov_base);
		else
			assert_string_equal(vvalue[VVALUE_IDX_DATA + i].iov_base, data[i]);
	}

	_destroy_key(ucmd_ctx->common->gen_buf, key);
}

static void _set_kv(struct sid_ucmd_ctx *ucmd_ctx, const char *core, char **data, size_t nr_data, kv_op_t op, bool vector)
{
	const char          *owner    = _get_mod_name(NULL);
	struct kv_key_spec   key_spec = base_spec;
	char                *key;
	kv_vector_t          vvalue[VVALUE_HEADER_CNT + nr_data];
	sid_ucmd_kv_flags_t  flags      = KV_RD;
	struct kv_update_arg update_arg = {.res      = ucmd_ctx->common->kv_store_res,
	                                   .owner    = owner,
	                                   .gen_buf  = ucmd_ctx->common->gen_buf,
	                                   .custom   = NULL,
	                                   .ret_code = -EREMOTEIO};
	size_t               i;

	key_spec.op   = op;
	key_spec.core = core;
	assert_non_null(key = _compose_key(ucmd_ctx->common->gen_buf, &key_spec));

	VVALUE_HEADER_PREP(vvalue, ucmd_ctx->req_env.dev.udev.seqnum, flags, ucmd_ctx->common->gennum, (char *) owner);
	for (i = 0; i < nr_data; i++)
		VVALUE_DATA_PREP(vvalue, i, data[i], data[i] ? strlen(data[i]) + 1 : 0);

	assert_non_null(kv_store_set_value(ucmd_ctx->common->kv_store_res,
	                                   key,
	                                   vvalue,
	                                   VVALUE_HEADER_CNT + nr_data,
	                                   KV_STORE_VALUE_VECTOR,
	                                   vector ? KV_STORE_VALUE_NO_OP : KV_STORE_VALUE_OP_MERGE,
	                                   _kv_cb_write,
	                                   &update_arg));
	assert_true(update_arg.ret_code >= 0);

	_destroy_key(ucmd_ctx->common->gen_buf, key);
}

static void _set_broken_kv(struct sid_ucmd_ctx *ucmd_ctx, const char *core)
{
	const char          *owner    = _get_mod_name(NULL);
	struct kv_key_spec   key_spec = base_spec;
	char                *key;
	kv_vector_t          vvalue[VVALUE_HEADER_CNT];
	sid_ucmd_kv_flags_t  flags      = KV_RD;
	struct kv_update_arg update_arg = {.res      = ucmd_ctx->common->kv_store_res,
	                                   .owner    = owner,
	                                   .gen_buf  = ucmd_ctx->common->gen_buf,
	                                   .custom   = NULL,
	                                   .ret_code = -EREMOTEIO};

	key_spec.core                   = core;
	assert_non_null(key = _compose_key(ucmd_ctx->common->gen_buf, &key_spec));

	VVALUE_HEADER_PREP(vvalue, ucmd_ctx->req_env.dev.udev.seqnum, flags, ucmd_ctx->common->gennum, (char *) owner);
	assert_non_null(kv_store_set_value(ucmd_ctx->common->kv_store_res,
	                                   key,
	                                   vvalue,
	                                   VVALUE_HEADER_CNT - 1,
	                                   KV_STORE_VALUE_VECTOR,
	                                   KV_STORE_VALUE_NO_OP,
	                                   NULL,
	                                   &update_arg));

	_destroy_key(ucmd_ctx->common->gen_buf, key);
}

#define ARRAY_LEN(array) (sizeof((array)) / sizeof((array)[0]))

struct test_state {
	sid_resource_t      *work_res;
	sid_resource_t      *main_res;
	struct sid_ucmd_ctx *work_ctx;
	struct sid_ucmd_ctx *main_ctx;
};

static void dumper_fn(const char *key, void *value, size_t size, unsigned ref_count, void *arg)
{
	struct sid_buffer *buf = arg;

	assert_int_equal(sid_buffer_add(buf, (void *) key, strlen(key) + 1, NULL, NULL), 0);
	assert_int_equal(sid_buffer_add(buf, value, size, NULL, NULL), 0);
}

static struct sid_buffer *dump_db(sid_resource_t *kv_store_res)
{
	struct kv_store *kv_store = sid_resource_get_data(kv_store_res);
	/* Could do this for hash as well but not sure if it's worth is */
	assert_true(kv_store->backend == KV_STORE_BACKEND_BPTREE);
	struct sid_buffer *buf = sid_buffer_create(&((struct sid_buffer_spec) {.backend = SID_BUFFER_BACKEND_MALLOC,
	                                                                       .type    = SID_BUFFER_TYPE_VECTOR,
	                                                                       .mode    = SID_BUFFER_MODE_PLAIN}),
	                                           &((struct sid_buffer_init) {.size = 0, .alloc_step = 2, .limit = 0}),
	                                           NULL);
	assert_non_null(buf);
	bptree_iter(kv_store->bpt, NULL, NULL, dumper_fn, buf);
	return buf;
}

static void compare_dumps(struct sid_buffer *old_dump, struct sid_buffer *new_dump)
{
	kv_vector_t *new, *old;
	size_t new_size, old_size, i;

	assert_int_equal(sid_buffer_get_data(old_dump, (const void **) &old, &old_size), 0);
	assert_int_equal(sid_buffer_get_data(new_dump, (const void **) &new, &new_size), 0);
	assert_true(old_size == new_size);
	assert_true(old_size % 2 == 0);
	for (i = 0; i < old_size; i++) {
		assert_ptr_equal(old[i].iov_base, new[i].iov_base);
		assert_int_equal(old[i].iov_len, new[i].iov_len);
	}
	sid_buffer_destroy(old_dump);
	sid_buffer_destroy(new_dump);
}

static void test_scalar(void **state)
{
	struct test_state *ts = *state;
	int                fd;
	char              *data[] = {"value"};

	_set_kv(ts->work_ctx, "key", data, ARRAY_LEN(data), KV_OP_SET, false);
	fd = _do_build_buffers(ts->work_res);
	assert_int_equal(_sync_main_kv_store(ts->main_res, ts->main_ctx->common, fd), 0);
	_check_kv(ts->main_ctx, "key", data, ARRAY_LEN(data), false);
	assert_int_equal(kv_store_num_entries(ts->main_ctx->common->kv_store_res), 1);
}

static void test_vector(void **state)
{
	struct test_state *ts = *state;
	int                fd;
	char              *data[] = {VALUE1, VALUE2, VALUE3};

	_set_kv(ts->work_ctx, "key", data, ARRAY_LEN(data), KV_OP_SET, true);
	fd = _do_build_buffers(ts->work_res);
	assert_int_equal(_sync_main_kv_store(ts->main_res, ts->main_ctx->common, fd), 0);
	_check_kv(ts->main_ctx, "key", data, ARRAY_LEN(data), true);
	assert_int_equal(kv_store_num_entries(ts->main_ctx->common->kv_store_res), 1);
}

static void test_unset_scalar(void **state)
{
	struct test_state *ts = *state;
	int                fd;
	char              *data[] = {"value"};

	_set_kv(ts->main_ctx, "key", data, ARRAY_LEN(data), KV_OP_SET, false);
	assert_int_equal(kv_store_num_entries(ts->main_ctx->common->kv_store_res), 1);
	_set_kv(ts->work_ctx, "key", NULL, 0, KV_OP_SET, false);
	fd = _do_build_buffers(ts->work_res);
	assert_int_equal(_sync_main_kv_store(ts->main_res, ts->main_ctx->common, fd), 0);
	_check_missing_kv(ts->main_ctx, "key");
	assert_int_equal(kv_store_num_entries(ts->main_ctx->common->kv_store_res), 0);
}

static void test_unset_vector(void **state)
{
	struct test_state *ts = *state;
	int                fd;
	char              *data[] = {VALUE1, VALUE2};

	_set_kv(ts->main_ctx, "key", data, ARRAY_LEN(data), KV_OP_SET, true);
	assert_int_equal(kv_store_num_entries(ts->main_ctx->common->kv_store_res), 1);
	_set_kv(ts->work_ctx, "key", NULL, 0, KV_OP_SET, true);
	fd = _do_build_buffers(ts->work_res);
	assert_int_equal(_sync_main_kv_store(ts->main_res, ts->main_ctx->common, fd), 0);
	_check_missing_kv(ts->main_ctx, "key");
	assert_int_equal(kv_store_num_entries(ts->main_ctx->common->kv_store_res), 0);
}

static void test_unset_missing(void **state)
{
	struct test_state *ts = *state;
	int                fd;

	_set_kv(ts->work_ctx, "key", NULL, 0, KV_OP_SET, false);
	fd = _do_build_buffers(ts->work_res);
	assert_int_equal(_sync_main_kv_store(ts->main_res, ts->main_ctx->common, fd), 0);
	_check_missing_kv(ts->main_ctx, "key");
	assert_int_equal(kv_store_num_entries(ts->main_ctx->common->kv_store_res), 0);
}

static void test_subtract_missing(void **state)
{
	struct test_state *ts = *state;
	int                fd;
	char              *data[] = {"value"};

	_set_kv(ts->work_ctx, "key", data, 1, KV_OP_MINUS, true);
	fd = _do_build_buffers(ts->work_res);
	assert_int_equal(_sync_main_kv_store(ts->main_res, ts->main_ctx->common, fd), 0);
	_check_kv(ts->main_ctx, "key", NULL, 0, true);
	assert_int_equal(kv_store_num_entries(ts->main_ctx->common->kv_store_res), 1);
}

static void test_add_missing(void **state)
{
	struct test_state *ts = *state;
	int                fd;
	char              *data[] = {"value"};

	_set_kv(ts->work_ctx, "key", data, 1, KV_OP_PLUS, true);
	fd = _do_build_buffers(ts->work_res);
	assert_int_equal(_sync_main_kv_store(ts->main_res, ts->main_ctx->common, fd), 0);
	_check_kv(ts->main_ctx, "key", data, 1, true);
	assert_int_equal(kv_store_num_entries(ts->main_ctx->common->kv_store_res), 1);
}

static void test_vector_subtract(void **state)
{
	struct test_state *ts = *state;
	int                fd;
	char              *data[] = {VALUE1, VALUE2, VALUE3};

	_set_kv(ts->main_ctx, "key", data, ARRAY_LEN(data), KV_OP_SET, true);
	assert_int_equal(kv_store_num_entries(ts->main_ctx->common->kv_store_res), 1);
	_set_kv(ts->work_ctx, "key", data, 2, KV_OP_MINUS, true);
	fd = _do_build_buffers(ts->work_res);
	assert_int_equal(_sync_main_kv_store(ts->main_res, ts->main_ctx->common, fd), 0);
	_check_kv(ts->main_ctx, "key", &data[2], 1, true);
	assert_int_equal(kv_store_num_entries(ts->main_ctx->common->kv_store_res), 1);
}

static void test_vector_add(void **state)
{
	struct test_state *ts = *state;
	int                fd;
	char              *data[] = {VALUE1, VALUE2};

	_set_kv(ts->main_ctx, "key", data, 1, KV_OP_SET, true);
	assert_int_equal(kv_store_num_entries(ts->main_ctx->common->kv_store_res), 1);
	_set_kv(ts->work_ctx, "key", &data[1], 1, KV_OP_PLUS, true);
	fd = _do_build_buffers(ts->work_res);
	assert_int_equal(_sync_main_kv_store(ts->main_res, ts->main_ctx->common, fd), 0);
	_check_kv(ts->main_ctx, "key", data, ARRAY_LEN(data), true);
	assert_int_equal(kv_store_num_entries(ts->main_ctx->common->kv_store_res), 1);
}

static void test_vector_change(void **state)
{
	struct test_state *ts = *state;
	int                fd;
	char              *data[] = {VALUE1, VALUE2, VALUE3, VALUE4};

	_set_kv(ts->main_ctx, "key", &data[1], 2, KV_OP_SET, true);
	assert_int_equal(kv_store_num_entries(ts->main_ctx->common->kv_store_res), 1);
	_set_kv(ts->work_ctx, "key", data, ARRAY_LEN(data), KV_OP_SET, true);
	fd = _do_build_buffers(ts->work_res);
	assert_int_equal(_sync_main_kv_store(ts->main_res, ts->main_ctx->common, fd), 0);
	_check_kv(ts->main_ctx, "key", data, ARRAY_LEN(data), true);
	assert_int_equal(kv_store_num_entries(ts->main_ctx->common->kv_store_res), 1);
}

static void test_scalar_change(void **state)
{
	struct test_state *ts = *state;
	int                fd;
	char              *data1[] = {VALUE1};
	char              *data2[] = {VALUE2};

	_set_kv(ts->main_ctx, "key", data1, ARRAY_LEN(data1), KV_OP_SET, false);
	assert_int_equal(kv_store_num_entries(ts->main_ctx->common->kv_store_res), 1);
	_set_kv(ts->work_ctx, "key", data2, ARRAY_LEN(data2), KV_OP_SET, false);
	fd = _do_build_buffers(ts->work_res);
	assert_int_equal(_sync_main_kv_store(ts->main_res, ts->main_ctx->common, fd), 0);
	_check_kv(ts->main_ctx, "key", data2, ARRAY_LEN(data2), false);
	assert_int_equal(kv_store_num_entries(ts->main_ctx->common->kv_store_res), 1);
}

static void test_type_change1(void **state)
{
	struct test_state *ts = *state;
	int                fd;
	char              *data[] = {VALUE1, VALUE2, VALUE3, VALUE4};

	_set_kv(ts->main_ctx, "key", &data[2], 1, KV_OP_SET, false);
	assert_int_equal(kv_store_num_entries(ts->main_ctx->common->kv_store_res), 1);
	_set_kv(ts->work_ctx, "key", data, ARRAY_LEN(data), KV_OP_SET, true);
	fd = _do_build_buffers(ts->work_res);
	assert_int_equal(_sync_main_kv_store(ts->main_res, ts->main_ctx->common, fd), 0);
	_check_kv(ts->main_ctx, "key", data, ARRAY_LEN(data), true);
	assert_int_equal(kv_store_num_entries(ts->main_ctx->common->kv_store_res), 1);
}

static void test_type_change2(void **state)
{
	struct test_state *ts = *state;
	int                fd;
	char              *data[] = {VALUE1, VALUE2, VALUE3, VALUE4};

	_set_kv(ts->main_ctx, "key", &data[1], 3, KV_OP_SET, true);
	assert_int_equal(kv_store_num_entries(ts->main_ctx->common->kv_store_res), 1);
	_set_kv(ts->work_ctx, "key", data, 1, KV_OP_SET, false);
	fd = _do_build_buffers(ts->work_res);
	assert_int_equal(_sync_main_kv_store(ts->main_res, ts->main_ctx->common, fd), 0);
	_check_kv(ts->main_ctx, "key", data, 1, false);
	assert_int_equal(kv_store_num_entries(ts->main_ctx->common->kv_store_res), 1);
}

static void test_empty_broken(void **state)
{
	struct test_state *ts = *state;
	int                fd;

	_set_broken_kv(ts->work_ctx, "key");
	fd = _do_build_buffers(ts->work_res);
	assert_int_equal(_sync_main_kv_store(ts->main_res, ts->main_ctx->common, fd), -1);
	assert_int_equal(kv_store_num_entries(ts->main_ctx->common->kv_store_res), 0);
}

static void test_set_broken(void **state)
{
	struct test_state *ts = *state;
	int                fd;
	char              *data[] = {VALUE1};

	_set_kv(ts->work_ctx, "key1", data, ARRAY_LEN(data), KV_OP_SET, false);
	_set_broken_kv(ts->work_ctx, "key2");
	fd = _do_build_buffers(ts->work_res);
	assert_int_equal(_sync_main_kv_store(ts->main_res, ts->main_ctx->common, fd), -1);
	assert_int_equal(kv_store_num_entries(ts->main_ctx->common->kv_store_res), 0);
}

static void test_unset_broken(void **state)
{
	struct test_state *ts = *state;
	int                fd;
	char              *data[] = {VALUE1, VALUE2};
	struct sid_buffer *old, *new;

	_set_kv(ts->main_ctx, "key1", data, ARRAY_LEN(data), KV_OP_SET, true);
	_set_kv(ts->work_ctx, "key1", NULL, 0, KV_OP_SET, true);
	_set_broken_kv(ts->work_ctx, "key2");
	fd  = _do_build_buffers(ts->work_res);
	old = dump_db(ts->main_ctx->common->kv_store_res);
	assert_int_equal(_sync_main_kv_store(ts->main_res, ts->main_ctx->common, fd), -1);
	new = dump_db(ts->main_ctx->common->kv_store_res);
	compare_dumps(old, new);
}

static void test_change_broken(void **state)
{
	struct test_state *ts = *state;
	int                fd;
	char              *data[] = {VALUE1, VALUE2};
	struct sid_buffer *old, *new;

	_set_kv(ts->main_ctx, "key1", &data[0], 1, KV_OP_SET, false);
	_set_kv(ts->work_ctx, "key1", &data[1], 1, KV_OP_SET, false);
	_set_broken_kv(ts->work_ctx, "key2");
	fd  = _do_build_buffers(ts->work_res);
	old = dump_db(ts->main_ctx->common->kv_store_res);
	assert_int_equal(_sync_main_kv_store(ts->main_res, ts->main_ctx->common, fd), -1);
	new = dump_db(ts->main_ctx->common->kv_store_res);
	compare_dumps(old, new);
}

static void test_subtract_broken(void **state)
{
	struct test_state *ts = *state;
	int                fd;
	char              *data[] = {VALUE1, VALUE2, VALUE3};
	struct sid_buffer *old, *new;

	_set_kv(ts->main_ctx, "key1", data, ARRAY_LEN(data), KV_OP_SET, true);
	assert_int_equal(kv_store_num_entries(ts->main_ctx->common->kv_store_res), 1);
	_set_kv(ts->work_ctx, "key1", data, 2, KV_OP_MINUS, true);
	_set_broken_kv(ts->work_ctx, "key2");
	fd  = _do_build_buffers(ts->work_res);
	old = dump_db(ts->main_ctx->common->kv_store_res);
	assert_int_equal(_sync_main_kv_store(ts->main_res, ts->main_ctx->common, fd), -1);
	new = dump_db(ts->main_ctx->common->kv_store_res);
	compare_dumps(old, new);
}

static void test_add_broken(void **state)
{
	struct test_state *ts = *state;
	int                fd;
	char              *data[] = {VALUE1, VALUE2};
	struct sid_buffer *old, *new;

	_set_kv(ts->main_ctx, "key1", data, 1, KV_OP_SET, true);
	assert_int_equal(kv_store_num_entries(ts->main_ctx->common->kv_store_res), 1);
	_set_kv(ts->work_ctx, "key1", &data[1], 1, KV_OP_PLUS, true);
	_set_broken_kv(ts->work_ctx, "key2");
	fd  = _do_build_buffers(ts->work_res);
	old = dump_db(ts->main_ctx->common->kv_store_res);
	assert_int_equal(_sync_main_kv_store(ts->main_res, ts->main_ctx->common, fd), -1);
	new = dump_db(ts->main_ctx->common->kv_store_res);
	compare_dumps(old, new);
}

static void test_multi_1(void **state)
{
	struct test_state *ts = *state;
	int                fd;
	char              *data[] = {VALUE1, VALUE2, VALUE3, VALUE4};

	_set_kv(ts->main_ctx, "key1", &data[1], 2, KV_OP_SET, true);
	_set_kv(ts->main_ctx, "key2", &data[2], 1, KV_OP_SET, false);
	_set_kv(ts->main_ctx, "key3", data, 3, KV_OP_SET, true);
	assert_int_equal(kv_store_num_entries(ts->main_ctx->common->kv_store_res), 3);
	_set_kv(ts->work_ctx, "key1", &data[2], 1, KV_OP_MINUS, true);
	_set_kv(ts->work_ctx, "key3", &data[2], 2, KV_OP_PLUS, true);
	_set_kv(ts->work_ctx, "key2", NULL, 0, KV_OP_SET, false);
	fd = _do_build_buffers(ts->work_res);
	assert_int_equal(_sync_main_kv_store(ts->main_res, ts->main_ctx->common, fd), 0);
	_check_kv(ts->main_ctx, "key1", &data[1], 1, true);
	_check_kv(ts->main_ctx, "key3", data, ARRAY_LEN(data), true);
	assert_int_equal(kv_store_num_entries(ts->main_ctx->common->kv_store_res), 2);
}

static void test_multi_broken_1(void **state)
{
	struct test_state *ts = *state;
	int                fd;
	char              *data[] = {VALUE1, VALUE2, VALUE3, VALUE4};
	struct sid_buffer *old, *new;

	_set_kv(ts->main_ctx, "key1", &data[1], 2, KV_OP_SET, true);
	_set_kv(ts->main_ctx, "key2", &data[2], 1, KV_OP_SET, false);
	_set_kv(ts->main_ctx, "key3", data, 3, KV_OP_SET, true);
	assert_int_equal(kv_store_num_entries(ts->main_ctx->common->kv_store_res), 3);
	_set_kv(ts->work_ctx, "key1", &data[2], 1, KV_OP_MINUS, true);
	_set_kv(ts->work_ctx, "key3", &data[2], 2, KV_OP_PLUS, true);
	_set_kv(ts->work_ctx, "key2", NULL, 0, KV_OP_SET, false);
	_set_broken_kv(ts->work_ctx, "key4");
	fd  = _do_build_buffers(ts->work_res);
	old = dump_db(ts->main_ctx->common->kv_store_res);
	assert_int_equal(_sync_main_kv_store(ts->main_res, ts->main_ctx->common, fd), -1);
	new = dump_db(ts->main_ctx->common->kv_store_res);
	compare_dumps(old, new);
}

static void test_multi_2(void **state)
{
	struct test_state *ts = *state;
	int                fd;
	char              *data[] = {VALUE1, VALUE2, VALUE3, VALUE4};

	_set_kv(ts->main_ctx, "key1", &data[1], 2, KV_OP_SET, true);
	_set_kv(ts->main_ctx, "key2", &data[2], 1, KV_OP_SET, false);
	_set_kv(ts->main_ctx, "key3", data, 4, KV_OP_SET, true);
	_set_kv(ts->main_ctx, "key4", &data[3], 1, KV_OP_SET, true);
	assert_int_equal(kv_store_num_entries(ts->main_ctx->common->kv_store_res), 4);
	_set_kv(ts->work_ctx, "key1", &data[2], 1, KV_OP_SET, false);
	_set_kv(ts->work_ctx, "key2", NULL, 0, KV_OP_SET, false);
	_set_kv(ts->work_ctx, "key4", data, 1, KV_OP_MINUS, true);
	_set_kv(ts->work_ctx, "key5", &data[1], 3, KV_OP_SET, true);
	fd = _do_build_buffers(ts->work_res);
	assert_int_equal(_sync_main_kv_store(ts->main_res, ts->main_ctx->common, fd), 0);
	_check_kv(ts->main_ctx, "key1", &data[2], 1, false);
	_check_kv(ts->main_ctx, "key3", data, 4, true);
	_check_kv(ts->main_ctx, "key4", &data[3], 1, true);
	_check_kv(ts->main_ctx, "key5", &data[1], 3, true);
	assert_int_equal(kv_store_num_entries(ts->main_ctx->common->kv_store_res), 4);
}

static void test_multi_broken_2(void **state)
{
	struct test_state *ts = *state;
	int                fd;
	char              *data[] = {VALUE1, VALUE2, VALUE3, VALUE4};
	struct sid_buffer *old, *new;

	_set_kv(ts->main_ctx, "key1", &data[1], 2, KV_OP_SET, true);
	_set_kv(ts->main_ctx, "key2", &data[2], 1, KV_OP_SET, false);
	_set_kv(ts->main_ctx, "key3", data, 4, KV_OP_SET, true);
	_set_kv(ts->main_ctx, "key4", &data[3], 1, KV_OP_SET, true);
	assert_int_equal(kv_store_num_entries(ts->main_ctx->common->kv_store_res), 4);
	_set_kv(ts->work_ctx, "key1", &data[2], 1, KV_OP_SET, false);
	_set_kv(ts->work_ctx, "key2", NULL, 0, KV_OP_SET, false);
	_set_kv(ts->work_ctx, "key4", data, 1, KV_OP_MINUS, true);
	_set_kv(ts->work_ctx, "key5", &data[1], 3, KV_OP_SET, true);
	_set_broken_kv(ts->work_ctx, "key6");
	fd  = _do_build_buffers(ts->work_res);
	old = dump_db(ts->main_ctx->common->kv_store_res);
	assert_int_equal(_sync_main_kv_store(ts->main_res, ts->main_ctx->common, fd), -1);
	new = dump_db(ts->main_ctx->common->kv_store_res);
	compare_dumps(old, new);
}

static void test_multi_broken_3(void **state)
{
	struct test_state *ts = *state;
	int                fd;
	char              *data[] = {VALUE1, VALUE2, VALUE3, VALUE4};
	struct sid_buffer *old, *new;

	_set_kv(ts->main_ctx, "key1", &data[1], 2, KV_OP_SET, true);
	_set_kv(ts->main_ctx, "key2", &data[2], 1, KV_OP_SET, false);
	_set_kv(ts->main_ctx, "key4", data, 4, KV_OP_SET, true);
	_set_kv(ts->main_ctx, "key5", &data[3], 1, KV_OP_SET, true);
	assert_int_equal(kv_store_num_entries(ts->main_ctx->common->kv_store_res), 4);
	_set_kv(ts->work_ctx, "key1", &data[2], 1, KV_OP_SET, false);
	_set_kv(ts->work_ctx, "key2", NULL, 0, KV_OP_SET, false);
	_set_broken_kv(ts->work_ctx, "key3");
	_set_kv(ts->work_ctx, "key5", data, 1, KV_OP_MINUS, true);
	_set_kv(ts->work_ctx, "key6", &data[1], 3, KV_OP_SET, true);
	fd  = _do_build_buffers(ts->work_res);
	old = dump_db(ts->main_ctx->common->kv_store_res);
	assert_int_equal(_sync_main_kv_store(ts->main_res, ts->main_ctx->common, fd), -1);
	new = dump_db(ts->main_ctx->common->kv_store_res);
	compare_dumps(old, new);
}

int setup(void **state)
{
	struct test_state *ts = malloc(sizeof(struct test_state));

	assert_non_null(ts);
	ts->work_res = _create_fake_cmd_res();
	ts->main_res = _create_fake_cmd_res();
	ts->work_ctx = sid_resource_get_data(ts->work_res);
	ts->main_ctx = sid_resource_get_data(ts->main_res);
	*state       = ts;
	return 0;
}

int teardown(void **state)
{
	struct test_state *ts = *state;
	sid_resource_unref(ts->work_res);
	sid_resource_unref(ts->main_res);
	free(ts);
	return 0;
}

#define setup_test(func) cmocka_unit_test_setup_teardown((func), setup, teardown)

int main(void)
{
	cmocka_set_message_output(CM_OUTPUT_STDOUT);
	const struct CMUnitTest tests[] = {
		setup_test(test_scalar),        setup_test(test_vector),           setup_test(test_unset_scalar),
		setup_test(test_unset_vector),  setup_test(test_unset_missing),    setup_test(test_vector_subtract),
		setup_test(test_vector_add),    setup_test(test_subtract_missing), setup_test(test_add_missing),
		setup_test(test_vector_change), setup_test(test_scalar_change),    setup_test(test_type_change1),
		setup_test(test_type_change2),  setup_test(test_empty_broken),     setup_test(test_set_broken),
		setup_test(test_unset_broken),  setup_test(test_change_broken),    setup_test(test_subtract_broken),
		setup_test(test_add_broken),    setup_test(test_multi_1),          setup_test(test_multi_broken_1),
		setup_test(test_multi_2),       setup_test(test_multi_broken_2),   setup_test(test_multi_broken_3),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
