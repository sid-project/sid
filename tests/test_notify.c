#include "../src/iface/service-link.c"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <systemd/sd-daemon.h>

#include <cmocka.h>

int __wrap_sd_notify(int unset_environment, const char *state)
{
	assert_string_equal(state, mock_ptr_type(char *));
	return 0;
}

int __real_sid_buf_get_data(struct sid_buf *buf, const void **data, size_t *data_size);

int __wrap_sid_buf_get_data(struct sid_buf *buf, const void **data, size_t *data_size)
{
	int r = __real_sid_buf_get_data(buf, data, data_size);
	assert_true(!*data || *data_size);
	return r;
}

static void test_notify_ready(void **state)
{
	struct sid_srv_lnk *sl = sid_srv_lnk_create(SID_SRV_LNK_TYPE_SYSTEMD, "systemd");

	assert_non_null(sl);
	sid_srv_lnk_notif_add(sl, SID_SRV_LNK_NOTIF_READY);
	will_return(__wrap_sd_notify, "READY=1\n");
	assert_int_equal(sid_srv_lnk_notify(sl, SID_SRV_LNK_NOTIF_READY, &SID_SRV_LNK_DEFAULT_LOG_REQ, NULL), 0);
	sid_srv_lnk_destroy(sl);
}

static void test_notify_ready_reloading(void **state)
{
	struct sid_srv_lnk *sl = sid_srv_lnk_create(SID_SRV_LNK_TYPE_SYSTEMD, "systemd");

	assert_non_null(sl);
	sid_srv_lnk_notif_add(sl, SID_SRV_LNK_NOTIF_READY);
	sid_srv_lnk_notif_add(sl, SID_SRV_LNK_NOTIF_RELOADING);
	will_return(__wrap_sd_notify, "READY=1\nRELOADING=1\n");
	assert_int_equal(
		sid_srv_lnk_notify(sl, SID_SRV_LNK_NOTIF_READY | SID_SRV_LNK_NOTIF_RELOADING, &SID_SRV_LNK_DEFAULT_LOG_REQ, NULL),
		0);
	sid_srv_lnk_destroy(sl);
}

static void test_notify_blank(void **state)
{
	struct sid_srv_lnk *sl = sid_srv_lnk_create(SID_SRV_LNK_TYPE_SYSTEMD, "systemd");

	assert_non_null(sl);
	sid_srv_lnk_notif_add(sl, SID_SRV_LNK_NOTIF_STATUS);
	will_return(__wrap_sd_notify, "");
	assert_int_equal(sid_srv_lnk_notify(sl, SID_SRV_LNK_NOTIF_STATUS, &SID_SRV_LNK_DEFAULT_LOG_REQ, NULL), 0);
	sid_srv_lnk_destroy(sl);
}

static void test_notify_errno(void **state)
{
	struct sid_srv_lnk *sl = sid_srv_lnk_create(SID_SRV_LNK_TYPE_SYSTEMD, "systemd");

	assert_non_null(sl);
	sid_srv_lnk_notif_add(sl, SID_SRV_LNK_NOTIF_ERRNO);
	will_return(__wrap_sd_notify, "ERRNO=2\n");
	assert_int_equal(sid_srv_lnk_notify(sl, SID_SRV_LNK_NOTIF_ERRNO, &SID_SRV_LNK_DEFAULT_LOG_REQ, "ERRNO=%d\n", 2), 0);
	sid_srv_lnk_destroy(sl);
}

static void test_notify_errno_status(void **state)
{
	struct sid_srv_lnk *sl = sid_srv_lnk_create(SID_SRV_LNK_TYPE_SYSTEMD, "systemd");

	assert_non_null(sl);
	sid_srv_lnk_notif_add(sl, SID_SRV_LNK_NOTIF_ERRNO);
	sid_srv_lnk_notif_add(sl, SID_SRV_LNK_NOTIF_STATUS);
	will_return(__wrap_sd_notify, "STATUS=testing\nERRNO=2\n");
	assert_int_equal(sid_srv_lnk_notify(sl,
	                                    SID_SRV_LNK_NOTIF_ERRNO | SID_SRV_LNK_NOTIF_STATUS,
	                                    &SID_SRV_LNK_DEFAULT_LOG_REQ,
	                                    "ERRNO=%d\nSTATUS=testing",
	                                    2),
	                 0);
	sid_srv_lnk_destroy(sl);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_notify_ready),
		cmocka_unit_test(test_notify_ready_reloading),
		cmocka_unit_test(test_notify_blank),
		cmocka_unit_test(test_notify_errno),
		cmocka_unit_test(test_notify_errno_status),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
