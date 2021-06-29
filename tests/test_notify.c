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

int __real_sid_buffer_get_data(struct buffer *buf, const void **data, size_t *data_size);

int __wrap_sid_buffer_get_data(struct buffer *buf, const void **data, size_t *data_size)
{
	int r = __real_sid_buffer_get_data(buf, data, data_size);
	assert_true(!*data || *data_size);
	return r;
}

static void test_notify_ready(void **state)
{
	struct service_link *sl = service_link_create(SERVICE_TYPE_SYSTEMD, "systemd");

	assert_non_null(sl);
	assert_int_equal(service_link_add_notification(sl, SERVICE_NOTIFICATION_READY), 0);
	will_return(__wrap_sd_notify, "READY=1\n");
	assert_int_equal(service_link_notify(sl, SERVICE_NOTIFICATION_READY, NULL), 0);
	service_link_destroy(sl);
}

static void test_notify_ready_reloading(void **state)
{
	struct service_link *sl = service_link_create(SERVICE_TYPE_SYSTEMD, "systemd");

	assert_non_null(sl);
	assert_int_equal(service_link_add_notification(sl, SERVICE_NOTIFICATION_READY), 0);
	assert_int_equal(service_link_add_notification(sl, SERVICE_NOTIFICATION_RELOADING), 0);
	will_return(__wrap_sd_notify, "READY=1\nRELOADING=1\n");
	assert_int_equal(service_link_notify(sl, SERVICE_NOTIFICATION_READY | SERVICE_NOTIFICATION_RELOADING, NULL), 0);
	service_link_destroy(sl);
}

static void test_notify_blank(void **state)
{
	struct service_link *sl = service_link_create(SERVICE_TYPE_SYSTEMD, "systemd");

	assert_non_null(sl);
	assert_int_equal(service_link_add_notification(sl, SERVICE_NOTIFICATION_STATUS), 0);
	will_return(__wrap_sd_notify, "");
	assert_int_equal(service_link_notify(sl, SERVICE_NOTIFICATION_STATUS, NULL), 0);
	service_link_destroy(sl);
}

static void test_notify_errno(void **state)
{
	struct service_link *sl = service_link_create(SERVICE_TYPE_SYSTEMD, "systemd");

	assert_non_null(sl);
	assert_int_equal(service_link_add_notification(sl, SERVICE_NOTIFICATION_ERRNO), 0);
	will_return(__wrap_sd_notify, "ERRNO=2\n");
	assert_int_equal(service_link_notify(sl, SERVICE_NOTIFICATION_ERRNO, "ERRNO=%d\n", 2), 0);
	service_link_destroy(sl);
}

static void test_notify_errno_status(void **state)
{
	struct service_link *sl = service_link_create(SERVICE_TYPE_SYSTEMD, "systemd");

	assert_non_null(sl);
	assert_int_equal(service_link_add_notification(sl, SERVICE_NOTIFICATION_ERRNO), 0);
	assert_int_equal(service_link_add_notification(sl, SERVICE_NOTIFICATION_STATUS), 0);
	will_return(__wrap_sd_notify, "STATUS=testing\nERRNO=2\n");
	assert_int_equal(
		service_link_notify(sl, SERVICE_NOTIFICATION_ERRNO | SERVICE_NOTIFICATION_STATUS, "ERRNO=%d\nSTATUS=testing", 2),
		0);
	service_link_destroy(sl);
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
