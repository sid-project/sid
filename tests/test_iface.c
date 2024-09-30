/*
 * SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "../src/base/util.c"
#include "../src/iface/ifc.c"
#include "base/buf.h"
#include "iface/ifc.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

static void test_sid_ifc_cmd_name_to_type(void **state)
{
	assert_int_equal(sid_ifc_cmd_name_to_type(NULL), SID_IFC_CMD_UNDEFINED);
	assert_int_equal(sid_ifc_cmd_name_to_type("garbage"), SID_IFC_CMD_UNKNOWN);
	assert_int_equal(sid_ifc_cmd_name_to_type("active"), SID_IFC_CMD_ACTIVE);
	assert_int_equal(sid_ifc_cmd_name_to_type("checkpoint"), SID_IFC_CMD_CHECKPOINT);
	assert_int_equal(sid_ifc_cmd_name_to_type("reply"), SID_IFC_CMD_REPLY);
	assert_int_equal(sid_ifc_cmd_name_to_type("scan"), SID_IFC_CMD_SCAN);
	assert_int_equal(sid_ifc_cmd_name_to_type("version"), SID_IFC_CMD_VERSION);
	assert_int_equal(sid_ifc_cmd_name_to_type("dbdump"), SID_IFC_CMD_DBDUMP);
	assert_int_equal(sid_ifc_cmd_name_to_type("dbstats"), SID_IFC_CMD_DBSTATS);
	assert_int_equal(sid_ifc_cmd_name_to_type("resources"), SID_IFC_CMD_RESOURCES);
}

char *__wrap_getenv(const char *name)
{
	return mock_ptr_type(char *);
}

#define TEST_COMM_FD   1111
#define TEST_EXPORT_FD 9999

int __real_close(int fd);

int __wrap_close(int fd)
{
	if (fd != TEST_COMM_FD && fd != TEST_EXPORT_FD)
		return __real_close(fd);
	return 0;
}

int __wrap_sid_comms_unix_init(const char *path, size_t path_len, int type)
{
	return TEST_COMM_FD;
}

ssize_t __wrap_sid_comms_unix_recv(int socket_fd, void *buf, ssize_t buf_len, int *fd_received)
{
	*fd_received = TEST_EXPORT_FD;
	return mock_type(ssize_t);
}

int __wrap_sid_buf_write_all(struct sid_buf *buf, int fd)
{
	char  *hdr;
	size_t size;
	int    ret;

	assert_int_equal(fd, TEST_COMM_FD);
	ret = mock_type(int);
	if (ret != 0)
		return ret;
	assert_int_equal(sid_buf_get_data(buf, (const void **) &hdr, &size), 0);
	assert_int_equal(size, mock_type(size_t));
	assert_int_equal(memcmp(hdr, mock_ptr_type(char *), size), 0);
	return ret;
}

ssize_t __wrap_sid_buf_read(struct sid_buf *buf, int fd)
{
	void   *data;
	ssize_t size = mock_type(ssize_t);

	if (size <= 0)
		return size;
	data = mock_ptr_type(void *);
	assert_int_equal(sid_buf_add(buf, data, size, NULL, NULL), 0);
	/* need to update size prefix */
	sid_buf_get_fd(buf);
	return size;
}

ssize_t __real_read(int fd, void *buf, size_t count);

ssize_t __wrap_read(int fd, void *buf, size_t count)
{
	ssize_t                  val;
	SID_BUF_SIZE_PREFIX_TYPE msg_size;

	if (fd != TEST_EXPORT_FD)
		return __real_read(fd, buf, count);
	val = mock_type(ssize_t);
	if (val < 0) {
		errno = -val;
		return val;
	}
	msg_size = val;
	assert_int_equal(count, SID_BUF_SIZE_PREFIX_LEN);
	assert_non_null(buf);
	memcpy(buf, &msg_size, SID_BUF_SIZE_PREFIX_LEN);
	return SID_BUF_SIZE_PREFIX_LEN;
}

void *_test_mmap_return;

void *__real_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);

void *__wrap_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	SID_BUF_SIZE_PREFIX_TYPE buf_len;
	ssize_t                  val;

	if (fd != TEST_EXPORT_FD)
		return __real_mmap(addr, length, prot, flags, fd, offset);
	val = mock_type(ssize_t);
	if (val < 0) {
		errno = -val;
		return MAP_FAILED;
	}
	assert_null(addr);
	assert_int_equal(length, val + SID_BUF_SIZE_PREFIX_LEN);
	assert_int_equal(prot, PROT_READ);
	assert_int_equal(flags, MAP_SHARED);
	assert_int_equal(offset, 0);
	assert_null(_test_mmap_return);

	_test_mmap_return = malloc(length);
	assert_non_null(_test_mmap_return);
	buf_len = length;

	memcpy(_test_mmap_return, &buf_len, SID_BUF_SIZE_PREFIX_LEN);
	memcpy(_test_mmap_return + SID_BUF_SIZE_PREFIX_LEN, mock_ptr_type(void *), length - SID_BUF_SIZE_PREFIX_LEN);
	return _test_mmap_return;
}

int __real_munmap(void *addr, size_t length);

int __wrap_munmap(void *addr, size_t length)
{
	if (!addr || addr != _test_mmap_return)
		__real_munmap(addr, length);
	assert_int_equal(length, mock_type(SID_BUF_SIZE_PREFIX_TYPE) + SID_BUF_SIZE_PREFIX_LEN);
	free(_test_mmap_return);
	_test_mmap_return = NULL;
	return 0;
}

static void _test_checkpoint(char *name, char *keys[], char *values[], int nr_keys, int ret_val)
{
	dev_t                          devnum = makedev(8, 0);
	char                          *data, *p, *kv;
	size_t                         size;
	struct sid_buf                *buf;
	struct sid_ifc_checkpoint_data check_data = {.name = name, .keys = keys, .nr_keys = nr_keys};
	unsigned int                   i;

	buf = sid_buf_create(&((struct sid_buf_spec) {.backend = SID_BUF_BACKEND_MALLOC,
	                                              .type    = SID_BUF_TYPE_LINEAR,
	                                              .mode    = SID_BUF_MODE_SIZE_PREFIX}),
	                     &((struct sid_buf_init) {.size = 0, .alloc_step = 1, .limit = 0}),
	                     NULL);

	assert_non_null(buf);
	if (ret_val == 0) {
		will_return(__wrap_getenv, "8");
		will_return(__wrap_getenv, "0");
		for (i = 0; i < nr_keys; i++) {
			will_return(__wrap_getenv, values[i]);
		}
	}
	assert_int_equal(_add_checkpoint_env_to_buf(buf, &check_data), ret_val);
	if (ret_val) {
		sid_buf_destroy(buf);
		return;
	}
	assert_int_equal(sid_buf_get_data(buf, (const void **) &data, &size), 0);
	assert_true(devnum == *(dev_t *) data);
	p = data + sizeof(dev_t);
	assert_string_equal(p, name);
	p += strlen(p) + 1;
	for (i = 0; i < nr_keys; i++) {
		assert_true(asprintf(&kv, "%s=%s", keys[i], values[i]) > 0);
		assert_string_equal(p, kv);
		p += strlen(p) + 1;
		free(kv);
	}
	assert_int_equal(size, p - data);
	sid_buf_destroy(buf);
}

#define CHECKPOINT_NAME "checkpoint_name"
#define NR_KEYS         2
char *check_keys[]   = {"KEY1", "KEY2"};
char *check_values[] = {"VALUE1", "VALUE2"};

static void test_checkpoint_with_key(void **state)
{
	_test_checkpoint(CHECKPOINT_NAME, check_keys, check_values, NR_KEYS, 0);
}

static void test_checkpoint_no_keys(void **state)
{
	_test_checkpoint(CHECKPOINT_NAME, NULL, NULL, 0, 0);
}

static void test_checkpoint_no_name(void **state)
{
	_test_checkpoint(NULL, check_keys, check_values, NR_KEYS, -EINVAL);
}

static void test_checkpoint_missing_keys(void **state)
{
	_test_checkpoint(CHECKPOINT_NAME, NULL, NULL, NR_KEYS, -EINVAL);
}

static void test_add_scan_env(void **state)
{
	struct sid_buf *buf;
	dev_t           devnum = makedev(8, 0);
	char           *data, *p, **kv;
	size_t          size;

	buf = sid_buf_create(&((struct sid_buf_spec) {.backend = SID_BUF_BACKEND_MALLOC,
	                                              .type    = SID_BUF_TYPE_LINEAR,
	                                              .mode    = SID_BUF_MODE_SIZE_PREFIX}),
	                     &((struct sid_buf_init) {.size = 0, .alloc_step = 1, .limit = 0}),
	                     NULL);
	assert_non_null(buf);
	will_return(__wrap_getenv, "8");
	will_return(__wrap_getenv, "0");
	assert_int_equal(_add_scan_env_to_buf(buf), 0);
	assert_int_equal(sid_buf_get_data(buf, (const void **) &data, &size), 0);
	assert_true(devnum == *(dev_t *) data);
	p = data + sizeof(dev_t);
	for (kv = environ; *kv; kv++) {
		assert_string_equal(*kv, p);
		p += strlen(p) + 1;
	}
	assert_int_equal(size, p - data);
	sid_buf_destroy(buf);
}

static void test_sid_ifc_req_fail_no_res(void **state)
{
	struct sid_ifc_req req;

	assert_int_equal(sid_ifc_req(&req, NULL), -EINVAL);
}

static void test_sid_ifc_req_fail_no_req(void **state)
{
	struct sid_ifc_rsl *rsl;

	assert_int_equal(sid_ifc_req(NULL, &rsl), -EINVAL);
	assert_null(rsl);
}

static void test_sid_ifc_req_fail_missing(void **state)
{
	struct sid_ifc_req              req = {.flags = SID_IFC_CMD_FL_UNMODIFIED_DATA};
	struct sid_ifc_rsl             *rsl;
	struct sid_ifc_unmodified_data *data = &req.data.unmodified;

	data->mem                            = NULL;
	data->size                           = 1;
	assert_int_equal(sid_ifc_req(&req, &rsl), -EINVAL);
	assert_null(rsl);
}

static void test_sid_ifc_req_fail_write(void **state)
{
	struct sid_ifc_req  req = {.cmd = SID_IFC_CMD_VERSION};
	struct sid_ifc_rsl *rsl;

	will_return(__wrap_sid_buf_write_all, -ENODATA);
	assert_int_equal(sid_ifc_req(&req, &rsl), -ENODATA);
	assert_null(rsl);
}

static void test_sid_ifc_req_fail_read1(void **state)
{
	struct sid_ifc_req        req = {.cmd = SID_IFC_CMD_VERSION};
	struct sid_ifc_rsl       *rsl;
	struct sid_ifc_msg_header hdr = {.prot = SID_IFC_PROTOCOL, .cmd = SID_IFC_CMD_VERSION};

	will_return(__wrap_sid_buf_write_all, 0);
	will_return(__wrap_sid_buf_write_all, sizeof(hdr));
	will_return(__wrap_sid_buf_write_all, &hdr);
	will_return(__wrap_sid_buf_read, -EBADMSG);
	assert_int_equal(sid_ifc_req(&req, &rsl), -EBADMSG);
	assert_null(rsl);
}

static void test_sid_ifc_req_fail_read2(void **state)
{
	struct sid_ifc_req        req = {.cmd = SID_IFC_CMD_VERSION};
	struct sid_ifc_rsl       *rsl;
	struct sid_ifc_msg_header hdr = {.prot = SID_IFC_PROTOCOL, .cmd = SID_IFC_CMD_VERSION};

	will_return(__wrap_sid_buf_write_all, 0);
	will_return(__wrap_sid_buf_write_all, sizeof(hdr));
	will_return(__wrap_sid_buf_write_all, &hdr);
	will_return(__wrap_sid_buf_read, -EINTR);
	will_return(__wrap_sid_buf_read, -EAGAIN);
	will_return(__wrap_sid_buf_read, 0);
	assert_int_equal(sid_ifc_req(&req, &rsl), -EBADMSG);
	assert_null(rsl);
}

static struct sid_ifc_rsl *__do_sid_ifc_req(struct sid_ifc_req *req,
                                            void               *req_data,
                                            size_t              req_data_size,
                                            uint64_t            status,
                                            void               *res_data,
                                            ssize_t             res_data_size,
                                            int                 ret)
{
	struct sid_ifc_msg_header *res_hdr, *req_hdr;
	struct sid_ifc_rsl        *rsl;

	req_hdr = calloc(1, sizeof(*req_hdr) + req_data_size);
	assert_non_null(req_hdr);
	req_hdr->status = req->seqnum;
	req_hdr->prot   = SID_IFC_PROTOCOL;
	req_hdr->cmd    = req->cmd;
	req_hdr->flags  = req->flags;
	if (req_data) {
		assert_true(req_data_size > 0);
		memcpy((char *) req_hdr + SID_IFC_MSG_HEADER_SIZE, req_data, req_data_size);
	}
	res_hdr = calloc(1, sizeof(*res_hdr) + res_data_size);
	assert_non_null(res_hdr);
	res_hdr->status = status;
	res_hdr->prot   = SID_IFC_PROTOCOL;
	res_hdr->cmd    = SID_IFC_CMD_REPLY;
	res_hdr->flags  = req->flags;
	if (res_data) {
		assert_true(res_data_size > 0);
		memcpy((char *) res_hdr + SID_IFC_MSG_HEADER_SIZE, res_data, res_data_size);
	}
	will_return(__wrap_sid_buf_write_all, 0);
	will_return(__wrap_sid_buf_write_all, sizeof(*req_hdr) + req_data_size);
	will_return(__wrap_sid_buf_write_all, req_hdr);
	will_return(__wrap_sid_buf_read, sizeof(*res_hdr) + res_data_size);
	will_return(__wrap_sid_buf_read, res_hdr);
	assert_int_equal(sid_ifc_req(req, &rsl), ret);
	free(req_hdr);
	free(res_hdr);

	return rsl;
}

static void __check_sid_ifc_req(struct sid_ifc_req *req,
                                void               *req_data,
                                size_t              req_data_size,
                                uint64_t            status,
                                void               *res_data,
                                ssize_t             res_data_size)
{
	const char         *data;
	uint64_t            res_status;
	uint8_t             res_prot;
	size_t              size;
	struct sid_ifc_rsl *rsl = __do_sid_ifc_req(req, req_data, req_data_size, status, res_data, res_data_size, 0);

	assert_non_null(rsl);
	assert_int_equal(sid_ifc_rsl_get_status(rsl, &res_status), 0);
	assert_int_equal(res_status, status);
	assert_int_equal(sid_ifc_rsl_get_protocol(rsl, &res_prot), 0);
	assert_int_equal(res_prot, SID_IFC_PROTOCOL);
	data = sid_ifc_rsl_get_data(rsl, &size);
	assert_int_equal(size, (status & SID_IFC_CMD_STATUS_FAILURE) ? 0 : res_data_size);
	if (status & SID_IFC_CMD_STATUS_FAILURE || res_data_size == 0)
		assert_null(data);
	else
		assert_memory_equal(data, res_data, res_data_size);
	sid_ifc_rsl_free(rsl);
}

#define RESULT_DATA "SID_IFC_PROTOCOL: 2\nSID_MAJOR: 1\nSID_MINOR: 2\nSID_RELEASE: 3\n"

static void test_sid_ifc_req_basic_pass(void **state)
{
	struct sid_ifc_req req = {.cmd = SID_IFC_CMD_VERSION};

	__check_sid_ifc_req(&req, NULL, 0, 0, RESULT_DATA, sizeof(RESULT_DATA));
}

static void test_sid_ifc_req_basic_fail1(void **state)
{
	struct sid_ifc_req req = {.cmd = SID_IFC_CMD_VERSION};

	__check_sid_ifc_req(&req, NULL, 0, SID_IFC_CMD_STATUS_FAILURE, NULL, 0);
}

static void test_sid_ifc_req_basic_fail2(void **state)
{
	struct sid_ifc_req req = {.cmd = SID_IFC_CMD_VERSION};

	__check_sid_ifc_req(&req, NULL, 0, SID_IFC_CMD_STATUS_FAILURE, RESULT_DATA, sizeof(RESULT_DATA));
}

static void test_sid_ifc_req_basic_no_data(void **state)
{
	struct sid_ifc_req req = {.cmd = SID_IFC_CMD_VERSION};

	__check_sid_ifc_req(&req, NULL, 0, 0, NULL, 0);
}

static void test_sid_ifc_req_scan(void **state)
{
	struct sid_ifc_req req = {.cmd = SID_IFC_CMD_SCAN};
	struct sid_buf    *buf;
	char              *data;
	size_t             size;

	buf = sid_buf_create(&((struct sid_buf_spec) {.backend = SID_BUF_BACKEND_MALLOC,
	                                              .type    = SID_BUF_TYPE_LINEAR,
	                                              .mode    = SID_BUF_MODE_SIZE_PREFIX}),
	                     &((struct sid_buf_init) {.size = 0, .alloc_step = 1, .limit = 0}),
	                     NULL);

	assert_non_null(buf);
	will_return(__wrap_getenv, "8");
	will_return(__wrap_getenv, "0");
	assert_int_equal(_add_scan_env_to_buf(buf), 0);
	assert_int_equal(sid_buf_get_data(buf, (const void **) &data, &size), 0);
	will_return(__wrap_getenv, "8");
	will_return(__wrap_getenv, "0");
	__check_sid_ifc_req(&req, data, size, 0, RESULT_DATA, sizeof(RESULT_DATA));
}

static void test_sid_ifc_req_checkpoint(void **state)
{
	struct sid_ifc_req              req = {.cmd = SID_IFC_CMD_CHECKPOINT};
	struct sid_buf                 *buf;
	char                           *req_data;
	size_t                          size;
	struct sid_ifc_checkpoint_data *data = &req.data.checkpoint;
	int                             i;

	data->name    = CHECKPOINT_NAME;
	data->keys    = check_keys;
	data->nr_keys = NR_KEYS;
	buf           = sid_buf_create(&((struct sid_buf_spec) {.backend = SID_BUF_BACKEND_MALLOC,
	                                                        .type    = SID_BUF_TYPE_LINEAR,
	                                                        .mode    = SID_BUF_MODE_SIZE_PREFIX}),
                             &((struct sid_buf_init) {.size = 0, .alloc_step = 1, .limit = 0}),
                             NULL);

	assert_non_null(buf);
	will_return(__wrap_getenv, "8");
	will_return(__wrap_getenv, "0");
	for (i = 0; i < NR_KEYS; i++) {
		will_return(__wrap_getenv, check_values[i]);
	}
	assert_int_equal(_add_checkpoint_env_to_buf(buf, data), 0);
	assert_int_equal(sid_buf_get_data(buf, (const void **) &req_data, &size), 0);
	will_return(__wrap_getenv, "8");
	will_return(__wrap_getenv, "0");
	for (i = 0; i < NR_KEYS; i++) {
		will_return(__wrap_getenv, check_values[i]);
	}
	__check_sid_ifc_req(&req, req_data, size, 0, RESULT_DATA, sizeof(RESULT_DATA));
}

static void test_sid_ifc_req_export_pass(void **state)
{
	struct sid_ifc_req req = {.cmd = SID_IFC_CMD_DBDUMP};

	will_return(__wrap_sid_comms_unix_recv, sizeof(unsigned char));
	will_return(__wrap_read, sizeof(RESULT_DATA) + SID_BUF_SIZE_PREFIX_LEN);
	will_return(__wrap_mmap, sizeof(RESULT_DATA));
	will_return(__wrap_mmap, RESULT_DATA);
	will_return(__wrap_munmap, sizeof(RESULT_DATA));
	__check_sid_ifc_req(&req, NULL, 0, 0, RESULT_DATA, sizeof(RESULT_DATA));
}

static void test_sid_ifc_req_export_fail1(void **state)
{
	struct sid_ifc_req req = {.cmd = SID_IFC_CMD_DBDUMP};

	will_return(__wrap_sid_comms_unix_recv, sizeof(unsigned char));
	will_return(__wrap_read, sizeof(RESULT_DATA) + SID_BUF_SIZE_PREFIX_LEN);
	will_return(__wrap_mmap, sizeof(RESULT_DATA));
	will_return(__wrap_mmap, RESULT_DATA);
	will_return(__wrap_munmap, sizeof(RESULT_DATA));
	__check_sid_ifc_req(&req, NULL, 0, SID_IFC_CMD_STATUS_FAILURE, NULL, 0);
}

static void test_sid_ifc_req_export_fail2(void **state)
{
	struct sid_ifc_req req = {.cmd = SID_IFC_CMD_DBDUMP};

	will_return(__wrap_sid_comms_unix_recv, sizeof(unsigned char));
	will_return(__wrap_read, sizeof(RESULT_DATA) + SID_BUF_SIZE_PREFIX_LEN);
	will_return(__wrap_mmap, sizeof(RESULT_DATA));
	will_return(__wrap_mmap, RESULT_DATA);
	will_return(__wrap_munmap, sizeof(RESULT_DATA));
	__check_sid_ifc_req(&req, NULL, 0, SID_IFC_CMD_STATUS_FAILURE, RESULT_DATA, sizeof(RESULT_DATA));
}

static void test_sid_ifc_req_export_no_data(void **state)
{
	struct sid_ifc_req req = {.cmd = SID_IFC_CMD_DBDUMP};

	will_return(__wrap_sid_comms_unix_recv, sizeof(unsigned char));
	will_return(__wrap_read, SID_BUF_SIZE_PREFIX_LEN);
	__check_sid_ifc_req(&req, NULL, 0, 0, NULL, 0);
}

static void test_sid_ifc_req_fail_recv_fd(void **state)
{
	struct sid_ifc_req  req = {.cmd = SID_IFC_CMD_DBDUMP};
	struct sid_ifc_rsl *rsl;

	will_return(__wrap_sid_comms_unix_recv, -EINTR);
	will_return(__wrap_sid_comms_unix_recv, -ENOTCONN);
	rsl = __do_sid_ifc_req(&req, NULL, 0, 0, NULL, 0, -ENOTCONN);
	assert_null(rsl);
}

static void test_sid_ifc_req_fail_read_fd1(void **state)
{
	struct sid_ifc_req  req = {.cmd = SID_IFC_CMD_DBDUMP};
	struct sid_ifc_rsl *rsl;

	will_return(__wrap_sid_comms_unix_recv, sizeof(unsigned char));
	will_return(__wrap_read, -EINTR);
	will_return(__wrap_read, -EIO);
	rsl = __do_sid_ifc_req(&req, NULL, 0, 0, NULL, 0, -EIO);
	assert_null(rsl);
}

static void test_sid_ifc_req_fail_read_fd2(void **state)
{
	struct sid_ifc_req  req = {.cmd = SID_IFC_CMD_DBDUMP};
	struct sid_ifc_rsl *rsl;

	will_return(__wrap_sid_comms_unix_recv, sizeof(unsigned char));
	will_return(__wrap_read, SID_BUF_SIZE_PREFIX_LEN - 1);
	rsl = __do_sid_ifc_req(&req, NULL, 0, 0, NULL, 0, -EBADMSG);
	assert_null(rsl);
}

static void test_sid_ifc_req_fail_mmap(void **state)
{
	struct sid_ifc_req  req = {.cmd = SID_IFC_CMD_DBDUMP};
	struct sid_ifc_rsl *rsl;

	will_return(__wrap_sid_comms_unix_recv, sizeof(unsigned char));
	will_return(__wrap_read, sizeof(RESULT_DATA) + SID_BUF_SIZE_PREFIX_LEN);
	will_return(__wrap_mmap, -ENOMEM);
	rsl = __do_sid_ifc_req(&req, NULL, 0, 0, NULL, 0, -ENOMEM);
	assert_null(rsl);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_sid_ifc_cmd_name_to_type),  cmocka_unit_test(test_checkpoint_with_key),
		cmocka_unit_test(test_checkpoint_no_keys),        cmocka_unit_test(test_checkpoint_no_name),
		cmocka_unit_test(test_checkpoint_missing_keys),   cmocka_unit_test(test_add_scan_env),
		cmocka_unit_test(test_sid_ifc_req_fail_no_res),   cmocka_unit_test(test_sid_ifc_req_fail_no_req),
		cmocka_unit_test(test_sid_ifc_req_fail_missing),  cmocka_unit_test(test_sid_ifc_req_fail_write),
		cmocka_unit_test(test_sid_ifc_req_fail_read1),    cmocka_unit_test(test_sid_ifc_req_fail_read2),
		cmocka_unit_test(test_sid_ifc_req_basic_pass),    cmocka_unit_test(test_sid_ifc_req_basic_fail1),
		cmocka_unit_test(test_sid_ifc_req_basic_fail2),   cmocka_unit_test(test_sid_ifc_req_basic_no_data),
		cmocka_unit_test(test_sid_ifc_req_scan),          cmocka_unit_test(test_sid_ifc_req_checkpoint),
		cmocka_unit_test(test_sid_ifc_req_export_pass),   cmocka_unit_test(test_sid_ifc_req_export_fail1),
		cmocka_unit_test(test_sid_ifc_req_export_fail2),  cmocka_unit_test(test_sid_ifc_req_export_no_data),
		cmocka_unit_test(test_sid_ifc_req_fail_recv_fd),  cmocka_unit_test(test_sid_ifc_req_fail_read_fd1),
		cmocka_unit_test(test_sid_ifc_req_fail_read_fd2), cmocka_unit_test(test_sid_ifc_req_fail_mmap),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
