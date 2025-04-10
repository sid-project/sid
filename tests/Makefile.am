#
# SPDX-FileCopyrightText: (C) 2017-2025 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

if HAVE_CMOCKA

include $(top_srcdir)/Makefile.common

LOG_DRIVER = CMOCKA_MESSAGE_OUTPUT=TAP $(top_srcdir)/autoconf/tap-driver.sh

check_PROGRAMS = \
	test_buffer \
	test_hash \
	test_notify \
	test_kv_store \
	test_bitmap \
	test_iface \
	test_internal \
	test_bptree \
	test_db_sync

TESTS = $(check_PROGRAMS)
test_buffer_SOURCES = test_buffer.c
test_buffer_LDADD = $(top_builddir)/src/internal/libsidinternal.la \
		    $(top_builddir)/src/base/libsidbase.la -lcmocka
test_hash_SOURCES = test_hash.c
test_hash_LDADD = $(top_builddir)/src/internal/libsidinternal.la \
		  $(top_builddir)/src/base/libsidbase.la -lcmocka
test_kv_store_SOURCES = test_kv_store.c
test_kv_store_CFLAGS = -I$(top_srcdir)/src/include/resource
test_kv_store_LDADD = \
	$(top_builddir)/src/base/libsidbase.la \
	$(top_builddir)/src/resource/libsidresource.la -lcmocka
test_notify_SOURCES = test_notify.c
test_notify_LDFLAGS = -Wl,--wrap=sd_notify -Wl,--wrap=sid_buf_get_data
test_notify_LDADD = \
	$(top_builddir)/src/iface/libsidiface_servicelink.la -lcmocka
test_bitmap_SOURCES = test_bitmap.c
test_bitmap_LDADD = $(top_builddir)/src/internal/libsidinternal.la \
		    $(top_builddir)/src/base/libsidbase.la -lcmocka
test_iface_SOURCES = test_iface.c
test_iface_LDFLAGS = -Wl,--wrap=read -Wl,--wrap=close -Wl,--wrap=getenv \
	-Wl,--wrap=sid_comms_unix_init -Wl,--wrap=sid_comms_unix_recv \
	-Wl,--wrap=sid_buf_write_all -Wl,--wrap=sid_buf_read \
	-Wl,--wrap=mmap -Wl,--wrap=munmap
test_iface_LDADD = $(top_builddir)/src/base/libsidbase.la -lcmocka
test_internal_SOURCES = test_internal.c
test_internal_LDADD = $(top_builddir)/src/internal/libsidinternal.la \
		      $(top_builddir)/src/base/libsidbase.la -lcmocka
test_bptree_SOURCES = test_bptree.c
test_bptree_LDADD = $(top_builddir)/src/internal/libsidinternal.la \
		    $(top_builddir)/src/base/libsidbase.la -lcmocka
test_db_sync_SOURCES = test_db_sync.c
test_db_sync_CFLAGS = -I$(top_srcdir)/src/include/resource
test_db_sync_LDADD = \
	$(top_builddir)/src/base/libsidbase.la \
	$(top_builddir)/src/resource/libsidresource.la -lcmocka

endif # HAVE_CMOCKA
