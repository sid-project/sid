if HAVE_CMOCKA
check_PROGRAMS = \
	test_buffer \
	test_notify \
	test_kv_store \
	test_bitmap
TESTS = $(check_PROGRAMS)
test_buffer_SOURCES = test_buffer.c
test_buffer_LDADD = $(top_builddir)/src/misc/libsidmisc.la -lcmocka
test_kv_store_SOURCES = test_kv_store.c
test_kv_store_LDADD = \
	$(top_builddir)/src/misc/libsidmisc.la \
	$(top_builddir)/src/resource/libsidresource.la -lcmocka
test_notify_SOURCES = test_notify.c
test_notify_LDFLAGS = -Wl,--wrap=sd_notify -Wl,--wrap=buffer_get_data
test_notify_LDADD = $(top_builddir)/src/iface/libsidiface.la -lcmocka
test_bitmap_SOURCES = test_bitmap.c
test_bitmap_LDADD = $(top_builddir)/src/misc/libsidmisc.la -lcmocka
endif # HAVE_CMOCKA
