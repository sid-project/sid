if HAVE_CMOCKA
check_PROGRAMS = \
	test_buffer \
	test_notify
TESTS = $(check_PROGRAMS)
test_buffer_SOURCES = test_buffer.c
test_buffer_LDADD = $(top_builddir)/src/misc/libsidmisc.la -lcmocka
test_notify_SOURCES = test_notify.c
test_notify_LDFLAGS = -Wl,--wrap=sd_notify -Wl,--wrap=buffer_get_data
test_notify_LDADD = $(top_builddir)/src/iface/libsidiface.la -lcmocka
endif # HAVE_CMOCKA
