if HAVE_CMOCKA
check_PROGRAMS = test_buffer
TESTS = $(check_PROGRAMS)
test_buffer_SOURCES = test_buffer.c
test_buffer_LDADD = $(top_builddir)/src/misc/libsidmisc.la -lcmocka
endif # HAVE_CMOCKA
