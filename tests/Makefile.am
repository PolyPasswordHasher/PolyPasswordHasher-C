AM_CFLAGS = -I$(top_builddir)/include

TESTS = check_libgfshare check_libpolypasshash
check_PROGRAMS = check_libgfshare check_libpolypasshash
check_libgfshare_SOURCES = check_libgfshare.c\
													$(top_builddir)/include/libgfshare.h\
												$(top_builddir)/include/libgfshare_tables.h
check_libgfshare_CFLAGS = @CHECK_CFLAGS@ -I../include
check_libgfshare_LDADD = $(top_builddir)/lib/libgfshare.la @CHECK_LIBS@

check_libpolypasshash_SOURCES = check_libpolypasshash.c\
																$(top_builddir)/include/libgfshare.h\
																$(top_builddir)/include/libpolypasshash.h
check_libpolypasshash_CFLAGS = @CHECK_CFLAGS@ -I$(top_builddir)/include
check_libpolypasshash_LDADD = $(top_builddir)/lib/libgfshare.la\
															$(top_builddir)/lib/libpolypasshash.la\
															@CHECK_LIBS@


