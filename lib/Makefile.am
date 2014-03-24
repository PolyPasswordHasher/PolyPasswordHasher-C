AM_CFLAGS = -I$(top_builddir)/include
AM_LDFLAGS = -lcrypto

lib_LTLIBRARIES = libgfshare.la libpolypasshash.la
libgfshare_la_SOURCES = $(top_builddir)/include/libgfshare.h libgfshare.c \
												$(top_builddir)/include/libgfshare_tables.h
include_HEADERS = $(top_builddir)/include/libgfshare.h
									$(top_builddir)/include/libpolypasshash.h

libpolypasshash_la_SOURCES = libpolypasshash.c\
														 $(top_builddir)/include/libgfshare.h\
														 $(top_builddir)/include/libpolypasshash.h
libpolypasshash_la_LIBADD = $(top_builddir)/lib/libgfshare.la
	
