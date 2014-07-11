## src-specific makefile
AM_LDFLAGS = -lcrypto
AM_CFLAGS = -I$(top_builddir)/include

lib_LTLIBRARIES = libpolypasswordhasher.la
libpolypasswordhasher_la_SOURCES = libpolypasswordhasher.c\
								$(top_builddir)/include/libgfshare.h\
							    $(top_builddir)/include/libpolypasswordhasher.h
libpolypasswordhasher_la_LIBADD = $(top_builddir)/lib/libgfshare.la
	

bin_PROGRAMS = polypasswordhasher
polypasswordhasher_SOURCES = polypasswordhasher.c 
polypasswordhasher_CFLAGS = -I$(top_builddir)/include/
polypasswordhasher_LDADD = $(top_builddir)/src/libpolypasswordhasher.la
