## src-specific makefile

lib_LTLIBRARIES = libshamir.la
libshamir_la_sources = libshamir.c libshamir.h

bin_PROGRAMS = polypasshash
polypasshash_SOURCES = polypasshash.c 
polypasshash_LDADD = libshamir.la
