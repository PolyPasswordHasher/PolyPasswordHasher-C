AM_CFLAGS = -I$(top_builddir)/include 
AM_LDFLAGS = -lcrypto

TESTS = check_libgfshare check_libpolypasswordhasher check_libpph_shielded\
				check_libpph_isolated_validation check_libpph_phc

check_PROGRAMS = check_libgfshare check_libpolypasswordhasher\
								 check_libpph_shielded check_libpph_isolated_validation\
								 check_libpph_phc

check_libgfshare_SOURCES = check_libgfshare.c\
													$(top_builddir)/include/libgfshare.h\
												$(top_builddir)/include/libgfshare_tables.h
check_libgfshare_CFLAGS = @CHECK_CFLAGS@ -I../include
check_libgfshare_LDADD = $(top_builddir)/lib/libgfshare.la @CHECK_LIBS@

check_libpolypasswordhasher_SOURCES = check_libpolypasswordhasher.c\
																$(top_builddir)/include/libgfshare.h\
																$(top_builddir)/include/libpolypasswordhasher.h
check_libpolypasswordhasher_CFLAGS = @CHECK_CFLAGS@ -I$(top_builddir)/include
check_libpolypasswordhasher_LDADD = $(top_builddir)/lib/libgfshare.la\
															$(top_builddir)/src/libpolypasswordhasher.la\
															@CHECK_LIBS@

check_libpph_shielded_SOURCES = check_libpph_shielded.c\
																$(top_builddir)/include/libgfshare.h\
																$(top_builddir)/include/libpolypasswordhasher.h

check_libpph_shielded_CFLAGS= @CHECK_CFLAGS@ -I$(top_builddir)/include
check_libpph_shielded_LDADD = $(top_builddir)/lib/libgfshare.la\
																	 $(top_builddir)/src/libpolypasswordhasher.la\
																	 @CHECK_LIBS@

check_libpph_isolated_validation_SOURCES= check_libpph_isolated_validation.c\
																$(top_builddir)/include/libgfshare.h\
																$(top_builddir)/include/libpolypasswordhasher.h

check_libpph_isolated_validation_CFLAGS= @CHECK_CFLAGS@ -I$(top_builddir)/include
check_libpph_isolated_validation_LDADD = $(top_builddir)/lib/libgfshare.la\
																	 $(top_builddir)/src/libpolypasswordhasher.la\
																	 @CHECK_LIBS@

check_libpph_phc_SOURCES= check_libpph_phc.c\
													$(top_builddir)/include/libgfshare.h\
												  $(top_builddir)/include/libpolypasswordhasher.h

check_libpph_phc_CFLAGS= @CHECK_CFLAGS@ -I$(top_builddir)/include
check_libpph_phc_LDADD = $(top_builddir)/lib/libgfshare.la\
												 $(top_builddir)/src/libpolypasswordhasher.la\
												 @CHECK_LIBS@
