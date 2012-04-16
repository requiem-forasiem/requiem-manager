AM_CPPFLAGS = -I$(top_srcdir)/src/include -I$(top_srcdir)/libmissing @LIBREQUIEM_CFLAGS@ @LIBREQUIEMDB_CFLAGS@
AM_CFLAGS = @GLOBAL_CFLAGS@ 

db_la_LDFLAGS = -module -avoid-version

if HAVE_LIBREQUIEMDB

db_la_SOURCES = db.c
db_la_LIBADD = @LIBREQUIEMDB_LIBS@
dbdir = $(libdir)/requiem-manager/reports
db_LTLIBRARIES = db.la

endif

-include $(top_srcdir)/git.mk
