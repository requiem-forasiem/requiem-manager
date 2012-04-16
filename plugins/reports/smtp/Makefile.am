AM_CPPFLAGS = -I$(top_srcdir)/src/include -I$(top_srcdir)/libmissing @LIBREQUIEM_CFLAGS@ @LIBREQUIEMDB_CFLAGS@
AM_CFLAGS = @GLOBAL_CFLAGS@

smtp_la_SOURCES = smtp.c
smtp_la_LDFLAGS = -module -avoid-version
smtp_la_LIBADD = @LIBREQUIEMDB_LIBS@
smtpdir = $(libdir)/requiem-manager/reports
smtp_LTLIBRARIES = smtp.la

smtptemplate_DATA = template.example
smtptemplatedir   = $(docdir)/smtp

EXTRA_DIST = $(smtptemplate_DATA)


-include $(top_srcdir)/git.mk
