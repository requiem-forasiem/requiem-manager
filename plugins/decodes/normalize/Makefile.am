AM_CPPFLAGS=-I$(top_srcdir)/src/include -I$(top_srcdir)/libmissing @LIBREQUIEM_CFLAGS@
AM_CFLAGS = @GLOBAL_CFLAGS@

normalize_la_SOURCES = normalize.c
normalize_la_LDFLAGS = -module -avoid-version
normalizedir = $(libdir)/requiem-manager/decodes
normalize_LTLIBRARIES = normalize.la

-include $(top_srcdir)/git.mk
