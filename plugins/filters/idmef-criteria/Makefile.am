AM_CPPFLAGS = -I$(top_srcdir)/src/include -I$(top_srcdir)/libmissing @LIBREQUIEM_CFLAGS@
AM_CFLAGS = @GLOBAL_CFLAGS@

idmef_criteria_la_SOURCES = idmef-criteria.c
idmef_criteria_la_LDFLAGS = -module -avoid-version
idmef_criteriadir = $(libdir)/requiem-manager/filters
idmef_criteria_LTLIBRARIES = idmef-criteria.la

-include $(top_srcdir)/git.mk
