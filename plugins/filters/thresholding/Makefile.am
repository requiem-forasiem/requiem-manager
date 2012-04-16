AM_CPPFLAGS = -I$(top_srcdir)/src/include -I$(top_srcdir)/libmissing @LIBREQUIEM_CFLAGS@
AM_CFLAGS = @GLOBAL_CFLAGS@

thresholding_la_SOURCES = thresholding.c
thresholding_la_LDFLAGS = -module -avoid-version
thresholdingdir = $(libdir)/requiem-manager/filters
thresholding_LTLIBRARIES = thresholding.la

-include $(top_srcdir)/git.mk
