AM_CPPFLAGS = -I$(top_srcdir)/src/include -I$(top_srcdir)/libmissing @LIBREQUIEM_CFLAGS@
AM_CFLAGS = @GLOBAL_CFLAGS@

skeleton_la_SOURCES = skeleton.c
skeleton_la_LDFLAGS = -module -avoid-version
skeletondir = $(libdir)/requiem-manager/filters
skeleton_LTLIBRARIES = skeleton.la

-include $(top_srcdir)/git.mk
