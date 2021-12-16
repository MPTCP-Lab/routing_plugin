AM_CPPFLAGS = 				\
	-I$(top_srcdir)/include		\
	-I$(top_builddir)/include

plugindir = @MPTCPD_PLUGINDIR@

plugin_LTLIBRARIES = routing.la

routing_la_SOURCES  = routing.c
routing_la_LIBADD   = 			      \
	$(top_builddir)/lib/librouting_ops.la \
	$(MPTCPD_LIBS) 			      \
	-lmnl
routing_la_CFLAGS   = $(MPTCPD_CFLAGS)
routing_la_LDFLAGS  = -no-undefined -module -avoid-version	
