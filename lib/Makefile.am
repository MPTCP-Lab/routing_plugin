AM_CPPFLAGS = -I$(top_srcdir)/include

noinst_LTLIBRARIES = librouting_ops.la

librouting_ops_la_SOURCES = \
	mnl_misc.c	    \
	mnl_ops.c	    \
	handler.c 	    
librouting_ops_la_LIBADD = \
	$(MPTCPD_LIBS)     \
	-lmnl
librouting_ops_la_LDFLAGS = -no-undefined -avoid-version
