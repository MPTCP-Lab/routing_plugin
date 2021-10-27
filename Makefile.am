## "plugindir" specifies where plugins should be installed.
## Override as needed if the default mptcpd plugin directory
## is not used.
SUBDIRS = src

## Doxygen stuff
@DX_RULES@
MOSTLYCLEANFILES = $(DX_CLEANFILES)

EXTRA_DIST = README.md Doxyfile LICENSES

README: $(top_srcdir)/README.md
	@test -z "$(PANDOC)" || $(PANDOC) --from gfm --to plain --output=$@ $<

dist-hook: README

MAINTAINERCLEANFILES = README
