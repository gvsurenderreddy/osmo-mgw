AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_builddir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMONETIF_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMONETIF_LIBS) \
	$(COVERAGE_LDFLAGS) \
	$(NULL)

# This is _NOT_ the library release version, it's an API version.
# Please read Chapter 6 "Library interface versions" of the libtool
# documentation before making any modification
MGCP_LIBVERSION=0:0:0

lib_LTLIBRARIES = \
	libosmo-mgcp.la \
	$(NULL)

noinst_HEADERS = \
	g711common.h \
	$(NULL)

libosmo_mgcp_la_SOURCES = \
	mgcp_protocol.c \
	mgcp_network.c \
	mgcp_vty.c \
	mgcp_osmux.c \
	mgcp_sdp.c \
	mgcp_msg.c \
	mgcp_conn.c \
	mgcp_stat.c \
	$(NULL)

libosmo_gcp_la_LDFLAGS = $(AM_LDFLAGS) -version-info $(LEGACY_MGCP_LIBVERSION)
