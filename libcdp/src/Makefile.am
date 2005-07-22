noinst_LIBRARIES = libcdp.a

libcdp_a_CPPFLAGS = $(LIBPCAP_CPPFLAGS) $(LIBNET_CPPFLAGS) -I$(top_srcdir)/lib
libcdp_a_SOURCES = \
	address.c \
	appliance.c \
	cdp.c cdp.h \
	checksum.c checksum.h \
	encoding.c encoding.h \
	ip_prefix.c \
	llist.c \
	packet.c \
	system.h

AUTOMAKE_OPTIONS = $(top_builddir)/lib/ansi2knr
