# Process this file with autoconf to produce a configure script.

AC_INIT([libcdp], [0.07], [libcdp@very.puzzling.org])
AC_CONFIG_SRCDIR([src/cdp.c])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE(${PACKAGE_NAME}, ${PACKAGE_VERSION})

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_RANLIB

# Checks for libraries.
MAC_LIB_PCAP
case "$HAVE_LIB_PCAP" in
no)
	AC_MSG_FAILURE([[libpcap could not be found]])
	;;
"")
	AC_MSG_ERROR([[libpcap is required by this module]])
	;;
esac

MAC_LIB_NET
case "$HAVE_LIB_NET" in
no)
	AC_MSG_FAILURE([[libnet (version 1.1.0 or later) could not be found]])
	;;
"")
	AC_MSG_ERROR([[libnet (version 1.1.0 or later) is required by this module]])
	;;
esac

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h locale.h stdlib.h sys/ioctl.h sys/socket.h sys/time.h sys/utsname.h], , , [-])

# This requires some of these header files

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

# Checks for library functions.
AC_PROG_GCC_TRADITIONAL
AC_CHECK_FUNCS([gethostname memset socket strchr strdup strerror uname])
MAC_SYS_MULTICAST

AC_CONFIG_FILES([Makefile src/Makefile config.pl])
AC_OUTPUT
