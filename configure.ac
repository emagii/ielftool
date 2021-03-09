AC_INIT([ielftool],
	[1.0],
	[Ulf Samuelsson],
	[ielftool-1.0],
	[http://www.emagii.com/])

AC_PREREQ([2.59])

AC_CONFIG_HEADER([src/include/config.h])

AC_CONFIG_SRCDIR([src])

AC_CONFIG_MACRO_DIR([m4])


AC_PROG_LN_S
AC_PROG_CPP
AC_PROG_CC
AC_PROG_CXX
AC_ARG_PROGRAM
AM_INIT_AUTOMAKE([1.10 -Wall no-define])

AC_PROG_MAKE_SET
AM_MAINTAINER_MODE
AC_HEADER_STDC
AC_PROG_LIBTOOL
AC_SUBST(ACLOCAL_AMFLAGS, "")
AC_HEADER_STDC
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME


AC_CHECK_HEADERS( \
	algorithm \
	deque \
	fstream \
	functional \
	iomanip \
	iostream \
	iterator \
	map \
	memory \
	ostream \
	set \
	sstream \
	stdexcept \
	string \
	utility \
	vector \
	assert.h \
	errno.h \
	fcntl.h \
	io.h \
	stddef.h \
	stdint.h \
	string.h \
	 \
	,
dnl to do if not found
	[],
dnl to do if not found
	[],
dnl default includes
	[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
dnl We do this default-include simply to make sure that the nameser_compat.h
dnl header *REALLY* can be include after the new nameser.h. It seems AIX 5.1
dnl (and others?) is not designed to allow this.
#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif

dnl *Sigh* these are needed in order for net/if.h to get properly detected.
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
]
)

# ==== Pthread Libraries
AC_ARG_WITH([pthread-include-path],
	[AS_HELP_STRING([--with-pthread-include-path],[location of the PThread headers, defaults to /usr/include])],
	[PTHREAD_CFLAGS="-I$withval"],
	[PTHREAD_CFLAGS="-I/usr/include"])
AC_SUBST([PTHREAD_CFLAGS])

AC_ARG_WITH([pthread-lib-path],
	[AS_HELP_STRING([--with-pthread-lib-path],[location of the PThread libraries, defaults to /usr/include])],
	[PTHREAD_LIBS="-L$withval -lpthread"],
	[PTHREAD_LIBS="-L/usr/include -lpthread"])
AC_SUBST([PTHREAD_LIBS])

AC_ARG_ENABLE(pthread,
	[--enable-pthread	Include PThreads],
	[case "${enableval}" in
		yes)	use_pthread=true  ;;
		no)	use_pthread=false ;;
		*) AC_MSG_ERROR(bad value ${enableval} for --enable-pthread) ;;
	 esac
	],
	[use_pthread=false])
AS_IF([test	x$use_pthread = xtrue], [AC_DEFINE([PTHREAD], [], [Description])])
AM_CONDITIONAL(USE_PTHREAD, test x$use_pthread = xtrue)

# ==== OS Support
AC_ARG_ENABLE(os-linux,
	[--enable-os-linux	Build for Linux enabled],
	[case "${enableval}" in
		yes)	os_linux=true  ;;
		no)	os_linux=false ;;
		*) AC_MSG_ERROR(bad value ${enableval} for --enable-os-linux) ;;
	 esac
	],
	[os_linux=false])
AS_IF([test	x$os_linux = xtrue], [AC_DEFINE([OS_LINUX], [], [Description])])
AM_CONDITIONAL(CONFIG_OS_LINUX, test x$os_linux = xtrue)

AC_SUBST([CFLAGS])

AC_SUBST([CPPFLAGS])

AC_SUBST([LIBS])

AC_SUBST([SLIBS])

AC_MSG_RESULT([$build_tests])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
