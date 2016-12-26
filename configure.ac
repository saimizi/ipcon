AC_PREREQ([2.65])
AC_INIT([ipcon],0.0.1)
AM_INIT_AUTOMAKE([foreign])

LT_PREREQ([2.2])
LT_INIT

AC_CONFIG_MACRO_DIRS([m4])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES])

AM_SILENT_RULES([yes])
: ${CFLAGS=""}
: ${CXXFLAGS=""}

AC_PROG_CC
AC_PROG_CXX

PKG_CHECK_MODULES([LIBNL], [libnl-3.0])
PKG_CHECK_MODULES([LIBNL_GENL], [libnl-genl-3.0])
PKG_CHECK_MODULES([LIBNL_CLI], [libnl-cli-3.0])

AC_ARG_WITH([ksrc],
	AS_HELP_STRING([--with-ksrc],[Linux kernel path.]))

AS_IF([test "x$with_ksrc" != "x"],
	[ksrc=$with_ksrc],
	[ksrc="/lib/modules/`uname -r`/build"])

AC_SUBST(ksrc)
AC_CONFIG_FILES([Makefile
		 driver/Makefile
		 lib/Makefile
		 app/Makefile
		])
AC_OUTPUT

echo \
"-------------------------------------------------

${PACKAGE_NAME} Version ${PACKAGE_VERSION}

Prefix: '${prefix}'.
Compiler: '${CC} ${CFLAGS} ${CPPFLAGS}'

Package features:
	kernel src: ${ksrc}

-------------------------------------------------"
