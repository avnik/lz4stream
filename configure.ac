dnl Process this file with autoconf to produce a configure script

AC_INIT([lz4stream], [0.1])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AS_BOX([Configuring AC_PACKAGE_TARNAME AC_PACKAGE_VERSION])
echo

AM_INIT_AUTOMAKE([-Wall foreign])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl Check for programs
AC_PROG_CC([gcc clang cc])
AC_PROG_CC_C99
AC_USE_SYSTEM_EXTENSIONS
LT_PREREQ([2.2.6])
LT_INIT([disable-static])

dnl Check for header files
AC_HEADER_STDC
AC_CHECK_HEADERS([lz4.h])

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
