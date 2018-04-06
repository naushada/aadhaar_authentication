#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([Uidai], [2.0], [naushad.dln@gmail.com])

AM_INIT_AUTOMAKE

AC_CHECK_LIB([crypto],[RSA_public_encrypt],[],[echo "crypto library is required for this program" exit -1])
AC_CHECK_LIB([ssl],[SSL_CTX_new],[],[echo "ssl library is required for this program" exit -1])
AC_CHECK_LIB([pthread],[pthread_create],[],[echo "pthread library is required for this program" exit -1])

AC_PROG_CC
AC_LANG([C]) 

# Checks for programs.

# Checks for libraries.
AC_LIBTOOL_DLOPEN

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_DIRENT

AC_SUBST([AM_CPPFLAGS])
AC_SUBST([AM_CFLAGS])
AC_SUBST([AM_LDFLAGS])
AC_SUBST([AM_LFLAGS])

#AC_CONFIG_HEADERS([src/config.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_CONFIG_FILES([Makefile src/Makefile])
AM_INIT_AUTOMAKE([subdir-objects])
AC_OUTPUT
