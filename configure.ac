#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(kcptun-raw, 0.1.0, tech@chionlab.moe)
AC_CONFIG_SRCDIR([src/client.c])
AC_CONFIG_HEADERS(src/config.h)
AM_INIT_AUTOMAKE([subdir-objects])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O 

# Checks for libraries.
AC_CHECK_LIB([ev], [ev_loop_destroy], [], [AC_MSG_ERROR([Couldn't find libev.])])
AC_CHECK_LIB([crypto], [AES_cfb128_encrypt], [], [AC_MSG_ERROR([Couldn't find libcrypto.])])

AC_PROG_RANLIB

# Checks for header files.
AC_CHECK_HEADERS([ev.h libev/ev.h])
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([bzero gettimeofday inet_ntoa memmove memset socket])

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
