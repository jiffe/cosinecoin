#AC_INIT(src)

#AC_CONFIG_FILES([Makefile], [src/Makefile])
AM_CONFIG_HEADER(config.h:config.in)
AC_CONFIG_AUX_DIR(.)

AC_INIT(focalcoind, 1.0.3)
AM_INIT_AUTOMAKE

AM_PROG_AS
AC_PROG_CXX
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_HEADER_STDC
AC_HEADER_SYS_WAIT

AC_CHECK_HEADERS(sys/types.h stdio.h stddef.h sys/wait.h)
AC_CHECK_HEADERS(fcntl.h)
AC_CHECK_HEADERS(strings.h)
AC_CHECK_HEADERS(sys/sockio.h)
AC_CHECK_HEADERS(sys/termios.h)
AC_CHECK_HEADERS(term.h)
AC_CHECK_HEADERS(sys/int_types.h)
AC_CHECK_HEADERS(sys/file.h)
AC_CHECK_HEADERS(sys/ioctl.h)
AC_CHECK_HEADERS(unistd.h)
AC_CHECK_HEADERS(sys/epoll.h)
AC_CHECK_HEADERS(sys/event.h)
AC_CHECK_HEADERS(sys/time.h)
AC_CHECK_HEADERS(time.h)

AC_OUTPUT([Makefile])
AC_OUTPUT([src/Makefile])