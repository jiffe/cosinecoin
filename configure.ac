#AC_INIT(src)

#AC_CONFIG_FILES([Makefile], [src/Makefile])
AM_CONFIG_HEADER(config.h:config.in)
m4_ifdef([AC_CONFIG_MACRO_DIR],[],[m4_define([AC_CONFIG_MACRO_DIR], [])])
AC_CONFIG_MACRO_DIR([src/m4])

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


AC_LANG_PUSH([C++])


BITCOIN_FIND_BDB48


AC_CHECK_LIB([crypto],[CRYPTO_new_ex_data], [], [AC_MSG_ERROR([OpenSSL libraries required])])
AC_CHECK_LIB([ssl],[SSL_library_init], [], [AC_MSG_ERROR([OpenSSL libraries required])])
AC_CHECK_HEADERS([openssl/crypto.h openssl/x509.h openssl/pem.h openssl/ssl.h openssl/err.h],[],[AC_MSG_ERROR([OpenSSL headers required])])


AX_BOOST_BASE
AX_BOOST_SYSTEM
AX_BOOST_FILESYSTEM
AX_BOOST_PROGRAM_OPTIONS
AX_BOOST_THREAD
AX_PTHREAD


COSINECOIN_FIND_JSON_SPIRIT
COSINECOIN_FIND_LEVELDB


AC_C_BIGENDIAN([AC_MSG_ERROR("Big Endian not supported")])


AC_OUTPUT([Makefile])
AC_OUTPUT([src/Makefile])