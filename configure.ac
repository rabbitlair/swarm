#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([swarm], [0.1.1], [ezequielvazq@gmail.com])
AM_INIT_AUTOMAKE()
AC_CONFIG_SRCDIR([src/swarm.cpp])
AM_CONFIG_HEADER(config.h)
AM_SILENT_RULES([yes])

# Checks for programs.
AC_PROG_CXX

# Checks for libraries.
AC_CHECK_LIB([mysqlclient], [mysql_init], [],
    echo "ERROR: libmysqlclient not found" && exit 1)
AC_CHECK_LIB([net], [libnet_init], [],
    echo "ERROR: libnet not found" && exit 1)
AC_CHECK_LIB([pcap], [pcap_open_live], [],
    echo "ERROR: libpcap not found" && exit 1)
AC_CHECK_LIB([config++], [config_init], [],
    echo "ERROR: libconfig not found" && exit 1)

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h stdlib.h netinet/ether.h netinet/ip.h netinet/ip_icmp.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_CHECK_FUNCS([inet_ntoa memset])

AC_CONFIG_FILES([makefile])
AC_OUTPUT
