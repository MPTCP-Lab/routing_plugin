AC_PREREQ([2.69])
AC_INIT([routing_plugin], [0.1])

AX_CHECK_ENABLE_DEBUG([yes])

AM_INIT_AUTOMAKE([1.15 -Wall -Werror -Wno-portability silent-rules std-options check-news foreign])
AM_SILENT_RULES([yes])
LT_INIT([disable-static])

AC_CONFIG_SRCDIR([src/routing.c])
AC_CONFIG_MACRO_DIRS([m4])

# ---------------------------------------------------------------
# Checks for programs.
# ---------------------------------------------------------------
AC_PROG_CC_STDC
AM_PROG_CC_C_O

# Check for Doxygen
DX_DOXYGEN_FEATURE(ON)
DX_DOT_FEATURE(ON)
DX_HTML_FEATURE(ON)
DX_CHM_FEATURE(OFF)
DX_CHI_FEATURE(OFF)
DX_MAN_FEATURE(OFF)
DX_RTF_FEATURE(OFF)
DX_XML_FEATURE(OFF)
DX_PDF_FEATURE(OFF)
DX_PS_FEATURE(OFF)
DX_INIT_DOXYGEN([routing], [Doxyfile], [doc])

# Check for pandoc
AC_ARG_VAR([PANDOC],[location of pandoc program])
AC_PATH_PROG([PANDOC], [pandoc])

PKG_PROG_PKG_CONFIG

# ---------------------------------------------------------------
# Checks for libraries.
# ---------------------------------------------------------------
ELL_VERSION=0.30  dnl Minimum required version of ELL.

# Find mptcpd and ELL
PKG_CHECK_MODULES([MPTCPD], [mptcpd])
PKG_CHECK_MODULES([ELL],
                  [ell >= $ELL_VERSION])
PKG_CHECK_MODULES([LIBMNL], [libmnl])

PKG_CHECK_VAR([MPTCPD_PLUGINDIR], [mptcpd], [plugindir])

AC_SUBST([ELL_VERSION])

# ---------------------------------------------------------------
# Enable additional C compiler warnings.  We do this after all
# Autoconf tests have been run since not all autoconf macros are
# warning free.
# ---------------------------------------------------------------
AX_CFLAGS_WARN_ALL([CFLAGS])
AX_APPEND_COMPILE_FLAGS([-Wextra -Werror -pedantic])

# ---------------------------------------------------------------
# Generate our build files.
# ---------------------------------------------------------------
AC_CONFIG_FILES([Makefile
                 include/Makefile
                 include/routing/Makefile
                 lib/Makefile
                 src/Makefile])
AC_OUTPUT
