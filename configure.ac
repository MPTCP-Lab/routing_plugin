AC_PREREQ([2.69])
AC_INIT([routing_plugin], [0.1])

AX_IS_RELEASE([git-directory])
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
ELL_VERSION=0.27  dnl Minimum required version of ELL.

# Find mptcpd and ELL
#PKG_CHECK_MODULES([MPTCPD], [mptcpd])
PKG_CHECK_MODULES([ELL],
                  [ell >= $ELL_VERSION])

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
# Enable compile-time defense
# ---------------------------------------------------------------

AC_ARG_ENABLE(stack-protection,
	[AS_HELP_STRING([--disable-stack-protection],
		[Disable compiler stack protection.
		FORTIFY_SOURCE=2 and -fstack-protector-strong]
	)],
	[],
	[enable_stack_protection=yes])

AS_IF([test "x$enable_stack_protection" = "xyes"],
	[
	# Fortify source
	# Enabling optimization implies _FORTIFY_SOURCE on some platforms.
	# Explicitly redefine to _FORTIFY_SOURCE=2 to make sure we have the
	# desired fortification level.
	AX_APPEND_FLAG([-U_FORTIFY_SOURCE], [CPPFLAGS])
	AX_APPEND_FLAG([-D_FORTIFY_SOURCE=2], [CPPFLAGS])

	# Stack-based buffer overrun detection
	MPTCPD_ADD_COMPILE_FLAG([-fstack-protector-strong],
	                        [# GCC < 4.9
	                         MPTCPD_ADD_COMPILE_FLAG([-fstack-protector])
	                        ])
	],[]
	)

# Format string vulnerabilities
# -Wformat=2 implies:
#    -Wformat -Wformat-nonliteral -Wformat-security -Wformat-y2k
AX_APPEND_COMPILE_FLAGS([-Wformat=2])

# Position Independent Execution (PIE)
AX_APPEND_COMPILE_FLAGS([-fPIE], [EXECUTABLE_CFLAGS])
AC_SUBST([EXECUTABLE_CFLAGS])


# ---------------------------------------------------------------
# Enable link-time defenses
# ---------------------------------------------------------------
# Stack execution protection
AX_APPEND_LINK_FLAGS([-Wl,-z,noexecstack])

# Data relocation and protection (RELRO)
AX_APPEND_LINK_FLAGS([-Wl,-z,now -Wl,-z,relro])

# Position Independent Execution
AX_APPEND_LINK_FLAGS([-pie], [EXECUTABLE_LDFLAGS])
AC_SUBST([EXECUTABLE_LDFLAGS])

# ---------------------------------------------------------------
# Generate our build files.
# ---------------------------------------------------------------
AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
