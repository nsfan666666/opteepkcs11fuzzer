#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([TAs], [0.0.0], [https://github.com/Open-TEE/TAs/issues],
	[TAs], [https://github.com/Open-TEE])
AM_INIT_AUTOMAKE([dist-bzip2 foreign subdir-objects])
AC_CONFIG_SRCDIR([ta_conn_test_app/ta_conn_test_app.c])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC

# Don't build static libraries of TAs
AC_ENABLE_SHARED(yes)
AC_ENABLE_STATIC(no)
LT_INIT

# Created configuration files
AC_CONFIG_FILES([Makefile])

AC_OUTPUT
