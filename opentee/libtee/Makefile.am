# Makefile.am -- Process this file with automake to produce Makefile.in

# Include libtool macros
ACLOCAL_AMFLAGS = -I m4

# Additional C compiler flags
AM_CFLAGS = -Wall -Wextra -DOT_LOGGING -O0 -g3 -ggdb3 # -Werror # to add while(1)

# Shared libraries
lib_LTLIBRARIES  =

# Public header files
include_HEADERS =

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libtee.pc

# Include module-specific Makefiles
include src/Makemodule.am
include include/Makemodule.am
