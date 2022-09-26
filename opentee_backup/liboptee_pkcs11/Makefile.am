# Makefile.am -- Process this file with automake to produce Makefile.in

# Include libtool macros
ACLOCAL_AMFLAGS = -I m4

# Additional C compiler flags
AM_CFLAGS = -Wall -Wextra -g3 # -Werror # -ggdb3 -O0

#AM_LDFLAGS = -fsanitize=address # -shared-libasan

# Shared libraries
lib_LTLIBRARIES  =

# Public header files
include_HEADERS =

# Include module-specific Makefiles
include src/Makemodule.am
include include/Makemodule.am
