dnl
dnl ReadBMP Copyright (C) 2013 Jean-Daniel Pauget
dnl A whole set of http tcp sessions
dnl
dnl readbmp@nekodune.com  -  http://readbmp.nekodune.com/


dnl This file is part of ReadBMP
dnl 
dnl ReadBMP is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 2 of the License, or
dnl (at your option) any later version.
dnl 
dnl ReadBMP is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl 
dnl You should have received a copy of the GNU General Public License
dnl along with ReadBMP; if not, write to the Free Software
dnl Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
dnl 
dnl you can also try the web at http://www.gnu.org/
dnl 
dnl
dnl readbmp@nekodune.com  -  http://readbmp.nekodune.com/

dnl Process this file with autoconf to produce a configure script.
AC_INIT([readbmp], [0.0.1], [readbmp@nekodune.com])
AC_CONFIG_SRCDIR([./readbmp.cpp])


dnl Detect the canonical host and target build environment
AC_CANONICAL_HOST
AC_CANONICAL_TARGET


dnl quieten some complains from missing files
AM_INIT_AUTOMAKE([foreign])

dnl the magic of additionnal local m4 ?
AC_CONFIG_MACRO_DIR([m4])

dnl autoheader
AM_CONFIG_HEADER(config.h)

dnl Check for tools

AC_PROG_CC
AC_PROG_CXX
AC_LIBTOOL_WIN32_DLL
AM_PROG_LIBTOOL

dnl Check for compiler environment

AC_C_CONST

dnl JD's standard minimum CFLAG
dnl CHANGED for JD's ENterGroup default nasty warnings
CFLAGS="$CFLAGS -O2 -Wall -Wcast-qual -Wwrite-strings -Wstrict-prototypes -Wmissing-prototypes"
dnl CXXFLAGS="$CXXFLAGS -O2 -Wall -Woverloaded-virtual -Wcast-qual -Wwrite-strings -Wstrict-prototypes -Wmissing-prototypes -Wredundant-decls -Winline"
CXXFLAGS="$CXXFLAGS -O2 -Wall -Woverloaded-virtual -Wcast-qual -Wwrite-strings -Wredundant-decls"

dnl check for qiconn sources
AC_MSG_CHECKING(for qiconn sources)
if test -f qiconn/qiconn/qiconn.h ; then
    INCPATH="$INCPATH -Iqiconn"
    QICONNSOURCE=qiconn
    AC_MSG_RESULT(found)
else
    AC_MSG_ERROR(Unable to find qiconn sources)
fi
AC_SUBST(QICONNSOURCE)


dnl badly look for readbmp includes ...
AC_MSG_CHECKING(for readbmp headers)
if test -f include/readbmp/readbmp.h ; then
    INCPATH="$INCPATH -Iinclude"
    AC_MSG_RESULT(found)
else
    AC_MSG_ERROR(Unable to find readbmp headers)
fi

dnl check for mac-osX file scheme
case "$target" in
    *-apple-darwin*)
	AC_DEFINE(OSXFILESCHEME, 1, a macosX file scheme flavour is used)
	;;
    *)
	AC_DEFINE(OSXFILESCHEME, 0, a regular unix file scheme flavour is used)
	;;
esac


dnl concatenation of include dirs
CFLAGS="$CFLAGS $INCPATH -DREADBMPVERSION=\"\\\"$PACKAGE_VERSION\\\"\""
CXXFLAGS="$CXXFLAGS $INCPATH -DREADBMPVERSION=\"\\\"$PACKAGE_VERSION\\\"\""

dnl Finally create all the generated files
AC_OUTPUT([
	Makefile
])


