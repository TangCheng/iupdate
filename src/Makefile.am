## Process this file with automake to produce Makefile.in

## Created by Anjuta

AM_CPPFLAGS = \
	-DPACKAGE_LOCALE_DIR=\""$(localedir)"\" \
	-DPACKAGE_SRC_DIR=\""$(srcdir)"\" \
	-DPACKAGE_DATA_DIR=\""$(pkgdatadir)"\"

AM_CFLAGS =\
	 -Wall\
	 -g

bin_PROGRAMS = \
	fw_encode \
	fw_decode

fw_encode_SOURCES =  \
	encode.c \
	fw_encode.c

fw_encode_CPPFLAGS = -I$(srcdir) -I$(srcdir)/icrypt 

fw_encode_LDFLAGS = 

fw_encode_LDADD = ${builddir}/icrypt/libicrypt.a 

fw_decode_SOURCES =  \
	decode.c \
	fw_decode.c

fw_decode_CPPFLAGS = -I$(srcdir) -I$(srcdir)/icrypt 

fw_decode_LDFLAGS = 

fw_decode_LDADD = ${builddir}/icrypt/libicrypt.a

SUBDIRS = \
	icrypt

noinst_HEADERS = firmware_pack.h
