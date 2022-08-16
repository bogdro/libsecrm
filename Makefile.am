SUBDIRS = src doc test

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = libsecrm.spec.in doc/libsecrm.3 m4/ax_c_check_flag.m4 m4/ac_define_path_style.m4 \
	m4/ax_gcc_warn_unused_result.m4 m4/ac_prototype.m4 m4/ax_check_link_flag.m4 THANKS

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libsecrm.pc

pack:	doc/libsecrm.info dist-gzip
	tar zxf libsecrm-@VERSION@.tar.gz
	echo '\input texinfo'			 > libsecrm-@VERSION@/doc/libsecrm.texi
	echo '@setfilename libsecrm.info'	>> libsecrm-@VERSION@/doc/libsecrm.texi
	echo '@settitle libsecrm manual'	>> libsecrm-@VERSION@/doc/libsecrm.texi
	echo '@bye'				>> libsecrm-@VERSION@/doc/libsecrm.texi
	tar zcf libsecrm-@VERSION@.tar.gz libsecrm-@VERSION@
	rm -fr libsecrm-@VERSION@

.PHONY: pack
