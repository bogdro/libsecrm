SUBDIRS = src doc test

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = libsecrm.spec.in doc/libsecrm.3 m4/ax_c_check_flag.m4 m4/ac_define_path_style.m4 \
	m4/ax_gcc_warn_unused_result.m4 m4/ac_prototype.m4 m4/ax_check_link_flag.m4 THANKS

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libsecrm.pc

pack:	doc/libsecrm.info
	make dist-gzip
	mkdir -p libsecrm-@VERSION@/doc
	echo '\input texinfo'			 > libsecrm-@VERSION@/doc/libsecrm.texi
	echo '@setfilename libsecrm.info'	>> libsecrm-@VERSION@/doc/libsecrm.texi
	echo '@settitle libsecrm manual'	>> libsecrm-@VERSION@/doc/libsecrm.texi
	echo '@bye'				>> libsecrm-@VERSION@/doc/libsecrm.texi
	gunzip -f libsecrm-@VERSION@.tar.gz
	tar --delete -f libsecrm-@VERSION@.tar libsecrm-@VERSION@/doc/libsecrm.texi
	tar -rf libsecrm-@VERSION@.tar libsecrm-@VERSION@/doc/libsecrm.texi
	gzip -9 -f libsecrm-@VERSION@.tar
	rm -fr libsecrm-@VERSION@

