# Special names here like %{__make} come from /usr/lib/rpm/macros

%define version 0.6
%define name libsecrm

Summary:	Library for secure removing files.
Name:		%{name}
Version:	%{version}
Release:	1
URL:		http://rudy.mif.pg.gda.pl/~bogdro/soft/
License:	GPL
Group:		System Utilities
Packager:	Bogdan Drozdowski <bogdandr@op.pl>
Prefix:		/usr/local
Source:		%{name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-build
BuildRequires:	gcc, glibc, glibc-devel, glibc-headers, make

%description

The libsecrm is a library which intercepts system calls that may lead to
insecure file deletion. The insecure removal functions are replaced by
secure ones (the same as in the shred utility).

%prep
%{__rm} -rf $RPM_BUILD_ROOT
%setup -q

%build

./configure --prefix=/usr/local --disable-static --mandir=/usr/share/man \
	--infodir=/usr/share/info --libdir=/usr/local/lib
%{__make}
touch $RPM_BUILD_ROOT/etc/libsecrm.progban
touch $RPM_BUILD_ROOT/etc/libsecrm.fileban

%install

DESTDIR="$RPM_BUILD_ROOT" %{__make} install
#%{__ln_s} $RPM_BUILD_ROOT/%{prefix}/lib/libsecrm.so.1.0.2 $RPM_BUILD_ROOT/%{prefix}/lib/libsecrm.so.1
#%{__ln_s} $RPM_BUILD_ROOT/%{prefix}/lib/libsecrm.so.1.0.2 $RPM_BUILD_ROOT/%{prefix}/lib/libsecrm.so

%post
#echo %{prefix}/lib/libsecrm.so >> /etc/ld.so.preload
#touch /etc/libsecrm.progban
#touch /etc/libsecrm.fileban

%preun
#sed -i 's/^.*libsecrm.so//g' /etc/ld.so.preload

%clean

%{__rm} -rf $RPM_BUILD_ROOT

#%define _unpackaged_files_terminate_build 0
%files

%defattr(-,root,root)
%{prefix}/lib/libsecrm.so
%{prefix}/lib/libsecrm.so.1
%{prefix}/lib/libsecrm.so.1.0.2
%{prefix}/lib/libsecrm.la
%doc /usr/share/info/libsecrm.info.gz
%doc /usr/share/man/man3/libsecrm.3.gz
%ghost %config %{prefix}/etc/libsecrm.progban
%ghost %config %{prefix}/etc/libsecrm.fileban

