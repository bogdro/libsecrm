# Special names here like %{__make} come from /usr/lib/rpm/macros

%define version 0.1
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

./configure --prefix=/usr/local --disable-shared
	#--mandir=$RPM_BUILD_ROOT/usr/local/man
#prefix=$RPM_BUILD_ROOT/usr/local
%{__make}

%install

#prefix=$RPM_BUILD_ROOT/usr/local
%{__make} DESTDIR="$RPM_BUILD_ROOT" install
#%{__mv} -f $RPM_BUILD_ROOT/usr/bin/wipefreespace $RPM_BUILD_ROOT/usr/local/bin/wipefreespace
#%{makeinstall}

%clean

%{__rm} -rf $RPM_BUILD_ROOT

#%define _unpackaged_files_terminate_build 0
%files

%defattr(-,root,root)
/usr/local/lib/libsecrm.so.0.0.0
/usr/local/lib/libsecrm.la
%doc /usr/share/info/libsecrm.info.gz
%doc /usr/share/man/man3/libsecrm.3.gz
%ghost /usr/local/lib/libsecrm.so  /usr/local/lib/libsecrm.so.0

