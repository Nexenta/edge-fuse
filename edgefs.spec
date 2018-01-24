Name:           edgefs
Version:        1.1.0
Release:        1%{?dist}
Summary:        FUSE-based file system backed by NexentaEdge Extended S3 API
Group:          System Environment/Base

License:        GPLv2
URL:            https://github.com/Nexenta/edge-fuse
Source0:        https://github.com/Nexenta/edge-fuse/archive/%{name}-%{version}.tar.gz

Requires:	fuse >= 2.8.4
Requires:       fuse-libs >= 2.8.4
Requires:	gnutls >= 3.3

BuildRequires:  fuse-devel, gnutls-devel
BuildRequires:	gcc, asciidoc

%description
edgefs is a FUSE based filesystem for mounting http or https URLS as files in
the filesystem. There is no notion of listable directories in Edge API so only
a single URL can be mounted.

%global debug_package %{nil}


%prep
%setup -q


%build
make %{?_smp_mflags} all


%install
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_mandir}/man1
cp edgefs %{buildroot}%{_bindir}/
cp cachemap/libcachemap.so %{buildroot}%{_libdir}/libcachemap.so
cp edgefs.1 %{buildroot}%{_mandir}/man1/


%files
%{_bindir}/edgefs
%{_libdir}/libcachemap.so
%{_mandir}/man1/edgefs.1*
%doc README.md


%changelog
* Wed Jan 24 2018 Dmitry Yusupov <dmitry.yusupov@nexenta.com> - 1.1.0-1
- Support for L2 extended cache on SSD/NVMe

* Fri Nov 10 2017 Dmitry Yusupov <dmitry.yusupov@nexenta.com> - 1.0.1-1
- Initial build of 1.0.1 from https://github.com/Nexenta/edge-fuse
