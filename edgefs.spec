Name:           edgefs
Version:        1.0.0
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
BuildRequires:	gcc

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
#make install DESTDIR=%{buildroot}
cp -p %{SOURCE1} passwd-s3fs


%files
%{_bindir}/s3fs
%{_mandir}/man1/s3fs.1*
%doc AUTHORS README.md ChangeLog COPYING passwd-s3fs


%changelog

* Fri Nov 10 2017 Dmitry Yusupov <dmitry.yusupov@nexenta.com> - 1.0.0-1
- Initial build of 1.0.0 from https://github.com/Nexenta/edge-fuse
