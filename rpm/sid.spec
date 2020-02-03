Name:           sid
Version:        0.0.2
Release:        mvp.1%{?dist}
Summary:        Minimum viable product for SID project

License:        GPLv2.0
URL:            http://sid-project.github.io
Source0:        https://github.com/sid-project/%{name}-mvp/archive/%{version}.tar.gz

BuildArch:      x86_64

BuildRequires:  systemd-devel >= 221
BuildRequires:  libuuid-devel
BuildRequires:  libblkid-devel
BuildRequires:  gcc
BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  libtool

Requires:  systemd-libs >= 221
Requires:  libblkid
Requires:  libuuid
Requires:  systemd-udev

%description
Storage Instantiation Daemon (SID) is a project that aims to help with Linux storage device
state tracking that encompasses device layers, groups and whole stacks by monitoring progression
of events. Based on monitored states and further recorded information, it is able to trigger
associated actions for well-defined triggers, including activation and deactivation of devices
and their layers in the stack.

%prep
%setup -q -c %{name}-%{version}
mv %{name}-mvp-%{version}/* .

%build
./autogen.sh
./configure --disable-mod-multipath_component CC=gcc
make

%install
make DESTDIR=%{buildroot} install
rm -rf %{buildroot}/usr/lib/.build-id/

%files
/usr/lib/udev/rules.d/00-sid.rules
/usr/lib/systemd/system/sid.*
/usr/local/bin/sid
/usr/local/bin/usid
/usr/local/etc/sysconfig/sid.sysconfig
/usr/local/include/sid/*
/usr/local/lib/sid/*

%license COPYING

%preun
%systemd_user_preun %{name}.service
%systemd_user_preun %{name}.socket

%changelog
