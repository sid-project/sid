#global commit 13a0dd86874b5d7558a0e131f3deaa42cd7d9d23
%{?commit:%global shortcommit %(c=%{commit}; echo ${c:0:7})}
%{?commit:%global commitdate 20200828}
%{?commit:%global scmsnap %{commitdate}git%{shortcommit}}

Name: sid
Version: 0.0.3
Release: 1%{?scmsnap:.%{scmsnap}}%{?dist}
Summary: Storage Instantiation Daemon (SID)

License: GPLv2+
URL: http://sid-project.github.io
%if %{defined commit}
Source0: https://github.com/sid-project/%{name}/archive/%{commit}/%{name}-%{shortcommit}.tar.gz
%else
Source0: https://github.com/sid-project/%{name}/archive/v%{version}/%{name}-%{version}.tar.gz
%endif

BuildRequires: autoconf
BuildRequires: automake
BuildRequires: libtool
BuildRequires: systemd-rpm-macros
BuildRequires: systemd-devel >= 221
BuildRequires: libudev-devel >= 174
BuildRequires: libuuid-devel
BuildRequires: libblkid-devel

Requires: %{name}-base-libs%{?_isa} = %{version}-%{release}
Requires: %{name}-log-libs%{?_isa} = %{version}-%{release}
Requires: %{name}-resource-libs%{?_isa} = %{version}-%{release}

%description
Storage Instantiation Daemon (SID) aims to help with Linux storage
device state tracking that encompasses device layers, groups and whole
stacks by monitoring progression of events. Based on monitored states
and further recorded information, it is able to trigger associated
actions for well-defined triggers, including activation and deactivation
of devices and their layers in the stack.

%prep
%if %{defined commit}
%autosetup -p1 -n sid-%{commit}
%else
%autosetup -p1 -n sid-%{version}
%endif

%build
./autogen.sh
%configure --disable-mod-multipath_component
%make_build

%install
make DESTDIR=%{buildroot} install
rm -f $RPM_BUILD_ROOT%{_libdir}/sid/*.{a,la}
rm -f $RPM_BUILD_ROOT%{_libdir}/sid/modules/ubridge-cmd/block/*.{a,la}
rm -f $RPM_BUILD_ROOT%{_libdir}/sid/modules/ubridge-cmd/type/*.{a,la}

%files
%{_sbindir}/sid
%{_sysconfdir}/sysconfig/sid.sysconfig
%{_udevrulesdir}/00-sid.rules
%{_unitdir}/sid.socket
%{_unitdir}/sid.service

%license COPYING

%post
%systemd_post sid.socket sid.service

%preun
%systemd_preun sid.service sid.socket

%package base-libs
Summary: Libraries for Storage Instantiation Daemon (SID) base
License: GPLv2+
%description base-libs
%files base-libs
%{_libdir}/sid/libsidbase.so.*

%package base-libs-devel
Summary: Development libraries and headers for Storage Instantiation Daemon (SID) base
License: GPLv2+
Requires: %{name}-base-libs%{?_isa} = %{version}-%{release}
%description base-libs-devel
%files base-libs-devel
%{_libdir}/sid/libsidbase.so
%{_includedir}/sid/base/bitmap.h
%{_includedir}/sid/base/buffer-common.h
%{_includedir}/sid/base/buffer.h
%{_includedir}/sid/base/comms.h
%{_includedir}/sid/base/list.h
%{_includedir}/sid/base/mem.h
%{_includedir}/sid/base/types.h
%{_includedir}/sid/base/util.h

%package log-libs
Summary: Libraries for Storage Instantiation Daemon (SID) logging
License: GPLv2+
%description log-libs
%files log-libs
%{_libdir}/sid/libsidlog.so.*

%package log-libs-devel
Summary: Development libraries and headers for Storage Instantiation Daemon (SID) logging
License: GPLv2+
Requires: %{name}-log-libs%{?_isa} = %{version}-%{release}
%description log-libs-devel
%files log-libs-devel
%{_libdir}/sid/libsidlog.so
%{_includedir}/sid/log/log.h

%package iface-libs
Summary: Libraries for Storage Instantiation Daemon (SID) interfaces
License: GPLv2+
Requires: %{name}-base-libs%{?_isa} = %{version}-%{release}
Requires: systemd-libs
%description iface-libs
%files iface-libs
%{_libdir}/sid/libsidiface_servicelink.so.*
%{_libdir}/sid/libsidiface_usid.so.*

%package iface-libs-devel
Summary: Development libraries and headers for Storage Instantiation Daemon (SID) interfaces
License: GPLv2+
Requires: %{name}-iface-libs%{?_isa} = %{version}-%{release}
%description iface-libs-devel
%files iface-libs-devel
%{_libdir}/sid/libsidiface_servicelink.so
%{_libdir}/sid/libsidiface_usid.so
%{_includedir}/sid/iface/service-link.h
%{_includedir}/sid/iface/usid.h

%package resource-libs
Summary: Libraries for Storage Instantiation Daemon (SID) resources
License: GPLv2+
Requires: %{name}-base-libs%{?_isa} = %{version}-%{release}
Requires: %{name}-log-libs%{?_isa} = %{version}-%{release}
Requires: %{name}-iface-libs%{?_isa} = %{version}-%{release}
# Systemd supports event loop since v221
Requires: systemd-libs >= 221
%description resource-libs
%files resource-libs
%{_libdir}/sid/libsidresource.so.*

%package resource-libs-devel
Summary: Development libraries and headers for Storage Instantiation Daemon (SID) resources
License: GPLv2+
Requires: %{name}-resource-libs%{?_isa} = %{version}-%{release}
%description resource-libs-devel
%files resource-libs-devel
%{_libdir}/sid/libsidresource.so
%{_includedir}/sid/resource/kv-store.h
%{_includedir}/sid/resource/module-registry.h
%{_includedir}/sid/resource/module.h
%{_includedir}/sid/resource/resource-type-regs.h
%{_includedir}/sid/resource/resource.h
%{_includedir}/sid/resource/ubridge-cmd-module.h
%{_includedir}/sid/resource/worker-control.h

%package mod-block-blkid
Summary: blkid block module for Storage Instantiation Daemon (SID)
Requires: %{name}-log-libs%{?_isa} = %{version}-%{release}
Requires: %{name}-resource-libs%{?_isa} = %{version}-%{release}
%description mod-block-blkid
%files mod-block-blkid
%{_libdir}/sid/modules/ubridge-cmd/block/blkid.so
%{_libdir}/sid/modules/ubridge-cmd/block/dummy_block.so

%package mod-block-multipath-component
Summary: multipath component block module for Storage Instantiation Daemon (SID)
Requires: %{name}-log-libs%{?_isa} = %{version}-%{release}
Requires: %{name}-resource-libs%{?_isa} = %{version}-%{release}
Requires: device-mapper-multipath-libs
%description mod-block-multipath-component
%files mod-block-multipath-component
%{_libdir}/sid/modules/ubridge-cmd/type/device_mapper.so
%{_libdir}/sid/modules/ubridge-cmd/type/dummy_type.so
%{_libdir}/sid/modules/ubridge-cmd/type/md.so
%{_libdir}/sid/modules/ubridge-cmd/type/sd.so

%package tools
Summary: Storage Instantiation Daemon (SID) supporting tools
Requires: %{name}-base-libs%{?_isa} = %{version}-%{release}
Requires: %{name}-log-libs%{?_isa} = %{version}-%{release}
Requires: %{name}-iface-libs%{?_isa} = %{version}-%{release}
%description tools
%files tools
%{_sbindir}/usid

%changelog
#* Fri Aug 28 2020 Peter Rajnoha <prajnoha@redhat.com> - 0.0.3-1
