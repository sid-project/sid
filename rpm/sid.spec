#global commit 13a0dd86874b5d7558a0e131f3deaa42cd7d9d23
%{?commit:%global shortcommit %(c=%{commit}; echo ${c:0:7})}
%{?commit:%global commitdate 20200828}
%{?commit:%global scmsnap %{commitdate}git%{shortcommit}}

%global enable_dm_mpath_support 1

##############################################################################
# SID
##############################################################################

Name: sid
%if 0%{?rhel}
Epoch: %{rhel}
%endif
Version: 0.0.5
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
BuildRequires: gperf
BuildRequires: libtool
BuildRequires: multilib-rpm-config
BuildRequires: gcc
BuildRequires: systemd-rpm-macros
BuildRequires: systemd-devel >= 221
BuildRequires: libudev-devel >= 174
BuildRequires: libuuid-devel
BuildRequires: libblkid-devel
%if %{enable_dm_mpath_support}
BuildRequires: device-mapper-multipath-devel >= 0.8.4-7
%endif

Requires: systemd
Requires: systemd-udev
Requires: %{name}-internal-libs%{?_isa} = %{?epoch}:%{version}-%{release}
Requires: %{name}-log-libs%{?_isa} = %{?epoch}:%{version}-%{release}
Requires: %{name}-resource-libs%{?_isa} = %{?epoch}:%{version}-%{release}
Requires: %{name}-tools = %{?epoch}:%{version}-%{release}

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

%if ! %{enable_dm_mpath_support}
%global configure_dm_mpath --disable-mod-dm_mpath
%endif

%build
./autogen.sh
%configure %{?configure_dm_mpath}
%make_build

%install
make DESTDIR=%{buildroot} install
rm -f %{buildroot}/%{_libdir}/sid/*.{a,la}
rm -f %{buildroot}/%{_libdir}/sid/modules/ucmd/block/*.{a,la}
rm -f %{buildroot}/%{_libdir}/sid/modules/ucmd/type/*.{a,la}
%multilib_fix_c_header --file %{_includedir}/sid/config.h

%files
%license COPYING BSD_LICENSE
%{_sbindir}/sid
%config(noreplace) %{_sysconfdir}/sysconfig/sid.sysconfig
%{_udevrulesdir}/00-sid.rules
%{_unitdir}/sid.socket
%{_unitdir}/sid.service
%{_mandir}/man8/sid.8.gz
%doc README.md

%post
%systemd_post sid.socket sid.service

%preun
%systemd_preun sid.service sid.socket

%postun
%systemd_postun sid.service sid.socket

##############################################################################
# SID-BASE-LIBS
##############################################################################

%package base-libs
Summary: Libraries for Storage Instantiation Daemon (SID) base
License: GPLv2+
%description base-libs
This package contains shared libraries with low-level functionality needed for
Storage Instantiation Daemon (SID), its modules and related tools. Currently,
it contains basic support for buffering, IPC, base64 encoding and other helper
functions.

%files base-libs
%dir %{_libdir}/sid
%{_libdir}/sid/libsidbase.so.*
%doc README.md


##############################################################################
# SID-BASE-LIBS-DEVEL
##############################################################################

%package base-libs-devel
Summary: Development files for Storage Instantiation Daemon (SID) base
License: GPLv2+
Requires: %{name}-base-libs%{?_isa} = %{?epoch}:%{version}-%{release}
%description base-libs-devel
This package contains development files for Storage Instantiation Daemon (SID)
base libraries.

%files base-libs-devel
%dir %{_libdir}/sid
%{_libdir}/sid/libsidbase.so
%dir %{_includedir}/sid
%{_includedir}/sid/config*.h
%dir %{_includedir}/sid/base
%{_includedir}/sid/base/binary.h
%{_includedir}/sid/base/buffer-common.h
%{_includedir}/sid/base/buffer.h
%{_includedir}/sid/base/common.h
%{_includedir}/sid/base/comms.h
%{_includedir}/sid/base/util.h
%doc README.md

##############################################################################
# SID-INTERNAL-LIBS
##############################################################################

%package internal-libs
Summary: Development files for Storage Instantiation Daemon (SID) internal
License: GPLv2+
Requires: %{name}-base-libs%{?_isa} = %{?epoch}:%{version}-%{release}
%description internal-libs
This package contains shared libraries with low-level functionality needed for
Storage Instantiation Daemon (SID) and its modules. Currently, it contains
basic support for bitmaps, hashing, lists, memory handling and other helper
functions.

%files base-libs
%dir %{_libdir}/sid
%{_libdir}/sid/libsidinternal.so.*
%doc README.md

##############################################################################
# SID-LOG-LIBS
##############################################################################

%package log-libs
Summary: Libraries for Storage Instantiation Daemon (SID) logging
License: GPLv2+
%description log-libs
This package contains shared libraries with logging support needed for Storage
Instantiation daemon (SID), its modules and related tools.

%files log-libs
%dir %{_libdir}/sid
%{_libdir}/sid/libsidlog.so.*
%doc README.md


##############################################################################
# SID-LOG-LIBS-DEVEL
##############################################################################

%package log-libs-devel
Summary: Development files for Storage Instantiation Daemon (SID) logging
License: GPLv2+
Requires: %{name}-log-libs%{?_isa} = %{?epoch}:%{version}-%{release}
%description log-libs-devel
This package contains development files for Storage Instantiation Daemon (SID)
logging libraries.

%files log-libs-devel
%dir %{_libdir}/sid
%{_libdir}/sid/libsidlog.so
%dir %{_includedir}/sid
%dir %{_includedir}/sid/log
%{_includedir}/sid/log/log.h
%doc README.md


##############################################################################
# SID-IFACE-LIBS
##############################################################################

%package iface-libs
Summary: Libraries for Storage Instantiation Daemon (SID) interfaces
License: GPLv2+
Requires: %{name}-base-libs%{?_isa} = %{?epoch}:%{version}-%{release}
%description iface-libs
This package contains shared libraries to support interfaces used in Storage
Instantiation Daemon (SID), its modules and related tools.

%files iface-libs
%dir %{_libdir}/sid
%{_libdir}/sid/libsidiface_servicelink.so.*
%{_libdir}/sid/libsidiface.so.*
%doc README.md


##############################################################################
# SID-IFACE-LIBS-DEVEL
##############################################################################

%package iface-libs-devel
Summary: Development files for Storage Instantiation Daemon (SID) interfaces
License: GPLv2+
Requires: %{name}-iface-libs%{?_isa} = %{?epoch}:%{version}-%{release}
%description iface-libs-devel
This package contains development files for Storage Instantiation Daemon (SID)
interface libraries.

%files iface-libs-devel
%dir %{_libdir}/sid
%{_libdir}/sid/libsidiface_servicelink.so
%{_libdir}/sid/libsidiface.so
%dir %{_includedir}/sid
%dir %{_includedir}/sid/iface
%{_includedir}/sid/iface/service-link.h
%{_includedir}/sid/iface/iface.h
%doc README.md


##############################################################################
# SID-RESOURCE-LIBS
##############################################################################

%package resource-libs
Summary: Libraries for Storage Instantiation Daemon (SID) resources
License: GPLv2+
Requires: %{name}-internal-libs%{?_isa} = %{?epoch}:%{version}-%{release}
Requires: %{name}-log-libs%{?_isa} = %{?epoch}:%{version}-%{release}
Requires: %{name}-iface-libs%{?_isa} = %{?epoch}:%{version}-%{release}
# Systemd supports event loop since v221
Requires: systemd-libs >= 221
%description resource-libs
This package contains shared libraries to support high-level resources that
represent hierarchical units of reusable code used in Storage Instantiation
Daemon (SID), its modules and related tools. Currently, it contains support
for aggregation, key-value store, module loading and registry, worker process
control, bridging SID core and udev and creating an instance of SID as a whole.

%files resource-libs
%dir %{_libdir}/sid
%{_libdir}/sid/libsidresource.so.*
%doc README.md


##############################################################################
# SID-RESOURCE-LIBS-DEVEL
##############################################################################

%package resource-libs-devel
Summary: Development files for Storage Instantiation Daemon (SID) resources
License: GPLv2+
Requires: %{name}-resource-libs%{?_isa} = %{?epoch}:%{version}-%{release}
%description resource-libs-devel
This package contains development files for Storage Instantiation Daemon (SID)
resource libraries.

%files resource-libs-devel
%dir %{_libdir}/sid
%{_libdir}/sid/libsidresource.so
%dir %{_includedir}/sid
%dir %{_includedir}/sid/resource
%{_includedir}/sid/resource/kv-store.h
%{_includedir}/sid/resource/module-registry.h
%{_includedir}/sid/resource/module.h
%{_includedir}/sid/resource/resource-type-regs.h
%{_includedir}/sid/resource/resource.h
%{_includedir}/sid/resource/ucmd-module.h
%{_includedir}/sid/resource/worker-control.h
%doc README.md


##############################################################################
# SID-TOOLS
##############################################################################

%package tools
Summary: Storage Instantiation Daemon (SID) supporting tools
Requires: %{name}-internal-libs%{?_isa} = %{?epoch}:%{version}-%{release}
Requires: %{name}-log-libs%{?_isa} = %{?epoch}:%{version}-%{release}
Requires: %{name}-iface-libs%{?_isa} = %{?epoch}:%{version}-%{release}
Requires: systemd-udev
%description tools
This package contains tools to support Storage Instantiation Daemon (SID).


%files tools
%{_sbindir}/sidctl
%{_udevrulesdir}/../usid
%doc README.md


##############################################################################
# SID-MOD-DUMMIES
##############################################################################
%package mod-dummies
Summary: Dummy block and type module for Storage Instantiation Daemon (SID)
Requires: %{name}-log-libs%{?_isa} = %{?epoch}:%{version}-%{release}
Requires: %{name}-resource-libs%{?_isa} = %{?epoch}:%{version}-%{release}
%description mod-dummies
This package contains dummy block and type modules for Storage Instantiation
Daemon (SID). Their only purpose is to test SID module functionality and hook
execution.

%files mod-dummies
%dir %{_libdir}/sid
%dir %{_libdir}/sid/modules/
%dir %{_libdir}/sid/modules/ucmd
%dir %{_libdir}/sid/modules/ucmd/block
%dir %{_libdir}/sid/modules/ucmd/type
%{_libdir}/sid/modules/ucmd/block/dummy_block.so
%{_libdir}/sid/modules/ucmd/type/dummy_type.so
%doc README.md


##############################################################################
# SID-MOD-BLOCK-BLKID
##############################################################################

%package mod-block-blkid
Summary: Blkid block module for Storage Instantiation Daemon (SID)
Requires: %{name}-log-libs%{?_isa} = %{?epoch}:%{version}-%{release}
Requires: %{name}-resource-libs%{?_isa} = %{?epoch}:%{version}-%{release}
%description mod-block-blkid
This package contains blkid block module for Storage Instantiation Daemon (SID).

%files mod-block-blkid
%dir %{_libdir}/sid
%dir %{_libdir}/sid/modules
%dir %{_libdir}/sid/modules/ucmd
%dir %{_libdir}/sid/modules/ucmd/block
%{_libdir}/sid/modules/ucmd/block/blkid.so
%doc README.md


##############################################################################
# SID-MOD-BLOCK-DM_MPATH
##############################################################################

%if %{enable_dm_mpath_support}

%package mod-block-dm-mpath
Summary: Device-mapper multipath block module for Storage Instantiation Daemon (SID)
Requires: %{name}-log-libs%{?_isa} = %{?epoch}:%{version}-%{release}
Requires: %{name}-resource-libs%{?_isa} = %{?epoch}:%{version}-%{release}
Requires: device-mapper-multipath-libs >= 0.8.4-7
%description mod-block-dm-mpath
This package contains device-mapper multipath block module for Storage
Instantiation Daemon (SID).

%files mod-block-dm-mpath
%dir %{_libdir}/sid
%dir %{_libdir}/sid/modules
%dir %{_libdir}/sid/modules/ucmd
%dir %{_libdir}/sid/modules/ucmd/block
%{_libdir}/sid/modules/ucmd/block/dm_mpath.so
%doc README.md

%endif


##############################################################################
# SID-MOD-TYPE-DM
##############################################################################

%package mod-type-dm
Summary: Device-mapper type module for Storage Instantiation Daemon (SID)
Requires: %{name}-log-libs%{?_isa} = %{?epoch}:%{version}-%{release}
Requires: %{name}-resource-libs%{?_isa} = %{?epoch}:%{version}-%{release}
%description mod-type-dm
This package contains device-mapper type module for Storage Instantiation
Daemon (SID).

%files mod-type-dm
%dir %{_libdir}/sid
%dir %{_libdir}/sid/modules
%dir %{_libdir}/sid/modules/ucmd
%dir %{_libdir}/sid/modules/ucmd/type
%dir %{_libdir}/sid/modules/ucmd/type/dm
%{_libdir}/sid/modules/ucmd/type/dm.so
%doc README.md


%changelog
* Tue Oct 06 2020 Peter Rajnoha <prajnoha@redhat.com> - 0.0.4-1
- Initial release.
