#
# SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

#global commit 13a0dd86874b5d7558a0e131f3deaa42cd7d9d23
%{?commit:%global shortcommit %(c=%{commit}; echo ${c:0:7})}
%{?commit:%global commitdate 20200828}
%{?commit:%global scmsnap %{commitdate}git%{shortcommit}}

%global enable_mod_dummies 1
%global enable_mod_block_blkid 1
%global enable_mod_block_dm_mpath 1
%global enable_mod_type_dm 1
%global enable_mod_type_dm__lvm 1

##############################################################################
# SID
##############################################################################

Name: sid
%if 0%{?rhel}
Epoch: %{rhel}
%endif
Version: 0.0.6
Release: 1%{?scmsnap:.%{scmsnap}}%{?dist}
Summary: Storage Instantiation Daemon (SID)

License: GPL-2.0-or-later
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
%if %{enable_mod_block_blkid}
BuildRequires: libblkid-devel
%endif
%if %{enable_mod_block_dm_mpath}
BuildRequires: device-mapper-multipath-devel >= 0.8.4-7
%endif

Requires: systemd
Requires: systemd-udev
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

%if %{enable_mod_block_blkid}
%global configure_mod_block_blkid --enable-mod-block-blkid
%else
%global configure_mod_block_dm_mpath --disable-mod-block-blkid
%endif

%if %{enable_mod_block_dm_mpath}
%global configure_mod_block_dm_mpath --enable-mod-block-dm_mpath
%else
%global configure_mod_block_dm_mpath --disable-mod-block-dm_mpath
%endif

%if %{enable_mod_type_dm}
%global configure_mod_type_dm --enable-mod-type-dm
%else
%global configure_mod_type_dm --disable-mod-type-dm
%endif

%if %{enable_mod_type_dm__lvm}
%global configure_mod_type_dm__lvm --enable-mod-type-dm-lvm
%else
%global configure_mod_type_dm__lvm --disable-mod-type-dm-lvm
%endif

%if %{enable_mod_dummies}
%global configure_mod_dummies --enable-mod-block-dummy --enable-mod-type-dummy
%else
%global configure_mod_dummies --disable-mod-block-dummy --disable-mod-type-dummy
%endif

%build
autoreconf -ivf
%configure %{?configure_mod_block_blkid} %{?configure_mod_block_dm_mpath} %{?configure_mod_type_dm} %{?configure_mod_type_dm__lvm} %{?configure_mod_dummies}

%make_build

%install
make DESTDIR=%{buildroot} install
rm -f %{buildroot}/%{_libdir}/sid/*.{a,la}
rm -f %{buildroot}/%{_libdir}/sid/modules/ucmd/block/*.{a,la}
rm -f %{buildroot}/%{_libdir}/sid/modules/ucmd/type/*.{a,la}
rm -f %{buildroot}/%{_libdir}/sid/modules/ucmd/type/dm/*.{a,la}

%files
%license LICENSES/GPL-2.0-or-later.txt LICENSES/BSD-3-Clause.txt LICENSES/FSFAP.txt LICENSES/FSFAP-no-warranty-disclaimer.txt LICENSES/CC0-1.0.txt
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
License: GPL-2.0-or-later AND BSD-3-Clause
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
License: GPL-2.0-or-later AND BSD-3-Clause
Requires: %{name}-base-libs%{?_isa} = %{?epoch}:%{version}-%{release}
%description base-libs-devel
This package contains development files for Storage Instantiation Daemon (SID)
base libraries.

%files base-libs-devel
%dir %{_libdir}/sid
%{_libdir}/sid/libsidbase.so
%dir %{_includedir}/sid
%dir %{_includedir}/sid/base
%{_includedir}/sid/base/buf-common.h
%{_includedir}/sid/base/buf-type.h
%{_includedir}/sid/base/buf.h
%{_includedir}/sid/base/comms.h
%{_includedir}/sid/base/conv.h
%{_includedir}/sid/base/conv-base64.h
%{_includedir}/sid/base/util.h
%doc README.md


##############################################################################
# SID-INTERNAL-LIBS
##############################################################################

%package internal-libs
Summary: Development files for Storage Instantiation Daemon (SID) internal
License: GPL-2.0-or-later AND BSD-3-Clause
Requires: %{name}-base-libs%{?_isa} = %{?epoch}:%{version}-%{release}
%description internal-libs
This package contains shared libraries with low-level functionality needed for
Storage Instantiation Daemon (SID) and its modules. Currently, it contains
basic support for bitmaps, hashing, lists, memory handling and other helper
functions.

%files internal-libs
%dir %{_libdir}/sid
%{_libdir}/sid/libsidinternal.so.*
%doc README.md


##############################################################################
# SID-INTERNAL-LIBS-DEVEL
##############################################################################
%package internal-libs-devel
Summary: Development files for Storage Instantiation Daemon (SID) internal
License: GPL-2.0-or-later AND BSD-3-Clause
Requires: %{name}-internal-libs%{?_isa} = %{?epoch}:%{version}-%{release}
%description internal-libs-devel
This package contains development files for Storage Instantiation Daemon (SID)
internal libraries.

%files internal-libs-devel
%dir %{_includedir}/sid/internal
%{_includedir}/sid/internal/bmp.h
%{_includedir}/sid/internal/bptree.h
%{_includedir}/sid/internal/common.h
%{_includedir}/sid/internal/comp-attrs.h
%{_includedir}/sid/internal/fmt.h
%{_includedir}/sid/internal/hash.h
%{_includedir}/sid/internal/list.h
%{_includedir}/sid/internal/mem.h
%{_includedir}/sid/internal/util.h
%{_libdir}/sid/libsidinternal.so


##############################################################################
# SID-LOG-LIBS
##############################################################################

%package log-libs
Summary: Libraries for Storage Instantiation Daemon (SID) logging
License: GPL-2.0-or-later
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
License: GPL-2.0-or-later
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
License: GPL-2.0-or-later
Requires: %{name}-internal-libs%{?_isa} = %{?epoch}:%{version}-%{release}
Requires: %{name}-log-libs%{?_isa} = %{?epoch}:%{version}-%{release}
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
License: GPL-2.0-or-later
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
%{_includedir}/sid/iface/srv-lnk.h
%{_includedir}/sid/iface/ifc.h
%{_includedir}/sid/iface/ifc-internal.h
%doc README.md


##############################################################################
# SID-RESOURCE-LIBS
##############################################################################

%package resource-libs
Summary: Libraries for Storage Instantiation Daemon (SID) resources
License: GPL-2.0-or-later
Requires: %{name}-internal-libs%{?_isa} = %{?epoch}:%{version}-%{release}
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
License: GPL-2.0-or-later
Requires: %{name}-resource-libs%{?_isa} = %{?epoch}:%{version}-%{release}
%description resource-libs-devel
This package contains development files for Storage Instantiation Daemon (SID)
resource libraries.

%files resource-libs-devel
%dir %{_libdir}/sid
%{_libdir}/sid/libsidresource.so
%dir %{_includedir}/sid
%dir %{_includedir}/sid/resource
%{_includedir}/sid/resource/kvs.h
%{_includedir}/sid/resource/mod-reg.h
%{_includedir}/sid/resource/mod.h
%{_includedir}/sid/resource/res-type-regs.h
%{_includedir}/sid/resource/res.h
%{_includedir}/sid/resource/ucmd-mod.h
%{_includedir}/sid/resource/ubr.h
%{_includedir}/sid/resource/wrk-ctl.h
%doc README.md


##############################################################################
# SID-TOOLS
##############################################################################

%package tools
Summary: Storage Instantiation Daemon (SID) supporting tools
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

%if %{enable_mod_dummies}

%package mod-dummies
Summary: Dummy block and type module for Storage Instantiation Daemon (SID)
Requires: %{name} = %{?epoch}:%{version}-%{release}
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

%endif


##############################################################################
# SID-MOD-BLOCK-BLKID
##############################################################################

%if %{enable_mod_block_blkid}

%package mod-block-blkid
Summary: Blkid block module for Storage Instantiation Daemon (SID)
Requires: %{name} = %{?epoch}:%{version}-%{release}
%description mod-block-blkid
This package contains blkid block module for Storage Instantiation Daemon (SID).

%files mod-block-blkid
%dir %{_libdir}/sid
%dir %{_libdir}/sid/modules
%dir %{_libdir}/sid/modules/ucmd
%dir %{_libdir}/sid/modules/ucmd/block
%{_libdir}/sid/modules/ucmd/block/blkid.so
%doc README.md

%endif


##############################################################################
# SID-MOD-BLOCK-DM_MPATH
##############################################################################

%if %{enable_mod_block_dm_mpath}

%package mod-block-dm-mpath
Summary: Device-mapper multipath block module for Storage Instantiation Daemon (SID)
Requires: %{name} = %{?epoch}:%{version}-%{release}
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

%if %{enable_mod_type_dm}

%package mod-type-dm
Summary: Device-mapper type module for Storage Instantiation Daemon (SID)
Requires: %{name} = %{?epoch}:%{version}-%{release}
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

%endif


##############################################################################
# SID-MOD-TYPE-DM-LVM
##############################################################################

%if %{enable_mod_type_dm__lvm}

%package mod-type-dm-lvm
Summary: LVM type module for Storage Instantiation Daemon (SID)
Requires: %{name} = %{?epoch}:%{version}-%{release}
Requires: %{name}-mod-type-dm%{?_isa} = %{?epoch}:%{version}-%{release}
%description mod-type-dm-lvm
This package contains LVM type module for Storage Instantiation
Daemon (SID).

%files mod-type-dm-lvm
%{_libdir}/sid/modules/ucmd/type/dm/lvm.so
%doc README.md

%endif


%changelog
* Tue Oct 06 2020 Peter Rajnoha <prajnoha@redhat.com> - 0.0.4-1
- Initial release.
