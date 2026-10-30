Name:		fprintd
Version:	1.94.5
Release:	99%{?dist}.aurora1
Summary:	D-Bus service for Fingerprint reader access

# man page is GFDL-1.1-or-later
License:	GPL-2.0-or-later AND GFDL-1.1-or-later
Source0:	https://gitlab.freedesktop.org/libfprint/fprintd/-/archive/v%{version}/fprintd-v%{version}.tar.gz
Patch0:	0001-preserve-print-on-device-delete-failure.patch
Source1:	test_account_gate.py
Url:		http://www.freedesktop.org/wiki/Software/fprint/fprintd

BuildRequires:	meson
BuildRequires:	gcc
BuildRequires:	gcc-c++
BuildRequires:	git
BuildRequires:	pam-devel
BuildRequires:	libfprint-devel >= 1.94.0
BuildRequires:	polkit-devel
BuildRequires:	gtk-doc
BuildRequires:	gettext
BuildRequires:	perl-podlators
BuildRequires:	pkgconfig(libsystemd)
BuildRequires:	pkgconfig(systemd)
BuildRequires:	python3
BuildRequires:	python3-dbusmock
BuildRequires:	python3-libpamtest
Requires:	libfprint(aurora-sep) >= 5


%description
D-Bus service to access fingerprint readers.


%package pam
Summary:	PAM module for fingerprint authentication
Requires:	%{name} = %{version}-%{release}
# Note that we obsolete pam_fprint, but as the configuration
# is different, it will be mentioned in the release notes
Provides:	pam_fprint = %{version}-%{release}
Obsoletes:	pam_fprint < 0.2-3
Requires(postun): authselect >= 0.3

License:	GPL-2.0-or-later

%description pam
PAM module that uses the fprintd D-Bus service for fingerprint
authentication.

%package devel
Summary:	Development files for %{name}
Requires:	%{name} = %{version}-%{release}
# dbus interfaces are GPL-2.0-or-later
# documentation is GFDL-1.1-or-later
License:	GPL-2.0-or-later AND GFDL-1.1-or-later
BuildArch:	noarch

%description devel
Development documentation for fprintd, the D-Bus service for
fingerprint readers access.

%prep
%autosetup -S git -n %{name}-v%{version}

%build
%meson -Dgtk_doc=true -Dpam=true -Dpam_modules_dir=%{_libdir}/security
%meson_build

%install
%meson_install
mkdir -p $RPM_BUILD_ROOT/%{_localstatedir}/lib/fprint

%find_lang %{name}

%check
python3 %{SOURCE1} src/device.c

%postun pam
if [ $1 -eq 0 ]; then
  /bin/authselect disable-feature with-fingerprint || :
fi

%files -f %{name}.lang
%doc README COPYING AUTHORS TODO
%{_bindir}/fprintd-*
%{_libexecdir}/fprintd
# FIXME This file should be marked as config when it does something useful
%{_sysconfdir}/fprintd.conf
%{_datadir}/dbus-1/system.d/net.reactivated.Fprint.conf
%{_datadir}/dbus-1/system-services/net.reactivated.Fprint.service
%{_unitdir}/fprintd.service
%{_datadir}/polkit-1/actions/net.reactivated.fprint.device.policy
%attr(0700, -, -) %{_localstatedir}/lib/fprint
%{_mandir}/man1/fprintd.1.gz

%files pam
%doc pam/README
%{_libdir}/security/pam_fprintd.so
%{_mandir}/man8/pam_fprintd.8.gz

%files devel
%{_datadir}/gtk-doc/
%{_datadir}/dbus-1/interfaces/net.reactivated.Fprint.Device.xml
%{_datadir}/dbus-1/interfaces/net.reactivated.Fprint.Manager.xml

%changelog
* Tue Oct 27 2026 Aurora Silicon contributors - 1.94.5-99.aurora1
- Keep local fingerprint records when deletion from the device fails
