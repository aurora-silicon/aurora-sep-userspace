Name:		fprintd
Version:	1.94.5
Release:	99%{?dist}.aurora4
Summary:	D-Bus service for Fingerprint reader access

# man page is GFDL-1.1-or-later
License:	GPL-2.0-or-later AND GFDL-1.1-or-later
Source0:	https://gitlab.freedesktop.org/libfprint/fprintd/-/archive/v%{version}/fprintd-v%{version}.tar.gz
Patch0:	0001-preserve-print-on-device-delete-failure.patch
Patch1:	0002-report-lockout-and-fall-back-to-the-password.patch
Patch2:	0003-say-why-the-reader-needs-the-password.patch
Patch3:	0004-dont-ask-for-a-finger-the-reader-will-not-take.patch
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
Provides:	fprintd(aurora-sep) = 1
Requires:	libfprint(aurora-sep) >= 5
Requires:	libfprint(aurora-sep-lockout)
# FP_DEVICE_ERROR_PASSWORD_REQUIRED{,_AFTER_BOOT} (0003)
Requires:	libfprint(aurora-sep-password-reasons)
# fp_device_get_password_required() (0004)
BuildRequires:	libfprint-devel >= 1.94.100-1.aurora12
Requires:	libfprint(aurora-sep-password-required)


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
# 0002 needs FP_DEVICE_ERROR_LOCKED_OUT (0x102 in libfprint aurora10's 0008).
# Build against any libfprint-devel, as the per-package CI does with stock
# headers; at run time the Requires below brings in the libfprint that
# reports it.
# 0003 likewise needs FP_DEVICE_ERROR_PASSWORD_REQUIRED (0x103) and
# FP_DEVICE_ERROR_PASSWORD_REQUIRED_AFTER_BOOT (0x104) from aurora11's 0009.
aurora_cflags=
if ! grep -q FP_DEVICE_ERROR_LOCKED_OUT %{_includedir}/libfprint-2/fp-device.h; then
  aurora_cflags="$aurora_cflags -DFP_DEVICE_ERROR_LOCKED_OUT=0x102"
fi
if ! grep -q FP_DEVICE_ERROR_PASSWORD_REQUIRED_AFTER_BOOT %{_includedir}/libfprint-2/fp-device.h; then
  aurora_cflags="$aurora_cflags -DFP_DEVICE_ERROR_PASSWORD_REQUIRED=0x103"
  aurora_cflags="$aurora_cflags -DFP_DEVICE_ERROR_PASSWORD_REQUIRED_AFTER_BOOT=0x104"
fi
if [ -n "$aurora_cflags" ]; then
  export CFLAGS="%{optflags}$aurora_cflags"
fi
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
* Tue Nov 10 2026 Ryan Murray <ryan@aurorasilicon.org> - 1.94.5-99.aurora4
- Don't emit VerifyFingerSelected while the reader needs the password, so
  pam_fprintd and GNOME don't ask for a finger before "Your password is
  required to enable Touch ID."

* Sun Nov 08 2026 Ryan Murray <ryan@aurorasilicon.org> - 1.94.5-99.aurora3
- Report a reader that waits for the first password since boot as
  verify-password-required-after-boot and any other password requirement as
  verify-password-required; pam_fprintd says "Your password is required to
  enable Touch ID." or "Your password is required to use Touch ID." and keeps
  "Too many failed fingerprint attempts" for a real lockout

* Sun Nov 08 2026 Ryan Murray <ryan@aurorasilicon.org> - 1.94.5-99.aurora2
- Report a reader lockout as verify-lockout; pam_fprintd then asks for the
  password at once

* Tue Oct 27 2026 Aurora Silicon contributors - 1.94.5-99.aurora1
- Keep local fingerprint records when deletion from the device fails
