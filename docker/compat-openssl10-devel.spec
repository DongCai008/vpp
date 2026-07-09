Name: compat-openssl10-devel
Version: 1.0.2
Release: 1
Summary: Empty placeholder for a package no longer available in Fedora's repos
License: None
BuildArch: noarch

%description
compat-openssl10-devel is no longer available in Fedora's repos (checked on
both Fedora 40 and 44). Nothing in VPP's build actually uses it (no
references anywhere in src/ or build-data/), but VPP's own `make build`
dependency check (Makefile's $(BR)/.deps.ok target) runs `rpm -q` against
every entry in RPM_DEPENDS unconditionally and fails if any are missing.
This empty package satisfies that check.

%files
