Name:           lh-web-auditor
Version:        0.1.0
Release:        1%{?dist}
Summary:        lh-web - Browser Defense Strictness & CSP Entropy Coefficient
License:        Apache-2.0
URL:            https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-web-auditor
Source0:        %{name}-%{version}-src.tar.gz
Packager:       Sameer Tawade <ops@logihertz.com>
BuildArch:      noarch

%description
HTTP security header and browser defense posture auditor evaluating Content-Security-Policy (CSP), HSTS preload, CORS origin wildcards, Cross-Origin isolation, and Subresource Integrity (SRI).

%prep
%autosetup -n %{name}-0.1.0

%build
# Industrial clean-room build with zero external runtime dependencies

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_docdir}/%{name}
mkdir -p %{buildroot}%{_mandir}/man1

if [ -f bin/lh-web ]; then
    install -m 0755 bin/lh-web %{buildroot}%{_bindir}/lh-web
elif [ -f lh-web ]; then
    install -m 0755 lh-web %{buildroot}%{_bindir}/lh-web
fi

install -m 0644 README.md %{buildroot}%{_docdir}/%{name}/README.md
install -m 0644 SPEC.md %{buildroot}%{_docdir}/%{name}/SPEC.md
install -m 0644 LICENSE %{buildroot}%{_docdir}/%{name}/LICENSE
install -m 0644 NOTICE %{buildroot}%{_docdir}/%{name}/NOTICE

%files
%doc %{_docdir}/%{name}/README.md
%doc %{_docdir}/%{name}/SPEC.md
%doc %{_docdir}/%{name}/NOTICE
%license %{_docdir}/%{name}/LICENSE

%changelog
* Mon Nov 16 2026 Sameer Tawade <ops@logihertz.com> - 0.1.0-1
- Initial production release for Logihertz Systems Ecosystem and STRUCT OS.
