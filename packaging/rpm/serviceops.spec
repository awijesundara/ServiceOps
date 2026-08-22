# Build: rpmbuild --define "version X.Y.Z" -ta dist/serviceops-X.Y.Z.tar.gz
# The source tarball is produced by packaging/build-dist.sh, which strips all
# application source and Dockerfiles out of the tree -- this package installs
# only the CLI, Compose/Helm definitions, and operations tooling. The actual
# application always runs from the pinned, immutable container image named
# in /etc/serviceops/serviceops.env; nothing here is ever built locally.
%global service_user serviceops
%global install_root /opt/serviceops

Name:           serviceops
Version:        %{?version}%{!?version:0.0.0}
Release:        1%{?dist}
Summary:        ServiceOps ITSM platform -- Docker Compose control plane
License:        Proprietary
URL:            https://github.com/awijesundara/ServiceOps
BuildArch:      noarch
Source0:        %{name}-%{version}.tar.gz

Requires:       docker-ce
Requires:       docker-compose-plugin
Requires:       curl
Requires:       openssl
Requires:       bash
Requires:       python3
Requires:       python3-requests
Requires:       tar
Requires:       gzip
Requires(pre):  shadow-utils
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
ServiceOps is a self-hosted ITSM platform. This package installs the
`serviceops` lifecycle CLI, Docker Compose service definitions, the
Kubernetes Helm chart, and operations tooling (backup, restore, migration
and upgrade rehearsal). It does not contain application source: every
release runs from an immutable, digest-pinned container image pulled from
the configured registry, so upgrading this package never requires a local
image build.

After installing, run:
    sudo serviceops install server --yes

%prep
%setup -q

%build
# Nothing to compile; this package ships shell/Python control-plane scripts
# and declarative Compose/Helm definitions only.

%install
rm -rf %{buildroot}
install -d -m 0755 %{buildroot}%{install_root}
cp -a . %{buildroot}%{install_root}/
rm -f %{buildroot}%{install_root}/serviceops.spec

install -d -m 0755 %{buildroot}%{_bindir}
ln -sf %{install_root}/serviceops %{buildroot}%{_bindir}/serviceops

install -d -m 0700 %{buildroot}%{_sysconfdir}/serviceops
install -m 0600 .env.example %{buildroot}%{_sysconfdir}/serviceops/serviceops.env.example
install -d -m 0700 %{buildroot}%{_sharedstatedir}/serviceops/backups

install -d -m 0755 %{buildroot}%{_unitdir}
install -m 0644 packaging/systemd/serviceops.service %{buildroot}%{_unitdir}/serviceops.service
rm -rf %{buildroot}%{install_root}/packaging

%pre
getent group %{service_user} >/dev/null || groupadd -r %{service_user}
getent passwd %{service_user} >/dev/null || \
  useradd -r -g %{service_user} -d %{install_root} -s /sbin/nologin \
    -c "ServiceOps service account" %{service_user}
# Docker Engine's own package creates this group; membership lets the
# service account use the Docker socket without running as root.
getent group docker >/dev/null && usermod -aG docker %{service_user} || :
exit 0

%post
# .env lives under /etc (not world-writable /opt) with real secrets in it;
# symlink it into the control-plane tree so the unmodified CLI scripts
# (which always read $ROOT_DIR/.env) transparently pick it up.
if [ ! -e %{install_root}/.env ]; then
  ln -s %{_sysconfdir}/serviceops/serviceops.env %{install_root}/.env
fi
if [ ! -L %{install_root}/backups ]; then
  rm -rf %{install_root}/backups
  ln -s %{_sharedstatedir}/serviceops/backups %{install_root}/backups
fi
chown -R %{service_user}:%{service_user} %{install_root} %{_sysconfdir}/serviceops %{_sharedstatedir}/serviceops
chmod 750 %{install_root}
%systemd_post serviceops.service
cat <<'MSG'

ServiceOps control plane installed to /opt/serviceops.
No database or secrets exist yet. Run:

    sudo serviceops install server --yes

then `systemctl enable --now serviceops` to bring it up on boot.
MSG

%preun
%systemd_preun serviceops.service

%postun
%systemd_postun_with_restart serviceops.service

%files
%dir %attr(0750,serviceops,serviceops) %{install_root}
%{install_root}/serviceops
%{install_root}/README.md
%{install_root}/VERSION
%{install_root}/.env.example
%{install_root}/compose.yaml
%{install_root}/compose.external-db.yaml
%{install_root}/compose.blue-green.yaml
%{install_root}/tools
%{install_root}/charts
%{install_root}/docs
%{_bindir}/serviceops
%dir %attr(0700,serviceops,serviceops) %{_sysconfdir}/serviceops
%config(noreplace) %attr(0600,serviceops,serviceops) %{_sysconfdir}/serviceops/serviceops.env.example
%dir %attr(0700,serviceops,serviceops) %{_sharedstatedir}/serviceops
%dir %attr(0700,serviceops,serviceops) %{_sharedstatedir}/serviceops/backups
%{_unitdir}/serviceops.service

%changelog
* Tue Jul 28 2026 ServiceOps Maintainer <serviceops-maintainer@users.noreply.github.com> - 1.23.3-1
- Security release: Flask 3.1.3, Authlib 1.6.12, requests 2.33.0, Werkzeug 3.1.6.
- build-dist.sh now accepts an image digest to pin packaged installs to an
  immutable repository@sha256:... reference instead of a mutable tag.
* Tue Jul 28 2026 ServiceOps Maintainer <serviceops-maintainer@users.noreply.github.com> - 1.23.2-1
- Initial RPM packaging of the ServiceOps control plane.
