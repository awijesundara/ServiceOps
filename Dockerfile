FROM python:3.14-slim@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6

ARG PIP_INDEX_URL=""
ARG PIP_TRUSTED_HOST=""
ARG APT_MIRROR="https://deb.debian.org/debian"
ARG APT_SECURITY_MIRROR="https://deb.debian.org/debian-security"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# The base image is pinned by digest for reproducibility, so newly disclosed
# OS-package CVEs with an upstream Debian security fix (found via the CI
# supply-chain gate's Trivy scan, e.g. CVE-2026-53615 in libblkid/util-linux)
# stay present until this digest is next bumped -- which can lag behind
# Debian's own security repo by days. Pulling the security-repo fixes
# directly here, on every build, closes that gap without waiting on (or
# needing to track) upstream image rebuilds.
RUN find /etc/apt -type f \( -name "*.list" -o -name "*.sources" \) -print0 | xargs -0 sed -i \
        -e "s|https\?://deb.debian.org/debian-security|${APT_SECURITY_MIRROR}|g" \
        -e "s|https\?://deb.debian.org/debian\([[:space:]]\|$\)|${APT_MIRROR}\\1|g" \
    && if apt-get -o Acquire::Retries=5 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 update \
        && DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=5 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 upgrade -y \
        && apt-get -o Acquire::Retries=5 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 install -y --no-install-recommends libpq5; then \
            echo "APT security update + libpq5 install succeeded"; \
        else \
            echo "WARNING: APT mirror is unreachable; continuing with wheel-bundled runtime libs for offline build"; \
        fi \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN addgroup --system app && adduser --system --ingroup app app
COPY requirements.txt .
# pip/setuptools/wheel are build-time only (nothing in this app imports pip,
# setuptools, or pkg_resources at runtime) and each vendors its own bundled
# copies of packaging/jaraco.context/wheel/msgpack that otherwise show up as
# unfixable image-scan findings independent of our own requirements.txt pins.
# Remove them once the real dependencies are installed.
# Prefer Debian's patched libpq whenever APT succeeded. The binary wheel
# remains installed only for the offline fallback, because its bundled EL8
# libraries otherwise trigger the release image vulnerability gate.
RUN if [ -n "$PIP_INDEX_URL" ]; then pip config set global.index-url "$PIP_INDEX_URL"; fi \
    && if [ -n "$PIP_TRUSTED_HOST" ]; then pip config set global.trusted-host "$PIP_TRUSTED_HOST"; fi \
    && pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && if ldconfig -p | grep -q 'libpq\.so\.5'; then pip uninstall -y psycopg-binary; fi \
    && site_packages="$(python -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')" \
    && pip uninstall -y pip setuptools wheel \
    && rm -rf "${site_packages}"/pip* "${site_packages}"/setuptools* "${site_packages}"/wheel* "${site_packages}"/pkg_resources* "${site_packages}"/_distutils_hack
COPY . .
# Never ship disposable-fixture/demo-data loaders in the production image:
# they seed well-known weak passwords and sample operational records, and
# must only be reachable from a developer checkout (or Dockerfile.test), not
# from `docker exec` against a running production container.
RUN rm -f /app/tools/load_test_fixture.py /app/tools/load_demo_dataset.py /app/tools/seed_load_test_dataset.py
RUN mkdir -p /app/uploads /app/logs && chmod 755 /app/tools/container-entrypoint.sh /app/tools/gunicorn-entrypoint.sh && chown -R app:app /app
USER app
EXPOSE 8080
# Docker's default stop signal is SIGTERM, but gunicorn's arbiter treats
# SIGTERM as a *fast* shutdown and reserves SIGQUIT for graceful shutdown
# (finish in-flight requests within --graceful-timeout, then exit -- see
# tools/gunicorn-entrypoint.sh). Without this, every container stop/restart
# (docker compose stop/restart/up --force-recreate, ./serviceops
# watchdog-heal, Kubernetes pod termination) can cut off a request that is
# actively being processed -- e.g. a user's ticket-form submit lands
# mid-write -- instead of letting it complete within the timeout budget
# that already exists but was never actually reached.
STOPSIGNAL SIGQUIT
ENTRYPOINT ["/app/tools/container-entrypoint.sh"]
CMD ["/app/tools/gunicorn-entrypoint.sh"]
