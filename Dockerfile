FROM python:3.14-slim@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6

ARG PIP_INDEX_URL=""
ARG PIP_TRUSTED_HOST=""

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
RUN addgroup --system app && adduser --system --ingroup app app
COPY requirements.txt .
# pip/setuptools/wheel are build-time only (nothing in this app imports pip,
# setuptools, or pkg_resources at runtime) and each vendors its own bundled
# copies of packaging/jaraco.context/wheel/msgpack that otherwise show up as
# unfixable image-scan findings independent of our own requirements.txt pins.
# Remove them once the real dependencies are installed.
RUN if [ -n "$PIP_INDEX_URL" ]; then pip config set global.index-url "$PIP_INDEX_URL"; fi \
    && if [ -n "$PIP_TRUSTED_HOST" ]; then pip config set global.trusted-host "$PIP_TRUSTED_HOST"; fi \
    && pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && pip uninstall -y pip setuptools wheel \
    && rm -rf /usr/local/lib/python3.12/site-packages/pip* /usr/local/lib/python3.12/site-packages/setuptools* /usr/local/lib/python3.12/site-packages/wheel* /usr/local/lib/python3.12/site-packages/pkg_resources* /usr/local/lib/python3.12/site-packages/_distutils_hack
COPY . .
# Never ship disposable-fixture/demo-data loaders in the production image:
# they seed well-known weak passwords and sample operational records, and
# must only be reachable from a developer checkout (or Dockerfile.test), not
# from `docker exec` against a running production container.
RUN rm -f /app/tools/load_test_fixture.py /app/tools/load_demo_dataset.py /app/tools/capture_screenshots.py /app/tools/regenerate_manual.sh
RUN mkdir -p /app/uploads && chmod 755 /app/tools/container-entrypoint.sh /app/tools/gunicorn-entrypoint.sh && chown -R app:app /app
USER app
EXPOSE 8080
ENTRYPOINT ["/app/tools/container-entrypoint.sh"]
CMD ["/app/tools/gunicorn-entrypoint.sh"]
