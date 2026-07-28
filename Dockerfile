FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

ARG PIP_INDEX_URL=""
ARG PIP_TRUSTED_HOST=""

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
RUN addgroup --system app && adduser --system --ingroup app app
COPY requirements.txt .
RUN if [ -n "$PIP_INDEX_URL" ]; then pip config set global.index-url "$PIP_INDEX_URL"; fi \
    && if [ -n "$PIP_TRUSTED_HOST" ]; then pip config set global.trusted-host "$PIP_TRUSTED_HOST"; fi \
    && pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt
COPY . .
# Never ship the disposable-fixture loader in the production image: it seeds
# well-known weak passwords and must only be reachable from a developer
# checkout (or Dockerfile.test), not from `docker exec` against a running
# production container.
RUN rm -f /app/tools/load_test_fixture.py
RUN mkdir -p /app/uploads && chmod 755 /app/tools/container-entrypoint.sh /app/tools/gunicorn-entrypoint.sh && chown -R app:app /app
USER app
EXPOSE 8080
ENTRYPOINT ["/app/tools/container-entrypoint.sh"]
CMD ["/app/tools/gunicorn-entrypoint.sh"]
