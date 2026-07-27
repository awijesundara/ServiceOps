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
    && pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /app/uploads && chmod 755 /app/tools/container-entrypoint.sh && chown -R app:app /app
USER app
EXPOSE 8080
ENTRYPOINT ["/app/tools/container-entrypoint.sh"]
CMD ["gunicorn", "--preload", "--bind", "0.0.0.0:8080", "--workers", "2", "--threads", "4", "--access-logfile", "-", "app:create_app()"]
