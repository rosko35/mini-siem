# mini-siem container image.
# Runs as an unprivileged user; reads host logs through a read-only bind mount.

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install . && rm -rf /root/.cache

COPY rules ./rules
COPY tools ./tools
COPY config.yml config.demo.yml ./
COPY demo/demo-geo.yml ./demo/demo-geo.yml

# uid 10001, member of "adm" (gid 4 on Debian/Ubuntu, the group that owns
# /var/log/auth.log and /var/log/nginx/*.log). compose adds gid 4 explicitly
# too, in case the image and host ever disagree.
RUN useradd --system --uid 10001 --gid nogroup --groups adm \
        --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin siem \
    && mkdir -p /data /app/demo/logs \
    && chown siem:nogroup /data /app/demo/logs

USER 10001

ENV SIEM_CONFIG=/app/config.yml \
    SIEM_DB=/data/siem.db \
    SIEM_DASHBOARD_HOST=0.0.0.0 \
    SIEM_DASHBOARD_PORT=8080

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3)"]

ENTRYPOINT ["siem"]
CMD ["run"]
