# =============================================================================
# SonarFort AI — Single-Stage Dockerfile (no npm/node inside Docker)
#
# PRE-REQUISITE — run this on your host ONCE before docker build:
#   cd ui
#   npx ng build --configuration production
#   cd ..
#
# Also download japicmp jar to tools/japicmp.jar before building.
#
# Directory structure:
#   sonarfort-ai/
#   ├── fortify-ai/
#   ├── sonar-ai/
#   ├── tools/japicmp.jar
#   ├── ui/dist/sonarfort-ai/browser/
#   ├── .env
#   ├── Dockerfile
#   └── docker-compose.yml
# =============================================================================

FROM python:3.11-bookworm

# ── Corporate SSL proxy fix — write pip.conf before any pip calls ─────────────
RUN mkdir -p /root/.config/pip && \
    echo "[global]" > /root/.config/pip/pip.conf && \
    echo "trusted-host = pypi.org pypi.python.org files.pythonhosted.org" >> /root/.config/pip/pip.conf

# ── System packages ───────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        openjdk-17-jdk-headless \
        maven \
        nginx \
        supervisor \
        git \
        curl \
        ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
ENV PATH="${JAVA_HOME}/bin:${PATH}"

# ── japicmp — copied from host (no curl/SSL needed) ──────────────────────────
RUN mkdir -p /opt/japicmp
COPY tools/japicmp.jar /opt/japicmp/japicmp.jar

# ── Python dependencies ───────────────────────────────────────────────────────
WORKDIR /app

# Single merged requirements — resolves langgraph/langchain-core version conflict
COPY requirements-merged.txt ./requirements-merged.txt
RUN pip install --no-cache-dir -r requirements-merged.txt

# ── Application source ────────────────────────────────────────────────────────
COPY sonar-ai/   /app/sonar-ai/
COPY fortify-ai/ /app/fortify-ai/
# .env is mounted at runtime via docker-compose volumes
# This ensures changes to .env take effect without rebuilding

# ── Angular — pre-built dist copied from host ─────────────────────────────────
RUN rm -rf /usr/share/nginx/html/*
COPY ui/dist/sonarfort-ai/browser /usr/share/nginx/html

# ── nginx config ──────────────────────────────────────────────────────────────
RUN rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/default.conf
RUN printf 'server {\n\
    listen 80;\n\
    server_name _;\n\
    root /usr/share/nginx/html;\n\
    index index.html;\n\
    location /api/ {\n\
        proxy_pass http://127.0.0.1:8000/api/;\n\
        proxy_http_version 1.1;\n\
        proxy_set_header Host $host;\n\
        proxy_set_header X-Real-IP $remote_addr;\n\
        proxy_read_timeout 300s;\n\
        client_max_body_size 50M;\n\
    }\n\
    location /fortify/ {\n\
        proxy_pass http://127.0.0.1:8001/;\n\
        proxy_http_version 1.1;\n\
        proxy_set_header Host $host;\n\
        proxy_set_header X-Real-IP $remote_addr;\n\
        proxy_read_timeout 300s;\n\
    }\n\
    location = /health/sonar   { proxy_pass http://127.0.0.1:8000/api/config; access_log off; }\n\
    location = /health/fortify { proxy_pass http://127.0.0.1:8001/health; access_log off; }\n\
    location / {\n\
        try_files $uri $uri/ /index.html;\n\
    }\n\
}\n' > /etc/nginx/conf.d/sonarfort.conf

# ── supervisord ───────────────────────────────────────────────────────────────
# Write main supervisord.conf with [include] directive
RUN printf '[supervisord]\nnodaemon=true\nuser=root\nlogfile=/var/log/supervisor/supervisord.log\nlogfile_maxbytes=10MB\npidfile=/var/run/supervisord.pid\n\n[include]\nfiles = /etc/supervisor/conf.d/*.conf\n' > /etc/supervisor/supervisord.conf

# Write individual program configs
RUN printf '[program:nginx]\ncommand=/usr/sbin/nginx -g "daemon off;"\nautostart=true\nautorestart=true\nstdout_logfile=/dev/stdout\nstdout_logfile_maxbytes=0\nstderr_logfile=/dev/stderr\nstderr_logfile_maxbytes=0\npriority=10\n' > /etc/supervisor/conf.d/nginx.conf

RUN printf '[program:sonar-api]\ncommand=uvicorn api:app --host 0.0.0.0 --port 8000 --workers 2\ndirectory=/app/sonar-ai\nautostart=true\nautorestart=true\nstartsecs=5\nstdout_logfile=/dev/stdout\nstdout_logfile_maxbytes=0\nstderr_logfile=/dev/stderr\nstderr_logfile_maxbytes=0\nenvironment=PYTHONUNBUFFERED="1",ENV_FILE="/app/sonar-ai/.env"\npriority=20\n' > /etc/supervisor/conf.d/sonar-api.conf

RUN printf '[program:fortify-api]\ncommand=uvicorn api_server:app --host 0.0.0.0 --port 8001 --workers 2\ndirectory=/app/fortify-ai\nautostart=true\nautorestart=true\nstartsecs=5\nstdout_logfile=/dev/stdout\nstdout_logfile_maxbytes=0\nstderr_logfile=/dev/stderr\nstderr_logfile_maxbytes=0\nenvironment=PYTHONUNBUFFERED="1",ENV_FILE="/app/fortify-ai/.env"\npriority=30\n' > /etc/supervisor/conf.d/fortify-api.conf

# ── Runtime directories ───────────────────────────────────────────────────────
RUN mkdir -p /tmp/fortifyai \
             /workspace \
             /app/sonar-ai/uploads \
             /var/log/supervisor \
             /var/run

ENV JAPICMP_JAR_PATH=/opt/japicmp/japicmp.jar \
    ADR_PATH=/app/fortify-ai/adr.py \
    PROJECT_PATH=/workspace \
    GCP_LOCATION=us-central1 \
    MAX_RETRIES=3 \
    MAX_UPGRADES=0 \
    PYTHONUNBUFFERED=1

EXPOSE 80 8000 8001

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]