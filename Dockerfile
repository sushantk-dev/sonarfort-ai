# =============================================================================
# SonarFort AI — Single-Stage Dockerfile (no npm/node inside Docker)
#
# PRE-REQUISITE — run this on your host ONCE before docker build:
#   cd ui
#   npx ng build --configuration production
#   cd ..
# This produces ui/dist/sonarfort-ai/browser which is copied directly in.
#
# Directory structure:
#   sonarfort-ai/
#   ├── fortify-ai/        FortifyAI Python source  (api_server.py)
#   ├── sonar-ai/          SonarAI Python source     (api.py)
#   ├── ui/
#   │   └── dist/sonarfort-ai/browser/   ← built by you on host
#   ├── .env
#   ├── Dockerfile
#   └── docker-compose.yml
#
# Processes (supervisord):
#   nginx       :80   → Angular SPA
#                       /api/     → SonarAI   :8000
#                       /fortify/ → FortifyAI :8001
#   sonar-api   :8000 → sonar-ai/api.py
#   fortify-api :8001 → fortify-ai/api_server.py
# =============================================================================

FROM python:3.11-bookworm

# ── System packages ───────────────────────────────────────────────────────────
# bookworm (Debian 12) ships openjdk-17 natively — no extra repo needed
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

# ── japicmp fat-jar (API breaking-change diff for FortifyAI) ─────────────────
ARG JAPICMP_VERSION=0.23.0
RUN mkdir -p /opt/japicmp && curl -fsSL \
    "https://repo1.maven.org/maven2/com/github/siom79/japicmp/japicmp/${JAPICMP_VERSION}/japicmp-${JAPICMP_VERSION}-jar-with-dependencies.jar" \
    -o /opt/japicmp/japicmp.jar

# ── Python dependencies ───────────────────────────────────────────────────────
WORKDIR /app

COPY sonar-ai/requirements.txt   ./sonar-requirements.txt
COPY fortify-ai/requirements.txt ./fortify-requirements.txt

RUN pip install --no-cache-dir -r sonar-requirements.txt \
 && pip install --no-cache-dir -r fortify-requirements.txt

# ── Application source ────────────────────────────────────────────────────────
COPY sonar-ai/   /app/sonar-ai/
COPY fortify-ai/ /app/fortify-ai/
COPY .env*       /app/

# ── Angular — copy pre-built dist from host (no npm/node needed here) ─────────
# Run on host first:  cd ui && npx ng build --configuration production
RUN rm -rf /usr/share/nginx/html/*
COPY ui/dist/sonarfort-ai/browser /usr/share/nginx/html

# ── nginx — SPA + reverse proxy for both APIs ─────────────────────────────────
RUN rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/default.conf
RUN printf '\
server {\n\
    listen 80;\n\
    server_name _;\n\
    root /usr/share/nginx/html;\n\
    index index.html;\n\
\n\
    location /api/ {\n\
        proxy_pass         http://127.0.0.1:8000/api/;\n\
        proxy_http_version 1.1;\n\
        proxy_set_header   Host          $host;\n\
        proxy_set_header   X-Real-IP     $remote_addr;\n\
        proxy_read_timeout 300s;\n\
        proxy_send_timeout 300s;\n\
        client_max_body_size 50M;\n\
    }\n\
\n\
    location /fortify/ {\n\
        proxy_pass         http://127.0.0.1:8001/;\n\
        proxy_http_version 1.1;\n\
        proxy_set_header   Host          $host;\n\
        proxy_set_header   X-Real-IP     $remote_addr;\n\
        proxy_read_timeout 300s;\n\
        proxy_send_timeout 300s;\n\
    }\n\
\n\
    location = /health/sonar   { proxy_pass http://127.0.0.1:8000/api/config; access_log off; }\n\
    location = /health/fortify { proxy_pass http://127.0.0.1:8001/health;    access_log off; }\n\
\n\
    location / {\n\
        try_files $uri $uri/ /index.html;\n\
        expires 1h;\n\
        add_header Cache-Control "public, must-revalidate";\n\
    }\n\
\n\
    location ~* \.(js|css|woff2?|ttf|eot|svg|ico|png|jpg|jpeg|gif)$ {\n\
        expires 1y;\n\
        add_header Cache-Control "public, immutable";\n\
        try_files $uri =404;\n\
    }\n\
}\n' > /etc/nginx/conf.d/sonarfort.conf

# ── supervisord — nginx + sonar-api + fortify-api ─────────────────────────────
RUN printf '\
[supervisord]\n\
nodaemon=true\n\
user=root\n\
logfile=/var/log/supervisor/supervisord.log\n\
logfile_maxbytes=10MB\n\
pidfile=/var/run/supervisord.pid\n\
\n\
[program:nginx]\n\
command=/usr/sbin/nginx -g "daemon off;"\n\
autostart=true\n\
autorestart=true\n\
stdout_logfile=/dev/stdout\n\
stdout_logfile_maxbytes=0\n\
stderr_logfile=/dev/stderr\n\
stderr_logfile_maxbytes=0\n\
priority=10\n\
\n\
[program:sonar-api]\n\
command=uvicorn api:app --host 127.0.0.1 --port 8000 --workers 2\n\
directory=/app/sonar-ai\n\
autostart=true\n\
autorestart=true\n\
startsecs=5\n\
stdout_logfile=/dev/stdout\n\
stdout_logfile_maxbytes=0\n\
stderr_logfile=/dev/stderr\n\
stderr_logfile_maxbytes=0\n\
environment=PYTHONUNBUFFERED="1"\n\
priority=20\n\
\n\
[program:fortify-api]\n\
command=uvicorn api_server:app --host 127.0.0.1 --port 8001 --workers 2\n\
directory=/app/fortify-ai\n\
autostart=true\n\
autorestart=true\n\
startsecs=5\n\
stdout_logfile=/dev/stdout\n\
stdout_logfile_maxbytes=0\n\
stderr_logfile=/dev/stderr\n\
stderr_logfile_maxbytes=0\n\
environment=PYTHONUNBUFFERED="1"\n\
priority=30\n' > /etc/supervisor/conf.d/sonarfort.conf

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

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]