# =============================================================================
# SonarFort AI — Single Multi-Stage Dockerfile
#
# Directory structure expected:
#   sonarfort-ai/
#   ├── fortify-ai/        FortifyAI Python source  (api_server.py lives here)
#   ├── sonar-ai/          SonarAI Python source    (api.py lives here)
#   ├── ui/                Angular 17 frontend
#   ├── .env
#   ├── Dockerfile         ← this file
#   └── docker-compose.yml
#
# Processes managed by supervisord inside the single container:
#   nginx          :80    → Angular SPA
#                          /api/      → SonarAI   :8000
#                          /fortify/  → FortifyAI :8001
#   sonar-api      :8000  → SonarAI   (sonar-ai/api.py)
#   fortify-api    :8001  → FortifyAI (fortify-ai/api_server.py)
# =============================================================================


# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 — Angular 17 production build  (source lives in ui/)
# ─────────────────────────────────────────────────────────────────────────────
FROM node:20-alpine AS node-builder

WORKDIR /ui

RUN npm install -g @angular/cli@17

COPY ui/package.json ui/package-lock.json* ./
RUN npm ci --prefer-offline

COPY ui/ .
RUN ng build --configuration production
# Output → dist/sonarfort-ai/browser


# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 — Runtime: Python 3.11 + Java 17 + nginx + supervisord
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.11-slim

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

# ── japicmp fat-jar ───────────────────────────────────────────────────────────
ARG JAPICMP_VERSION=0.23.0
RUN mkdir -p /opt/japicmp && curl -fsSL \
    "https://repo1.maven.org/maven2/com/github/siom79/japicmp/japicmp/${JAPICMP_VERSION}/japicmp-${JAPICMP_VERSION}-jar-with-dependencies.jar" \
    -o /opt/japicmp/japicmp.jar

# ── Python deps — install both pipelines' requirements ───────────────────────
WORKDIR /app

# SonarAI requirements
COPY sonar-ai/requirements.txt ./sonar-requirements.txt
RUN pip install --no-cache-dir -r sonar-requirements.txt

# FortifyAI requirements (pip skips already-installed packages automatically)
COPY fortify-ai/requirements.txt ./fortify-requirements.txt
RUN pip install --no-cache-dir -r fortify-requirements.txt

# ── Application source ────────────────────────────────────────────────────────
# Both pipelines copied into named subdirs; supervisord launches each in its dir
COPY sonar-ai/   /app/sonar-ai/
COPY fortify-ai/ /app/fortify-ai/

# Shared .env at project root (also readable by both servers)
COPY .env* /app/

# ── Angular static files from Stage 1 ────────────────────────────────────────
RUN rm -rf /usr/share/nginx/html/*
COPY --from=node-builder /ui/dist/sonarfort-ai/browser /usr/share/nginx/html

# ── nginx configuration ───────────────────────────────────────────────────────
RUN rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/default.conf
RUN printf '\
server {\n\
    listen 80;\n\
    server_name _;\n\
    root /usr/share/nginx/html;\n\
    index index.html;\n\
\n\
    # SonarAI API  (sonar-ai/api.py — port 8000)\n\
    location /api/ {\n\
        proxy_pass         http://127.0.0.1:8000/api/;\n\
        proxy_http_version 1.1;\n\
        proxy_set_header   Host            $host;\n\
        proxy_set_header   X-Real-IP       $remote_addr;\n\
        proxy_read_timeout 300s;\n\
        proxy_send_timeout 300s;\n\
        client_max_body_size 50M;\n\
    }\n\
\n\
    # FortifyAI API  (fortify-ai/api_server.py — port 8001)\n\
    location /fortify/ {\n\
        proxy_pass         http://127.0.0.1:8001/;\n\
        proxy_http_version 1.1;\n\
        proxy_set_header   Host            $host;\n\
        proxy_set_header   X-Real-IP       $remote_addr;\n\
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

# ── supervisord ───────────────────────────────────────────────────────────────
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

# 80   = nginx (Angular UI + proxy)
# 8000 = SonarAI FastAPI (direct)
# 8001 = FortifyAI FastAPI (direct)
EXPOSE 80 8000 8001

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
