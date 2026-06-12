# =============================================================================
# SonarFort AI — Single Multi-Stage Dockerfile
#
# Stages
#   1. node-builder   Angular 17 production build
#   2. final image    Python 3.11 + Java 17 + Maven + nginx + supervisord
#
# Processes (managed by supervisord inside the single container)
#   nginx          :80    → serves Angular SPA
#                          /api/      proxied → SonarAI   :8000
#                          /fortify/  proxied → FortifyAI :8001
#   sonar-api      :8000  → SonarAI   (api.py)
#   fortify-api    :8001  → FortifyAI (api_server.py)
#
# Quick start
#   docker build -t sonarfort-ai .
#   docker run --env-file .env -p 80:80 -p 8000:8000 -p 8001:8001 \
#              -v /your/maven/project:/workspace sonarfort-ai
#   Open http://localhost
# =============================================================================


# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 — Angular 17 production build
# ─────────────────────────────────────────────────────────────────────────────
FROM node:20-alpine AS node-builder

WORKDIR /ui

# Install Angular CLI 17 globally
RUN npm install -g @angular/cli@17

# Install Node deps (cached layer — only re-runs on package.json changes)
COPY package.json package-lock.json* ./
RUN npm ci --prefer-offline

# Copy the full Angular workspace and compile
COPY . .
RUN ng build --configuration production
# Output → dist/sonarfort-ai/browser  (Angular 17 standalone / esbuild default)


# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 — Runtime: Python 3.11 + Java 17 + nginx + both API servers
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.11-slim

# ── System packages ───────────────────────────────────────────────────────────
# openjdk-17  → Maven builds + japicmp API diff
# maven       → mvn clean install validation steps inside the pipeline
# nginx       → serves Angular, proxies API calls
# supervisor  → PID-1 process manager for nginx + two uvicorn workers
# git         → GitPython cloning inside the pipeline
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

# ── japicmp fat-jar (API breaking-change diff) ────────────────────────────────
ARG JAPICMP_VERSION=0.23.0
RUN mkdir -p /opt/japicmp && curl -fsSL \
    "https://repo1.maven.org/maven2/com/github/siom79/japicmp/japicmp/${JAPICMP_VERSION}/japicmp-${JAPICMP_VERSION}-jar-with-dependencies.jar" \
    -o /opt/japicmp/japicmp.jar

# ── Python dependencies ───────────────────────────────────────────────────────
# The single requirements.txt (from the uploaded file) covers both pipelines:
#   SonarAI:   langgraph, langchain, chromadb, langsmith, fastapi, uvicorn …
#   FortifyAI: pygithub, javalang, pydantic-settings, loguru, requests …
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Application source (SonarAI + FortifyAI share one working directory) ──────
COPY . .

# ── Angular static files from Stage 1 ────────────────────────────────────────
RUN rm -rf /usr/share/nginx/html/*
COPY --from=node-builder /ui/dist/sonarfort-ai/browser /usr/share/nginx/html

# ── nginx — SPA + reverse-proxy for both APIs ─────────────────────────────────
RUN rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/default.conf
RUN printf '\
server {\n\
    listen 80;\n\
    server_name _;\n\
    root /usr/share/nginx/html;\n\
    index index.html;\n\
\n\
    # SonarAI API  (api.py  — port 8000)\n\
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
    # FortifyAI API  (api_server.py  — port 8001)\n\
    location /fortify/ {\n\
        proxy_pass         http://127.0.0.1:8001/;\n\
        proxy_http_version 1.1;\n\
        proxy_set_header   Host            $host;\n\
        proxy_set_header   X-Real-IP       $remote_addr;\n\
        proxy_read_timeout 300s;\n\
        proxy_send_timeout 300s;\n\
    }\n\
\n\
    # Liveness probes\n\
    location = /health/sonar   { proxy_pass http://127.0.0.1:8000/api/config; access_log off; }\n\
    location = /health/fortify { proxy_pass http://127.0.0.1:8001/health;    access_log off; }\n\
\n\
    # Angular SPA fallback\n\
    location / {\n\
        try_files $uri $uri/ /index.html;\n\
        expires 1h;\n\
        add_header Cache-Control "public, must-revalidate";\n\
    }\n\
\n\
    # Long-cache hashed Angular assets\n\
    location ~* \.(js|css|woff2?|ttf|eot|svg|ico|png|jpg|jpeg|gif)$ {\n\
        expires 1y;\n\
        add_header Cache-Control "public, immutable";\n\
        try_files $uri =404;\n\
    }\n\
}\n' > /etc/nginx/conf.d/sonarfort.conf

# ── supervisord — manages nginx + sonar-api + fortify-api ────────────────────
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
; SonarAI  — api.py  → :8000\n\
[program:sonar-api]\n\
command=uvicorn api:app --host 127.0.0.1 --port 8000 --workers 2\n\
directory=/app\n\
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
; FortifyAI  — api_server.py  → :8001\n\
[program:fortify-api]\n\
command=uvicorn api_server:app --host 127.0.0.1 --port 8001 --workers 2\n\
directory=/app\n\
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
             /app/uploads \
             /var/log/supervisor \
             /var/run

# ── Default env — all overridden via --env-file or -e ────────────────────────
ENV JAPICMP_JAR_PATH=/opt/japicmp/japicmp.jar \
    ADR_PATH=/app/adr.py \
    PROJECT_PATH=/workspace \
    GCP_LOCATION=us-central1 \
    MAX_RETRIES=3 \
    MAX_UPGRADES=0 \
    PYTHONUNBUFFERED=1

# Port legend
#   80    nginx  — Angular UI + proxy entrypoint  (primary)
#   8000  sonar-api  — SonarAI FastAPI (also reachable directly)
#   8001  fortify-api — FortifyAI FastAPI (also reachable directly)
EXPOSE 80 8000 8001

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
