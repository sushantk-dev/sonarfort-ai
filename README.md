# sonarfort-ai

SonarFort AI is an end-to-end automated security remediation platform that unifies SonarQube and Fortify SSC into a single AI-driven pipeline. It ingests findings from both tools, triages and groups vulnerabilities by dependency, resolves the minimum safe upgrade version, runs API compatibility analysis with japicmp, and uses a LangGraph agent graph with Claude on Vertex AI to reason about upgrade safety, generate code fixes, and validate them against a Maven build. Passing fixes are delivered as GitHub pull requests with full context — CVE detail, AI confidence, build result, and OWASP mapping. Failed fixes trigger a retry loop with AI-generated call-site patches; issues that cannot be resolved are escalated and written back to Fortify SSC as structured comments. The Angular dashboard provides live pipeline traces, issue management, and escalation review across both sources.





cp .env.example .env

docker compose up --build



\# Access points:

\# http://localhost       → Angular UI

\# http://localhost:8000/docs  → SonarAI Swagger

\# http://localhost:8001/docs  → FortifyAI Swagger



Step 1 — Authenticate with GCP:

gcloud auth login



gcloud config set project YOUR\_GCP\_PROJECT\_ID



Step 2 — Create Artifact Registry repo (once):

gcloud artifacts repositories create sonarfort --repository-format=docker --location=us-central1 --project=YOUR\_GCP\_PROJECT\_ID



Step 3 — Configure Docker to use GCP registry:

gcloud auth configure-docker us-central1-docker.pkg.dev



Step 4 — Build Angular first (if not already done):

cd ui

npx ng build --configuration production

cd ..



Step 5 — Build Docker image with GCP tag:

docker build -t us-central1-docker.pkg.dev/YOUR\_GCP\_PROJECT\_ID/sonarfort/sonarfort-ai:latest .



Step 6 — Push to Artifact Registry:

docker push us-central1-docker.pkg.dev/YOUR\_GCP\_PROJECT\_ID/sonarfort/sonarfort-ai:latest



Step 7 — Verify it's there:

gcloud artifacts docker images list us-central1-docker.pkg.dev/YOUR\_GCP\_PROJECT\_ID/sonarfort



Replace these values:

YOUR\_GCP\_PROJECT\_ID  → your actual GCP project ID

us-central1          → your preferred region

sonarfort            → repo name (can be anything)



Subsequent pushes (after code changes):

cd ui \&\& npx ng build --configuration production \&\& cd ..

docker build -t us-central1-docker.pkg.dev/YOUR\_GCP\_PROJECT\_ID/sonarfort/sonarfort-ai:latest .

docker push us-central1-docker.pkg.dev/YOUR\_GCP\_PROJECT\_ID/sonarfort/sonarfort-ai:latest





python -c "import certifi; print(certifi.where())"



python -c "import certifi; open(certifi.where(), 'ab').write(open('C:\\\\path\\\\to\\\\SecR46.crt','rb').read())"



set REQUESTS\_CA\_BUNDLE=C:\\path\\to\\SecR46.crt

set SSL\_CERT\_FILE=C:\\path\\to\\SecR46.crt



C:\\Users\\sxk1277\\AppData\\Local\\Programs\\Python\\Python313\\Lib\\site-packages\\certifi\\cacert.pem



type "C:\\Work\\Special-Project-AI\\sonarfort-ai\\certs\\SecR46.crt" >> "C:\\Users\\sxk1277\\AppData\\Local\\Programs\\Python\\Python313\\Lib\\site-packages\\certifi\\cacert.pem"



set REQUESTS\_CA\_BUNDLE=C:\\Users\\sxk1277\\AppData\\Local\\Programs\\Python\\Python313\\Lib\\site-packages\\certifi\\cacert.pem

