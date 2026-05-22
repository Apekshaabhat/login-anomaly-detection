# Login Anomaly Detection

A full-stack login security dashboard for detecting suspicious authentication activity. The project combines a FastAPI backend for risk scoring, behavioral learning, OTP verification, audit logging, and attack simulation with a Vite React frontend for login analysis, dashboards, model insights, and admin workflows.

## Features

- Password strength validation and blacklist checks
- Login anomaly detection using rule-based signals and an Isolation Forest model
- Behavioral learning from successful user logins
- Adaptive OTP verification for risky logins
- MFA method capture (`email_otp` or `sms_otp`) on login attempts
- Request IP tracking, new device/IP email alerts, and optional admin approval
- Enterprise AI risk engine with fraud probability, session trust scoring, and continuous authentication telemetry
- Behavioral biometrics from typing cadence, correction rate, mouse movement, scroll behavior, focus changes, idle ratio, and session-replay anomaly metadata
- Optional threat intelligence integrations for AbuseIPDB, IPQualityScore, MaxMind GeoIP2, VirusTotal, and Have I Been Pwned Pwned Passwords
- AI Security dashboard for attack monitoring, suspicious sessions, heatmaps, anomaly timelines, and trust trends
- Account lockout and administrative alert handling
- Dashboard views for risk trends, locations, alerts, and behavior profiles
- Simulation endpoints for brute-force, anomaly, and live event testing

## Tech Stack

- Frontend: React, TypeScript, Vite, Tailwind CSS, shadcn/ui, React Query
- Backend: FastAPI, SQLAlchemy, Pydantic, scikit-learn, GeoIP2-ready enrichment
- Storage: SQLite by default, PostgreSQL optional
- Cache/rate limiting: Redis optional
- Tests: Vitest for frontend tests

## Prerequisites

- Node.js 18 or newer
- npm or Bun
- Python 3.10 or newer
- Redis and PostgreSQL if you want to run the production-like setup

## Environment

Copy the example environment file and adjust values as needed:

```bash
cp .env.example .env
```

By default, the backend can run with SQLite:

```env
DATABASE_URL=sqlite:///./login_security.db
REDIS_URL=redis://localhost:6379
SECRET_KEY=change-this-before-production
```

The checked-in `.env.example` also includes PostgreSQL settings for use with `docker-compose.yml`.
Set `SMTP_HOST`, `SMTP_USERNAME`, `SMTP_PASSWORD`, and `SMTP_FROM_EMAIL` to send real new device/IP emails; without SMTP, the backend prints an email preview to the console. Set `REQUIRE_DEVICE_IP_APPROVAL=true` when admins should approve newly observed device/IP combinations.

Optional enterprise threat intelligence:

```env
ABUSEIPDB_API_KEY=
IPQUALITYSCORE_API_KEY=
HIBP_API_KEY=
MAXMIND_ACCOUNT_ID=
MAXMIND_LICENSE_KEY=
MAXMIND_GEOIP_DB_PATH=
VIRUSTOTAL_API_KEY=
THREAT_INTEL_TIMEOUT_SECONDS=4
THREAT_INTEL_CACHE_TTL_SECONDS=3600
CONTINUOUS_AUTH_INTERVAL_SECONDS=30
```

AbuseIPDB and IPQualityScore enrich IP reputation when keys are configured. Have I Been Pwned Pwned Passwords uses the k-anonymous SHA-1 prefix range API and is also used by password validation/registration.

Optional enterprise platform integrations:

```env
SENDGRID_API_KEY=
RESEND_API_KEY=
BREVO_API_KEY=
AUTHY_API_KEY=
FIREBASE_PROJECT_ID=
CLERK_PUBLISHABLE_KEY=
AUTH0_DOMAIN=
FINGERPRINTJS_PUBLIC_KEY=
RRWEB_ENABLED=false
MAPBOX_ACCESS_TOKEN=
```

These integrations are surfaced in the AI Security dashboard so the project can demonstrate a realistic enterprise identity-security architecture while still running locally without external services.

The frontend also reads optional public keys for browser-side demos:

```env
VITE_ADMIN_SECRET_TOKEN=
VITE_FINGERPRINTJS_PUBLIC_KEY=
VITE_RRWEB_ENABLED=false
VITE_MAPBOX_ACCESS_TOKEN=
```

Do not commit real API keys. Keep them only in `.env` or your deployment provider's secret manager.

## Demo Login Credentials

The backend seeds two demo users on startup when `SEED_DEMO_USERS=true`.

Normal user:

```text
Username: demo_user
Password: DemoUser@12345
```

Admin demo user:

```text
Username: admin_user
Password: AdminUser@12345
```

The admin demo user can sign in like a normal user to access authenticated pages. Admin actions such as resolving alerts, blocking users, approving devices, retraining, or adding password blacklist entries still require the admin action token:

```env
ADMIN_SECRET_TOKEN=admin@123
VITE_ADMIN_SECRET_TOKEN=admin@123
```

For production or public demos, change these credentials and set `SEED_DEMO_USERS=false` after creating real accounts.

## Backend Setup

Use one PowerShell terminal for the backend.

Go to the project folder:

```powershell
cd "C:\Users\apeks\Desktop\apeksha\projects\bph technologies\login-anomaly-detection\login-anamoly-detection"
```

Create a Python virtual environment:

```powershell
python -m venv .venv
```

Allow PowerShell to activate the virtual environment for this terminal session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
```

Activate the virtual environment:

```powershell
& ".\.venv\Scripts\Activate.ps1"
```

Install backend dependencies:

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Start the API server:

```powershell
uvicorn app.main:app --reload
```

The backend API runs at:

```text
http://127.0.0.1:8000
```

Useful backend URLs:

- API root: `http://127.0.0.1:8000/`
- Health check: `http://127.0.0.1:8000/health`
- Swagger docs: `http://127.0.0.1:8000/docs`
- ReDoc: `http://127.0.0.1:8000/redoc`

## Frontend Setup

Use a second PowerShell terminal for the frontend. Keep the backend terminal running.

Go to the project folder:

```powershell
cd "C:\Users\apeks\Desktop\apeksha\projects\bph technologies\login-anomaly-detection\login-anamoly-detection"
```

Install frontend dependencies:

```powershell
npm install --legacy-peer-deps
```

`--legacy-peer-deps` is needed because this project uses React 19 while `next-themes@0.3.0` declares support for React 16/17/18. This command lets npm install the dependency tree without failing on that peer dependency warning.

Start the Vite dev server:

```powershell
npm run dev
```

The frontend runs at the URL printed by Vite, usually:

```text
http://localhost:8080
```

If Vite prints a different port, such as `http://localhost:5173`, open that URL instead.

The frontend sends backend API requests to:

```text
http://127.0.0.1:8000
```

## Run Order

Start the backend first:

```powershell
cd "C:\Users\apeks\Desktop\apeksha\projects\bph technologies\login-anomaly-detection\login-anamoly-detection"
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
& ".\.venv\Scripts\Activate.ps1"
uvicorn app.main:app --reload
```

Then start the frontend in a second terminal:

```powershell
cd "C:\Users\apeks\Desktop\apeksha\projects\bph technologies\login-anomaly-detection\login-anamoly-detection"
npm install --legacy-peer-deps
npm run dev
```

Use these URLs:

```text
Frontend app: http://localhost:8080
Backend API:  http://127.0.0.1:8000
API docs:     http://127.0.0.1:8000/docs
```

If `http://127.0.0.1:8000/` shows this, the backend is working:

```json
{"message":"Universal Login Security Middleware API"}
```

That JSON page is not the frontend. Open the Vite frontend URL for the dashboard UI.

## Docker Services

To run PostgreSQL and Redis locally:

```bash
docker compose up -d db redis
```

Then set `DATABASE_URL` and `REDIS_URL` in `.env` to match the values in `docker-compose.yml`.

## Common Commands

```powershell
npm install --legacy-peer-deps      # Install frontend dependencies
npm run dev                         # Start frontend development server
npm run build                       # Build frontend for production
npm run lint                        # Run ESLint
npm run test                        # Run frontend tests
uvicorn app.main:app --reload       # Start backend API server
```

## API Overview

Authentication:

- `POST /api/auth/validate-password`
- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/verify`
- `POST /api/auth/analyze`
- `POST /api/auth/verify-otp`
- `POST /api/auth/approve-device`
- `POST /api/auth/deny-device`
- `POST /api/auth/refresh`
- `POST /api/auth/logout`

AI security:

- `POST /api/ai/telemetry` - continuous behavioral biometrics and session trust scoring
- `POST /api/ai/risk-score` - dynamic risk score from IP, device, behavior, geo, and history
- `GET /api/ai/dashboard` - live AI security analytics
- `GET /api/ai/threat-intel/ip/{ip_address}` - AbuseIPDB/IPQualityScore-backed IP intelligence
- `POST /api/ai/threat-intel/password` - HIBP Pwned Passwords range check

Administration:

- `GET /api/admin/dashboard`
- `GET /api/admin/behavior/{username}`
- `GET /api/admin/alerts`
- `POST /api/admin/alerts/{alert_id}/resolve`
- `POST /api/admin/alerts/{alert_id}/block`
- `GET /api/admin/devices`
- `POST /api/admin/devices/{device_id}/approve`
- `GET /api/admin/logs`
- `GET /api/admin/login-attempts`
- `POST /api/admin/retrain-model`
- `POST /api/admin/add-blacklist`
- `POST /api/admin/unlock`

Simulation:

- `POST /api/simulation/simulate-brute-force`
- `POST /api/simulation/simulate-anomaly`
- `POST /api/simulation/live/generate`

Model operations:

- `GET /api/model/status` - current model metrics, dataset size, version, latency, and drift health
- `GET /api/model/drift` - PSI/KL drift result and affected features
- `POST /api/model/retrain` - retrain Isolation Forest from successful login attempts
- `GET /api/model/history` - model version history persisted in local metadata
- `POST /api/model/explain` - explain a prediction from login feature values
- `GET /api/model/monitoring` - prediction latency, anomaly rate, and health telemetry
- `GET /api/model/confusion-matrix` - true/false normal/anomaly counts for visualization
- `GET /api/model/registry` - registered model adapters and default active model

## Model Monitoring Architecture

The model page uses real backend APIs instead of random frontend values.

Flow:

```text
Frontend Model page
  -> /api/model/status
  -> /api/model/drift
  -> /api/model/monitoring
  -> /api/model/history
  -> /api/model/explain

Backend model router
  -> app/services/model_monitoring.py
  -> app/ml/registry.py
  -> app/ml/model.py
  -> login_attempts table
  -> app/ml/model_metadata.json
  -> app/ml/model_predictions.jsonl
```

`model_metadata.json` stores the current model version, training history, and baseline feature distributions.

`model_predictions.jsonl` stores lightweight prediction telemetry such as risk score, decision, latency, and feature values. If telemetry writing fails, prediction still continues.

## Future-Ready Model Registry

The backend includes a small plug-and-play model registry in `app/ml/registry.py`.

Current default:

```text
isolation_forest -> Isolation Forest
```

Registered future adapters:

```text
xgboost
autoencoder
lstm
```

These future adapters are intentionally marked unavailable until their real dependencies and training logic are added. The API contract is already stable, so future models can implement:

```text
predict_anomaly_score(features)
train(rows)
metadata()
```

This keeps the current Isolation Forest pipeline fully backward-compatible while preparing the codebase for additional model classes.

## Confusion Matrix

`GET /api/model/confusion-matrix` returns counts for frontend visualization:

```json
{
  "labels": ["normal", "anomaly"],
  "matrix": [
    [120, 8],
    [4, 32]
  ],
  "counts": {
    "tn": 120,
    "fp": 8,
    "fn": 4,
    "tp": 32
  },
  "total": 164,
  "generated_at": "2026-05-11T00:00:00"
}
```

Rows are actual labels and columns are predicted labels:

```text
[[true normal, false alert],
 [missed anomaly, true anomaly]]
```

## Drift Detection

Drift detection compares recent production login features with the stored training baseline.

Implemented methods:

- PSI, Population Stability Index
- KL divergence
- feature-level affected feature reporting

The backend marks drift as detected when the highest feature drift score is greater than `DRIFT_THRESHOLD`.
Drift scores are PSI/KL-style raw scores, not accuracy percentages. A score above `0.2` usually means meaningful drift.
Production histograms are compared against the same baseline bin edges captured during retraining, so retraining resets the baseline consistently.

Drift score calculation:

```text
normalized_psi = min(1.0, psi)
normalized_kl = tanh(kl / 5)
feature_score = (normalized_psi * 0.8) + (normalized_kl * 0.2)
drift_score = mean(feature_scores)
```

This makes PSI the primary signal, keeps KL for monitoring/debugging, and avoids one noisy feature forcing the whole model into drift.

## Enterprise Security Integrations

These integrations are optional for local development. When keys are present, the backend exposes their configured status in `/api/ai/integrations` and the AI Security dashboard displays them as enterprise capabilities.

IP reputation:

- AbuseIPDB for abuse confidence score, report count, and blacklist checks
- IPQualityScore for fraud score, VPN/proxy/TOR/bot detection
- VirusTotal for advanced IP/domain enrichment

Use these to enrich:

```text
ip_risk_score
attack_type
login reasons
```

GeoIP:

- MaxMind GeoIP2 for city, country, ASN, ISP, and coordinates
- Leaflet for the free login map
- Mapbox as an optional premium live attack-map provider

Use this to improve:

```text
geo_distance_from_last_login
impossible travel detection
country/ASN anomaly scoring
```

Device fingerprinting:

- FingerprintJS for stable browser/device identifiers
- Existing local browser fingerprint fallback for no-key demos

Use this to improve:

```text
trusted devices
new device detection
account takeover detection
```

Threat intelligence:

- Have I Been Pwned Pwned Passwords for k-anonymous breached password checks

Authentication and MFA:

- Authy for production MFA
- Firebase Authentication for OTP and social login options
- Clerk for modern hosted auth, device, and session management
- Auth0 as an enterprise adaptive-authentication reference

Email and notifications:

- SendGrid for security emails and OTP delivery
- Resend for developer-friendly transactional email
- Brevo for transactional email with a generous free tier
- SMTP fallback for any provider

Behavioral biometrics:

- Typing cadence and correction rate
- Mouse velocity and idle ratio
- Scroll depth and scroll velocity
- Session-replay anomaly metadata, rrweb-ready without requiring rrweb for local demos

AI/ML upgrade path:

- Isolation Forest is the current model baseline
- Autoencoders can model higher-dimensional behavioral anomaly patterns
- XGBoost can combine vendor, device, geo, and behavioral features into a supervised risk score
- Sequence models can learn user-specific login order, timing, and location patterns

Observability:

- Sentry for frontend/backend exception monitoring
- PostHog for analytics and model event dashboards

## Production Hardening Roadmap

This project demonstrates an enterprise-inspired adaptive authentication and anomaly detection system for educational and research purposes.

The current implementation focuses on:

- Adaptive MFA
- Device fingerprinting
- IP intelligence
- Anomaly-based risk scoring
- Behavioral biometrics
- Trusted device workflows
- Suspicious login detection

### Future Production Security Enhancements

#### Identity & Access

- RBAC/ABAC authorization
- SSO federation, SAML/OAuth2/OIDC
- SCIM provisioning
- Just-in-time access controls

#### Infrastructure Security

- Secrets rotation with Vault/KMS
- HSM-backed signing keys
- WAF integration
- Zero-trust network policies

#### Audit & Compliance

- Immutable audit logging
- SIEM integration
- SOC alert pipelines
- GDPR/ISO/SOC2 alignment

#### Platform Hardening

- Distributed rate limiting
- DDoS protection
- Secure deployment pipelines
- Container/runtime isolation
- Threat modeling
- Security penetration testing

#### Monitoring & Reliability

- Prometheus/Grafana monitoring
- OpenTelemetry tracing
- Centralized logging
- Auto-scaling infrastructure
- Multi-region failover

This project is designed as a modern security engineering demonstration platform and not as a replacement for commercial IAM providers such as Okta, Microsoft Entra ID, or Cloudflare Access.

Default config:

```env
DRIFT_THRESHOLD=0.7
MODEL_METADATA_PATH=app/ml/model_metadata.json
MODEL_MONITORING_LOG_PATH=app/ml/model_predictions.jsonl
```

Drift levels:

```text
< 0.2      stable / low
0.2-0.5    moderate
0.5-0.75   high
> 0.75     critical
```

The frontend shows moderate drift as an informational variation and only strongly recommends retraining for significant drift.

## Retraining Flow

Retraining is triggered from:

- the Model page `Retrain Model` button
- `POST /api/model/retrain`
- existing backend auto-retraining hooks after enough successful logins

Retraining behavior:

1. Query successful `LoginAttempt` rows.
2. Build the same Isolation Forest feature columns used for prediction.
3. Validate minimum sample count.
4. Train a candidate model.
5. Save model artifacts using `joblib`.
6. Swap the trained model into memory only after training completes.
7. Persist version metadata and baseline distributions.

If there are not enough successful login samples, the API returns a safe error and the existing model remains active.

## Explainability

`POST /api/model/explain` accepts login feature values and returns the top anomalous factors.

Example request:

```json
{
  "login_features": {
    "login_hour": 2,
    "location_lat": 40.7128,
    "location_lon": -74.006,
    "typing_speed": 18,
    "failed_attempts": 3,
    "geo_distance_from_last_login": 1200
  }
}
```

The service uses lightweight feature contribution scoring against the learned baseline. This avoids adding a heavy SHAP dependency while still explaining why a login appears anomalous.

## Testing

Backend syntax/import check:

```powershell
python -m compileall app main.py
python -c "from app.main import app; print('routes', len(app.routes))"
```

Backend model service smoke check:

```powershell
python -c "from app.database.connection import SessionLocal; from app.services.model_monitoring import model_monitoring_service; db=SessionLocal(); data=model_monitoring_service.get_status(db); print(data['model_name'], data['status'], data['dataset_size']); db.close()"
```

Frontend type check:

```powershell
npx tsc --noEmit
```

Frontend tests:

```powershell
npm run test
```

Frontend build:

```powershell
npm run build
```

If `npm run test` or `npm run build` fails with `spawn EPERM` on Windows, it is usually an esbuild process permission issue. Reopen PowerShell as a normal user, reinstall with `npm install --legacy-peer-deps`, and retry.

## Project Structure

```text
app/                 FastAPI backend
  routers/           API route modules
  services/          Security, learning, logging, verification services
  database/          SQLAlchemy connection and models
  ml/                Anomaly detection model
src/                 React frontend
  components/        Shared UI and dashboard components
  pages/             App routes/pages
  lib/               API client and utilities
public/              Static frontend assets
```

## Notes

- Do not commit `.env`, local databases, logs, virtual environments, or dependency folders.
- Change `SECRET_KEY` before using the app outside local development.
- The SQLite database file is generated automatically when the backend starts.
- The backend can run through either `uvicorn app.main:app --reload` or `uvicorn main:app --reload`.
