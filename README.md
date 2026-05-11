# Login Anomaly Detection

A full-stack login security dashboard for detecting suspicious authentication activity. The project combines a FastAPI backend for risk scoring, behavioral learning, OTP verification, audit logging, and attack simulation with a Vite React frontend for login analysis, dashboards, model insights, and admin workflows.

## Features

- Password strength validation and blacklist checks
- Login anomaly detection using rule-based signals and an Isolation Forest model
- Behavioral learning from successful user logins
- Adaptive OTP verification for risky logins
- Account lockout and administrative alert handling
- Dashboard views for risk trends, locations, alerts, and behavior profiles
- Simulation endpoints for brute-force, anomaly, and live event testing

## Tech Stack

- Frontend: React, TypeScript, Vite, Tailwind CSS, shadcn/ui, React Query
- Backend: FastAPI, SQLAlchemy, Pydantic, scikit-learn
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

Administration:

- `GET /api/admin/dashboard`
- `GET /api/admin/behavior/{username}`
- `GET /api/admin/alerts`
- `POST /api/admin/alerts/{alert_id}/resolve`
- `POST /api/admin/alerts/{alert_id}/block`
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

Default config:

```env
DRIFT_THRESHOLD=0.2
MODEL_METADATA_PATH=app/ml/model_metadata.json
MODEL_MONITORING_LOG_PATH=app/ml/model_predictions.jsonl
```

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
