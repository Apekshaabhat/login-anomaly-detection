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

Create and activate a virtual environment, then install Python dependencies:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Start the API server:

```bash
uvicorn app.main:app --reload
```

The API runs at `http://127.0.0.1:8000`.

Useful backend URLs:

- `GET /health`
- `GET /docs`
- `GET /redoc`

## Frontend Setup

Install dependencies:

```bash
npm install
```

Start the Vite dev server:

```bash
npm run dev
```

The frontend runs at `http://localhost:8080` and proxies `/api` requests to `http://127.0.0.1:8000`.

## Docker Services

To run PostgreSQL and Redis locally:

```bash
docker compose up -d db redis
```

Then set `DATABASE_URL` and `REDIS_URL` in `.env` to match the values in `docker-compose.yml`.

## Common Commands

```bash
npm run dev          # Start frontend development server
npm run build        # Build frontend for production
npm run lint         # Run ESLint
npm run test         # Run frontend tests
uvicorn app.main:app --reload
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
