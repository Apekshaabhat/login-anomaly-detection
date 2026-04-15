# Universal Login Security Middleware API

A production-grade FastAPI backend for universal login security, anomaly detection, and behavioral analysis.

## Features

- **Password Security Engine**: Validates password strength and maintains blacklist
- **Behavioral Learning System**: Learns user patterns over time
- **Anomaly Detection**: Hybrid ML and rule-based detection
- **Explainable AI**: Provides reasons for security decisions
- **Adaptive Multi-Step Verification**: OTP-based verification system
- **Account Lock & Recovery**: Secure account management
- **Real-Time Learning**: Continuous profile adaptation
- **Device Trust System**: Tracks trusted devices
- **Cybersecurity Protections**: Rate limiting, input validation, secure logging
- **Attack Simulation**: Test endpoints for security validation

## Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Set up environment variables (copy .env.example to .env and modify)
4. Run the application:
   ```bash
   uvicorn app.main:app --reload
   ```

## API Endpoints

### Authentication
- `POST /api/auth/validate-password` - Validate password strength
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login with anomaly detection
- `POST /api/auth/verify` - Verify login with OTP

### Administration
- `GET /api/admin/logs` - Get audit logs
- `GET /api/admin/login-attempts` - Get login attempts
- `POST /api/admin/retrain-model` - Retrain ML model
- `POST /api/admin/add-blacklist` - Add password to blacklist
- `POST /api/admin/unlock` - Unlock account

### Simulation
- `POST /api/simulation/simulate-brute-force` - Simulate brute force attack
- `POST /api/simulation/simulate-anomaly` - Simulate various anomalies

## Usage

### Basic Login Flow

1. Register user with strong password
2. Login with user credentials and metadata
3. Receive decision: allow, require_verification, or block
4. If verification required, provide OTP
5. System learns from successful logins

### Integration

Send login data including:
- username, password
- IP address, location
- device fingerprint
- typing speed, keystroke timing

Receive decision with risk score and reasons.

## Security Features

- Rate limiting (Redis-based)
- Account lock after failed attempts
- Travel velocity detection
- Device fingerprinting
- Behavioral biometrics
- Secure password hashing (bcrypt)
- Audit logging

## Configuration

Modify settings in `app/config.py` or environment variables.

## Database

Uses SQLAlchemy with SQLite (default) or PostgreSQL.

## ML Model

Isolation Forest for anomaly detection, retrainable via admin endpoint.

## Testing

Use simulation endpoints to test various attack scenarios.
