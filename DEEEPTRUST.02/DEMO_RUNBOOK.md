# DeepTrust P10 — Golden Demo Runbook

## Overview
DeepTrust is an Enterprise Zero-Trust Identity Verification & Continuous Protection Gateway.

---

## 1. System Startup
To launch the complete platform (MongoDB, FastAPI AI Engine, Express Gateway, React Frontend, and Protected Healthcare Demo App):

```cmd
START_DEEPTRUST.bat
```

Verify service endpoints:
- **Express API Gateway / Admin Frontend**: http://localhost:5000
- **FastAPI AI Engine**: http://localhost:8000
- **Protected Healthcare Demo Portal**: http://localhost:5050

---

## 2. Golden Demo Sequence (12 Steps)

1. **Launch Platform**: Run `START_DEEPTRUST.bat`. Ensure all health checks pass.
2. **Access Admin Portal**: Navigate to `http://localhost:5000` and sign in with Admin credentials.
3. **Inspect Organization Policy**: Open **Organizations** -> **Demo Healthcare Org** -> **Security Policies**. Show active policy controls (e.g. biometrics required, risk thresholds).
4. **Open Protected Demo App**: In a separate browser tab, navigate to `http://localhost:5050` (Protected Healthcare Portal).
5. **Trigger Access Request**: Click **Access Protected Resource**. The demo app initiates an authorization request to DeepTrust Gateway (`/api/v1/access/request`).
6. **Execute Identity Verification**:
   - Complete Credential Check (Email / Password).
   - Complete 1:1 Biometric Face Match.
   - Complete Active Liveness Challenge (head rotation/smile).
   - Complete Voice Challenge phrase verification.
   - Complete Google Authenticator TOTP check.
7. **Policy & Risk Evaluation**: Backend risk engine computes risk score. Policy engine evaluates device trust and org policy -> **ALLOW**.
8. **View Protected Resource**: DeepTrust issues short-lived authorization token. Demo app verifies token via `/api/v1/access/verify` and displays synthetic patient records.
9. **Inspect Security Monitoring**: Return to Admin Portal (`http://localhost:5000`). Navigate to **Active Sessions** & **Audit Trail**. Point out the active authorization session.
10. **Revoke Session**: Click **Revoke Session** for the user's active session.
11. **Verify Immediate Access Denial**: Switch back to Protected App (`http://localhost:5050`) and retry accessing protected patient data. Request is immediately **DENIED** (HTTP 403 / Access Revoked).
12. **Audit & Incident Trail**: Return to Admin Portal. Navigate to **Security Events** / **Incidents**. Show real-time `SESSION_REVOKED` security event and export the **Incident PDF Report**.

---

## 3. Platform Shutdown
To perform a clean shutdown of all DeepTrust processes:

```cmd
STOP_DEEPTRUST.bat
```

---

## 4. Emergency Backup & Restore Procedure

- **Create Timestamped Database Backup**:
  ```cmd
  BACKUP_DEEPTRUST.bat
  ```
- **Restore Database**:
  ```cmd
  RESTORE_DEEPTRUST.bat
  ```
