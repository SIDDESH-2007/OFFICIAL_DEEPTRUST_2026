# DeepTrust AI – Deepfake Detection & Content Authentication System

Prototype-ready Flask application for AI-driven registration, contextual authentication risk scoring, and deepfake media analysis.

## Features

- AI-based registration with profile photo + 5-second live video
- AI-based login with live face verification and risk scoring
- Enterprise login option with optional face verification toggle
- SQLite storage for users and login attempts
- Upload module for image/video/audio deepfake scanning
- Dashboard analytics: overview cards, history table, trend + risk distribution
- Session-protected user dashboard and admin dashboard
- Mock OTP verification for medium-risk logins
- Deepfake warning logging with snapshot persistence
- Admin controls: block/unblock users and export forensic PDF report

## Tech Stack

- Frontend: HTML, CSS, Vanilla JavaScript
- Backend: Python Flask
- Database: SQLite
- AI Layer: Modular simulated logic in `ai/detect.py`
- Camera Access: WebRTC via `getUserMedia`

## Project Structure

```
deeptrust-ai/
├── app.py
├── database.db
├── requirements.txt
├── templates/
│   ├── register.html
│   ├── login.html
│   ├── dashboard.html
│   ├── upload.html
│   └── admin.html
├── static/
│   ├── css/styles.css
│   └── js/
│       ├── register.js
│       ├── login.js
│       └── upload.js
├── uploads/
└── ai/
    └── detect.py
```

## Run Locally

1. Create virtual environment
2. Install dependencies
   ```bash
   pip install -r requirements.txt
   ```
3. Run app
   ```bash
   python app.py
   ```
4. Open
   - `http://127.0.0.1:5000/register`
   - `http://127.0.0.1:5000/login`
   - `http://127.0.0.1:5000/upload` (after login)

## Demo Admin Credentials

- Email: `admin@deeptrust.ai`
- Password: `Admin@123`

Change these using environment variables:

- `ADMIN_EMAIL`
- `ADMIN_PASSWORD`
- `SECRET_KEY`

## AI Integration Notes

Current AI functions are placeholders in `ai/detect.py`:

- `analyze_video(video_path)`
- `compare_face(stored_signature, live_frame)`
- `calculate_risk(deepfake_prob, face_mismatch, device_score)`

Replace internals with real model inference pipelines for production.

## Cloud-Ready Architecture Path

Current prototype uses a monolithic Flask app for fast demonstration, but maps directly to a microservice architecture:

Frontend (Web UI) -> Auth API -> AI Inference Service -> Database + Object Storage

Recommended production path:

- React/Tailwind frontend
- Node.js/Express auth gateway (JWT)
- Python AI microservice (TensorFlow/PyTorch)
- MongoDB for metadata/logs
- S3-compatible object storage for media
- NGINX reverse proxy + Docker containerization
