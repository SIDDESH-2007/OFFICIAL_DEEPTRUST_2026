# 🔐 Secure Admin Login System — Frontend

A **3-stage AI-assisted authentication flow** built with pure HTML, CSS, and Vanilla JavaScript.  
No frameworks. No build tools. Copy the files and go.

---

## 📁 Project Structure

```
secure-admin-login/
│
├── login.html              ← Login page (drop-in or reference your own)
│
└── js/
    ├── login.js            ← 🎯 Main orchestrator — runs all stages
    ├── faceAuth.js         ← Stage 1A: Webcam face verification
    ├── patternAuth.js      ← Stage 1B: Password/pattern validation
    ├── mouseTracker.js     ← Stage 2:  Mouse behaviour analysis
    ├── captcha.js          ← Stage 3:  CAPTCHA (mock or Google)
    ├── apiService.js       ← Sends auth payload to backend API
    ├── session.js          ← JWT storage & session management
    └── dashboard_guard.js  ← Protects your existing dashboard page
```

---

## ⚡ Quick Start

### 1. Add scripts to your login page

Paste these `<script>` tags at the bottom of your `login.html`, **in this exact order**:

```html
<script src="js/session.js"></script>
<script src="js/faceAuth.js"></script>
<script src="js/patternAuth.js"></script>
<script src="js/mouseTracker.js"></script>
<script src="js/captcha.js"></script>
<script src="js/apiService.js"></script>
<script src="js/login.js"></script>
```

### 2. Add required HTML IDs

Your login page must have elements with these IDs:

| ID                   | Purpose                              |
|----------------------|--------------------------------------|
| `login-form`         | The `<form>` element                 |
| `username`           | Username `<input>`                   |
| `password`           | Password `<input>`                   |
| `login-btn`          | Submit button                        |
| `auth-status`        | Where messages appear                |
| `face-container`     | Where webcam preview is injected     |
| `captcha-container`  | Where CAPTCHA widget is injected     |
| `password-strength`  | *(optional)* Strength label          |

### 3. Protect your dashboard

Add to the `<head>` of your **existing** `dashboard.html`:

```html
<script src="js/session.js"></script>
<script src="js/dashboard_guard.js"></script>
```

That's it — unauthenticated users are redirected instantly.

---

## 🔄 Authentication Flow

```
User submits form
      │
      ▼
[Stage 1B] patternAuth.js
  Password format check (instant)
      │ FAIL → show error, STOP
      │ PASS ↓
[Stage 1A] faceAuth.js
  Webcam open → capture frame → mock verify
      │ FAIL → show error, STOP
      │ PASS ↓
[Stage 2] mouseTracker.js
  3-second mouse tracking → behaviour score
      │ score < 40 → show error, STOP
      │ score ≥ 40 ↓
[Stage 3] captcha.js
  Math CAPTCHA (or Google reCAPTCHA v2)
      │ FAIL → show error, STOP
      │ PASS ↓
apiService.js → POST /api/admin/login
      │ HTTP error → show error, STOP
      │ success ↓
session.js → save JWT
      │
      ▼
Redirect → /dashboard.html ✅
```

---

## ⚙️ Configuration

### Switch to Google reCAPTCHA

In `captcha.js`, change:
```js
const CAPTCHA_MODE = 'google'; // was 'mock'
const RECAPTCHA_SITE_KEY = 'YOUR_SITE_KEY_HERE';
```

Then add to your HTML `<head>`:
```html
<script src="https://www.google.com/recaptcha/api.js" async defer></script>
```

### Change the backend URL

In `apiService.js`:
```js
const BASE_URL = 'https://api.yourdomain.com'; // default is ''
```

### Adjust mouse sensitivity

In `mouseTracker.js`:
```js
CONFIG.humanThreshold = 40;        // minimum score to pass (0–100)
CONFIG.collectionDurationMs = 3000; // how long to track (ms)
```

### Change session timeout

In `session.js`:
```js
const SESSION_TIMEOUT_MINUTES = 30; // auto-logout after inactivity
```

---

## 🔌 Backend API Contract

`apiService.js` sends a **POST** to `/api/admin/login`:

```json
{
  "username": "admin",
  "password": "Secret123!",
  "faceVerificationResult": true,
  "patternVerificationResult": true,
  "mouseBehaviorScore": 72,
  "captchaResult": true,
  "clientTimestamp": 1712345678901
}
```

Expected success response:
```json
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiJ9...",
  "user": { "id": "u_123", "role": "admin", "username": "admin" }
}
```

Expected failure response:
```json
{
  "success": false,
  "message": "Invalid credentials."
}
```

---

## 🛡️ Security Notes

| Topic              | Detail                                                                 |
|--------------------|------------------------------------------------------------------------|
| JWT storage        | `sessionStorage` — cleared when tab closes                            |
| Password check     | Client-side is FORMAT only; real auth is on the server                |
| Face verification  | Mock implementation — integrate AWS Rekognition / Azure Face API      |
| Mouse analysis     | Heuristic bot detection — complement with server-side checks          |
| CAPTCHA            | Built-in math challenge or Google reCAPTCHA v2                        |
| Production tip     | Use `HttpOnly` cookies instead of sessionStorage for highest security |

---

## 🧩 Module Reference

| File                | Exports         | Key Method                          |
|---------------------|-----------------|-------------------------------------|
| `faceAuth.js`       | `FaceAuth`      | `FaceAuth.verify(container)`        |
| `patternAuth.js`    | `PatternAuth`   | `PatternAuth.verify({username, password})` |
| `mouseTracker.js`   | `MouseTracker`  | `MouseTracker.isHuman(onTick)`      |
| `captcha.js`        | `Captcha`       | `Captcha.verify(container)`         |
| `apiService.js`     | `ApiService`    | `ApiService.loginAdmin({...})`      |
| `session.js`        | `Session`       | `Session.save(token, user)`         |
| `dashboard_guard.js`| *(auto-runs)*   | `Session.requireAuth()`             |
| `login.js`          | *(auto-runs)*   | attaches to `#login-form`           |

---

*Built for hackathons — clean, modular, easy to extend.* 🚀
