import base64
import hashlib
import os
import secrets
import shutil
import sqlite3
from io import BytesIO
from datetime import datetime
from functools import wraps

import bcrypt
from flask import Flask, jsonify, redirect, render_template, request, send_file, session, url_for
from reportlab.pdfgen import canvas
from werkzeug.utils import secure_filename

from ai.detect import analyze_media, analyze_video, calculate_risk, compare_face, generate_face_signature

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
DB_PATH = os.path.join(BASE_DIR, "database.db")

ALLOWED_IMAGE_EXT = {"png", "jpg", "jpeg", "webp"}
ALLOWED_VIDEO_EXT = {"webm", "mp4", "mov"}
ALLOWED_AUDIO_EXT = {"wav", "mp3", "m4a"}
ALLOWED_MEDIA_EXT = ALLOWED_IMAGE_EXT | ALLOWED_VIDEO_EXT | ALLOWED_AUDIO_EXT


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", secrets.token_hex(24))
    app.config["UPLOAD_FOLDER"] = UPLOAD_DIR
    app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024
    app.config["ADMIN_EMAIL"] = os.getenv("ADMIN_EMAIL", "admin@deeptrust.ai")
    app.config["ADMIN_PASSWORD"] = os.getenv("ADMIN_PASSWORD", "Admin@123")

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    init_db()
    seed_admin_user(app)

    def login_required(handler):
        @wraps(handler)
        def wrapper(*args, **kwargs):
            if not session.get("user_id"):
                return redirect(url_for("login_page"))
            return handler(*args, **kwargs)

        return wrapper

    def admin_required(handler):
        @wraps(handler)
        def wrapper(*args, **kwargs):
            if not session.get("user_id"):
                return redirect(url_for("login_page"))
            if not session.get("is_admin"):
                return redirect(url_for("dashboard"))
            return handler(*args, **kwargs)

        return wrapper

    @app.route("/")
    def root():
        if session.get("user_id"):
            return redirect(url_for("dashboard"))
        return redirect(url_for("login_page"))

    @app.route("/register")
    def register_page():
        return render_template("register.html")

    @app.route("/login")
    def login_page():
        return render_template("login.html")

    @app.route("/face-auth")
    def face_auth_page():
        return render_template("face_auth.html", has_pending=bool(session.get("pending_face_auth")))

    @app.route("/api/register", methods=["POST"])
    def register_api():
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        profile_photo = request.files.get("profile_photo")
        live_video = request.files.get("live_video")

        if not name or not email or not password or not profile_photo or not live_video:
            return jsonify({"ok": False, "message": "All fields are required."}), 400

        if not is_allowed_file(profile_photo.filename, ALLOWED_IMAGE_EXT):
            return jsonify({"ok": False, "message": "Invalid profile photo format."}), 400

        if not is_allowed_file(live_video.filename, ALLOWED_VIDEO_EXT):
            return jsonify({"ok": False, "message": "Invalid live video format."}), 400

        if find_user_by_email(email):
            return jsonify({"ok": False, "message": "Email already registered."}), 409

        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
        photo_path = save_uploaded_file(profile_photo, f"profile_{timestamp}")
        video_path = save_uploaded_file(live_video, f"register_{timestamp}")

        # AI registration flow:
        # 1) extract face embedding/signature from uploaded profile image (mock hash)
        # 2) run deepfake analysis over recorded live video
        # 3) reject if deepfake probability is high
        face_signature = generate_face_signature(photo_path)
        ai_result = analyze_video(video_path)
        deepfake_probability = ai_result["deepfake_probability"]
        authenticity_score = ai_result["authenticity_score"]

        if deepfake_probability > 60:
            snapshot_path = os.path.join(app.config["UPLOAD_FOLDER"], f"deepfake_reg_{timestamp}.jpg")
            shutil.copy(photo_path, snapshot_path)
            log_attempt(
                user_id=None,
                deepfake_probability=deepfake_probability,
                face_match_score=0,
                risk_score=deepfake_probability,
                status="registration_rejected_deepfake",
            )
            return (
                jsonify(
                    {
                        "ok": False,
                        "message": "Registration rejected: Deepfake probability too high.",
                        "deepfake_probability": deepfake_probability,
                        "snapshot": os.path.basename(snapshot_path),
                    }
                ),
                403,
            )

        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        with get_db() as conn:
            conn.execute(
                """
                INSERT INTO Users (name, email, password_hash, face_signature, authenticity_score)
                VALUES (?, ?, ?, ?, ?)
                """,
                (name, email, password_hash, face_signature, authenticity_score),
            )

        return jsonify(
            {
                "ok": True,
                "message": "Identity Verified – Registration Successful",
                "authenticity_score": authenticity_score,
            }
        )

    @app.route("/api/login", methods=["POST"])
    def login_api():
        payload = request.get_json(silent=True) or {}

        email = str(payload.get("email", "")).strip().lower()
        password = str(payload.get("password", ""))
        role = str(payload.get("role", "institutional_user")).strip().lower()
        remember_me = bool(payload.get("remember_me", False))
        device_fingerprint = str(payload.get("device_fingerprint", "unknown-device"))[:180]
        login_locale = str(payload.get("login_locale", "unknown-locale"))[:80]
        try:
            device_score = float(payload.get("device_score", 20.0))
        except (TypeError, ValueError):
            device_score = 20.0
        device_score = max(0.0, min(100.0, device_score))

        user = find_user_by_email(email)
        if not user:
            return jsonify({"ok": False, "message": "Invalid email or password."}), 401

        if not bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
            ip_address = (request.headers.get("X-Forwarded-For") or request.remote_addr or "unknown").split(",")[0].strip()
            log_attempt(
                user["id"],
                deepfake_probability=0,
                face_match_score=0,
                risk_score=100,
                status="failed_credentials",
                ip_address=ip_address,
                device_fingerprint=device_fingerprint,
                suspicious_score=100,
            )
            return jsonify({"ok": False, "message": "Invalid email or password."}), 401

        if user["is_blocked"]:
            return jsonify({"ok": False, "message": "Account is blocked by admin review."}), 403

        ip_address = (request.headers.get("X-Forwarded-For") or request.remote_addr or "unknown").split(",")[0].strip()

        new_ip_score = 10.0
        if user["last_login_ip"] and user["last_login_ip"] != ip_address:
            new_ip_score = 72.0

        new_device_score = 12.0
        if user["last_device_fingerprint"] and user["last_device_fingerprint"] != device_fingerprint:
            new_device_score = 75.0

        suspicious_location_score = 14.0
        if user["last_login_locale"] and user["last_login_locale"] != login_locale:
            suspicious_location_score = 62.0

        failed_attempts_score = calculate_failed_attempts_score(user["id"])

        risk_score = round(
            max(
                0.0,
                min(
                    100.0,
                    (new_device_score * 0.30)
                    + (new_ip_score * 0.25)
                    + (suspicious_location_score * 0.20)
                    + (failed_attempts_score * 0.25),
                ),
            ),
            2,
        )

        suspicious_pattern_score = calculate_suspicious_pattern_score(user["id"])

        if risk_score >= 50:
            session["pending_face_auth"] = {
                "user_id": user["id"],
                "name": user["name"],
                "email": user["email"],
                "is_admin": user["email"] == app.config["ADMIN_EMAIL"],
                "ip_address": ip_address,
                "device_fingerprint": device_fingerprint,
                "login_locale": login_locale,
                "role": role,
                "remember_me": remember_me,
                "risk_score": risk_score,
                "device_score": device_score,
            }

            log_attempt(
                user["id"],
                deepfake_probability=0,
                face_match_score=0,
                risk_score=risk_score,
                status="face_verification_required",
                ip_address=ip_address,
                device_fingerprint=device_fingerprint,
                suspicious_score=suspicious_pattern_score,
            )
            return jsonify(
                {
                    "ok": True,
                    "status": "face_verification_required",
                    "message": "Suspicious login pattern detected. Additional verification required.",
                    "risk_score": risk_score,
                    "attempt_counter": int(failed_attempts_score / 20),
                    "risk_breakdown": {
                        "new_ip": new_ip_score,
                        "new_device": new_device_score,
                        "suspicious_location": suspicious_location_score,
                        "failed_attempts": failed_attempts_score,
                        "suspicious_pattern": suspicious_pattern_score,
                    },
                    "redirect_url": url_for("face_auth_page"),
                }
            )

        session.permanent = remember_me
        status = "success"
        log_attempt(
            user["id"],
            deepfake_probability=0,
            face_match_score=100,
            risk_score=risk_score,
            status=status,
            ip_address=ip_address,
            device_fingerprint=device_fingerprint,
            suspicious_score=suspicious_pattern_score,
        )

        with get_db() as conn:
            conn.execute(
                """
                UPDATE Users
                SET last_login_ip = ?,
                    last_device_fingerprint = ?,
                    last_login_locale = ?,
                    last_login_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (ip_address, device_fingerprint, login_locale, user["id"]),
            )

        session["user_id"] = user["id"]
        session["name"] = user["name"]
        session["email"] = user["email"]
        session["is_admin"] = user["email"] == app.config["ADMIN_EMAIL"]
        session["role"] = role
        session["last_auth"] = {
            "deepfake_probability": 0,
            "face_match_score": 100,
            "risk_score": risk_score,
            "status": status,
        }

        return jsonify(
            {
                "ok": True,
                "status": status,
                "message": "Authentication successful.",
                "risk_score": risk_score,
                "risk_breakdown": {
                    "new_ip": new_ip_score,
                    "new_device": new_device_score,
                    "suspicious_location": suspicious_location_score,
                    "failed_attempts": failed_attempts_score,
                    "suspicious_pattern": suspicious_pattern_score,
                },
                "redirect_url": url_for("admin_dashboard") if session["is_admin"] else url_for("dashboard"),
            }
        )

    @app.route("/api/face-auth-complete", methods=["POST"])
    def face_auth_complete_api():
        pending = session.get("pending_face_auth")
        if not pending:
            return jsonify({"ok": False, "message": "Face verification session expired."}), 400

        payload = request.get_json(silent=True) or {}
        live_frame_data = str(payload.get("live_frame", ""))
        if not live_frame_data:
            return jsonify({"ok": False, "message": "Live face frame is required."}), 400

        with get_db() as conn:
            user = conn.execute("SELECT * FROM Users WHERE id = ?", (pending["user_id"],)).fetchone()

        if not user:
            session.pop("pending_face_auth", None)
            return jsonify({"ok": False, "message": "User not found."}), 404

        frame_path = save_base64_frame(live_frame_data)
        deepfake_probability = analyze_video(frame_path)["deepfake_probability"]
        face_match_score = compare_face(user["face_signature"], frame_path)
        face_mismatch = 100.0 - face_match_score
        face_risk = calculate_risk(deepfake_probability, face_mismatch, pending.get("device_score", 20.0))

        final_risk = round(max(0.0, min(100.0, (pending["risk_score"] * 0.55) + (face_risk * 0.45))), 2)

        if final_risk > 70:
            log_attempt(
                user["id"],
                deepfake_probability,
                face_match_score,
                final_risk,
                "high_risk_blocked",
                ip_address=pending.get("ip_address"),
                device_fingerprint=pending.get("device_fingerprint"),
                suspicious_score=final_risk,
            )
            session.pop("pending_face_auth", None)
            return (
                jsonify(
                    {
                        "ok": False,
                        "message": "High Risk Authentication Attempt",
                        "deepfake_probability": deepfake_probability,
                        "risk_score": final_risk,
                    }
                ),
                403,
            )

        log_attempt(
            user["id"],
            deepfake_probability,
            face_match_score,
            final_risk,
            "face_verified_success",
            ip_address=pending.get("ip_address"),
            device_fingerprint=pending.get("device_fingerprint"),
            suspicious_score=final_risk,
        )

        with get_db() as conn:
            conn.execute(
                """
                UPDATE Users
                SET last_login_ip = ?,
                    last_device_fingerprint = ?,
                    last_login_locale = ?,
                    last_login_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (pending.get("ip_address"), pending.get("device_fingerprint"), pending.get("login_locale"), user["id"]),
            )

        session.permanent = bool(pending.get("remember_me"))
        session["user_id"] = user["id"]
        session["name"] = user["name"]
        session["email"] = user["email"]
        session["is_admin"] = user["email"] == app.config["ADMIN_EMAIL"]
        session["role"] = pending.get("role", "institutional_user")
        session["last_auth"] = {
            "deepfake_probability": deepfake_probability,
            "face_match_score": face_match_score,
            "risk_score": final_risk,
            "status": "face_verified_success",
        }
        session.pop("pending_face_auth", None)

        return jsonify(
            {
                "ok": True,
                "message": "Face verification successful.",
                "risk_score": final_risk,
                "redirect_url": url_for("admin_dashboard") if session["is_admin"] else url_for("dashboard"),
            }
        )

    @app.route("/api/verify-otp", methods=["POST"])
    def verify_otp_api():
        payload = request.get_json(silent=True) or {}
        otp_input = str(payload.get("otp", "")).strip()
        pending_auth = session.get("pending_auth")

        if not pending_auth:
            return jsonify({"ok": False, "message": "No pending OTP verification."}), 400

        if otp_input != session.get("mock_otp"):
            return jsonify({"ok": False, "message": "Invalid OTP code."}), 401

        with get_db() as conn:
            conn.execute(
                "UPDATE LoginAttempts SET status = ? WHERE id = ?",
                ("otp_verified_success", pending_auth["attempt_id"]),
            )

        session["user_id"] = pending_auth["user_id"]
        session["name"] = pending_auth["name"]
        session["email"] = pending_auth["email"]
        session["is_admin"] = pending_auth["is_admin"]
        session["last_auth"] = {
            "deepfake_probability": pending_auth["deepfake_probability"],
            "face_match_score": pending_auth["face_match_score"],
            "risk_score": pending_auth["risk_score"],
            "status": "otp_verified_success",
        }

        session.pop("mock_otp", None)
        session.pop("pending_auth", None)

        return jsonify(
            {
                "ok": True,
                "message": "OTP verified. Login approved.",
                "redirect_url": url_for("admin_dashboard") if session["is_admin"] else url_for("dashboard"),
            }
        )

    @app.route("/dashboard")
    @login_required
    def dashboard():
        user_id = session["user_id"]
        media_filter = request.args.get("type", "all").lower()

        with get_db() as conn:
            user = conn.execute("SELECT * FROM Users WHERE id = ?", (user_id,)).fetchone()
            last_attempt = conn.execute(
                """
                SELECT deepfake_probability, face_match_score, risk_score, status, timestamp
                FROM LoginAttempts
                WHERE user_id = ?
                ORDER BY id DESC LIMIT 1
                """,
                (user_id,),
            ).fetchone()

            total_scanned = conn.execute(
                "SELECT COUNT(*) FROM MediaScans WHERE user_id = ?",
                (user_id,),
            ).fetchone()[0]
            authentic_count = conn.execute(
                "SELECT COUNT(*) FROM MediaScans WHERE user_id = ? AND status = 'authentic'",
                (user_id,),
            ).fetchone()[0]
            deepfake_count = conn.execute(
                "SELECT COUNT(*) FROM MediaScans WHERE user_id = ? AND status = 'deepfake_detected'",
                (user_id,),
            ).fetchone()[0]
            high_risk_alerts = conn.execute(
                "SELECT COUNT(*) FROM MediaScans WHERE user_id = ? AND risk_level = 'HIGH'",
                (user_id,),
            ).fetchone()[0]

            if media_filter in {"image", "video", "audio"}:
                history = conn.execute(
                    """
                    SELECT id, file_name, media_type, authenticity_score, risk_level, status, created_at
                    FROM MediaScans
                    WHERE user_id = ? AND media_type = ?
                    ORDER BY id DESC
                    LIMIT 20
                    """,
                    (user_id, media_filter),
                ).fetchall()
            else:
                history = conn.execute(
                    """
                    SELECT id, file_name, media_type, authenticity_score, risk_level, status, created_at
                    FROM MediaScans
                    WHERE user_id = ?
                    ORDER BY id DESC
                    LIMIT 20
                    """,
                    (user_id,),
                ).fetchall()

            trend_rows = conn.execute(
                """
                SELECT substr(created_at, 1, 7) AS month, COUNT(*) AS total
                FROM MediaScans
                WHERE user_id = ?
                GROUP BY substr(created_at, 1, 7)
                ORDER BY month DESC
                LIMIT 6
                """,
                (user_id,),
            ).fetchall()

            risk_distribution_rows = conn.execute(
                """
                SELECT risk_level, COUNT(*) AS total
                FROM MediaScans
                WHERE user_id = ?
                GROUP BY risk_level
                """,
                (user_id,),
            ).fetchall()

        auth_confidence = 100.0
        if last_attempt:
            auth_confidence = round(100.0 - last_attempt["risk_score"], 2)

        account_risk_level = "Low"
        if last_attempt and last_attempt["risk_score"] >= 70:
            account_risk_level = "High"
        elif last_attempt and last_attempt["risk_score"] >= 40:
            account_risk_level = "Medium"

        risk_distribution = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
        for row in risk_distribution_rows:
            risk_distribution[row["risk_level"]] = row["total"]

        trend_labels = [row["month"] for row in reversed(trend_rows)]
        trend_values = [row["total"] for row in reversed(trend_rows)]

        return render_template(
            "dashboard.html",
            user=user,
            auth_confidence=auth_confidence,
            last_attempt=last_attempt,
            total_scanned=total_scanned,
            authentic_count=authentic_count,
            deepfake_count=deepfake_count,
            high_risk_alerts=high_risk_alerts,
            history=history,
            media_filter=media_filter,
            trend_labels=trend_labels,
            trend_values=trend_values,
            risk_distribution=risk_distribution,
            last_login_at=user["last_login_at"],
            account_risk_level=account_risk_level,
        )

    @app.route("/upload")
    @login_required
    def upload_page():
        return render_template("upload.html")

    @app.route("/api/upload-media", methods=["POST"])
    def upload_media_api():
        if not session.get("user_id"):
            return jsonify({"ok": False, "message": "Login required."}), 401

        media_file = request.files.get("media_file")
        if not media_file:
            return jsonify({"ok": False, "message": "No media file uploaded."}), 400

        if not is_allowed_file(media_file.filename, ALLOWED_MEDIA_EXT):
            return jsonify({"ok": False, "message": "Unsupported file type."}), 400

        media_type = detect_media_type(media_file.filename)
        saved_path = save_uploaded_file(media_file, f"scan_{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}")
        file_hash = hash_file(saved_path)

        ai_result = analyze_media(saved_path, media_type)

        with get_db() as conn:
            cursor = conn.execute(
                """
                INSERT INTO MediaScans (
                    user_id, file_name, media_type, file_hash,
                    deepfake_probability, authenticity_score, risk_level, confidence, status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session["user_id"],
                    os.path.basename(saved_path),
                    media_type,
                    file_hash,
                    ai_result["deepfake_probability"],
                    ai_result["authenticity_score"],
                    ai_result["risk_level"],
                    ai_result["confidence"],
                    ai_result["status"],
                ),
            )
            scan_id = cursor.lastrowid

        return jsonify(
            {
                "ok": True,
                "scan_id": scan_id,
                "file_name": os.path.basename(saved_path),
                "media_type": media_type,
                "deepfake_probability": ai_result["deepfake_probability"],
                "authenticity_score": ai_result["authenticity_score"],
                "risk_level": ai_result["risk_level"],
                "confidence": ai_result["confidence"],
                "status": ai_result["status"],
                "frames_analyzed": ai_result["frames_analyzed"],
            }
        )

    @app.route("/admin")
    @admin_required
    def admin_dashboard():
        with get_db() as conn:
            total_users = conn.execute("SELECT COUNT(*) FROM Users").fetchone()[0]
            total_attempts = conn.execute("SELECT COUNT(*) FROM LoginAttempts").fetchone()[0]
            total_scans = conn.execute("SELECT COUNT(*) FROM MediaScans").fetchone()[0]
            high_risk_count = conn.execute(
                "SELECT COUNT(*) FROM LoginAttempts WHERE status = 'high_risk_blocked'"
            ).fetchone()[0]
            recent_alerts = conn.execute(
                """
                SELECT id, user_id, deepfake_probability, risk_score, status, timestamp
                FROM LoginAttempts
                WHERE status IN ('high_risk_blocked', 'registration_rejected_deepfake')
                ORDER BY id DESC
                LIMIT 10
                """
            ).fetchall()

            users = conn.execute(
                "SELECT id, name, email, is_blocked, authenticity_score FROM Users ORDER BY id DESC"
            ).fetchall()

            flagged_uploads = conn.execute(
                """
                SELECT ms.id, ms.user_id, ms.file_name, ms.media_type, ms.deepfake_probability,
                       ms.authenticity_score, ms.risk_level, ms.confidence, ms.status, ms.created_at,
                       u.email AS user_email
                FROM MediaScans ms
                LEFT JOIN Users u ON u.id = ms.user_id
                WHERE ms.risk_level IN ('HIGH', 'MEDIUM')
                ORDER BY ms.id DESC
                LIMIT 20
                """
            ).fetchall()

        return render_template(
            "admin.html",
            total_users=total_users,
            total_attempts=total_attempts,
            total_scans=total_scans,
            high_risk_count=high_risk_count,
            recent_alerts=recent_alerts,
            users=users,
            flagged_uploads=flagged_uploads,
        )

    @app.route("/admin/block-user/<int:user_id>", methods=["POST"])
    @admin_required
    def block_user(user_id: int):
        if user_id == session.get("user_id"):
            return jsonify({"ok": False, "message": "Admin cannot block own account."}), 400

        with get_db() as conn:
            user = conn.execute("SELECT is_blocked FROM Users WHERE id = ?", (user_id,)).fetchone()
            if not user:
                return jsonify({"ok": False, "message": "User not found."}), 404

            new_status = 0 if user["is_blocked"] else 1
            conn.execute("UPDATE Users SET is_blocked = ? WHERE id = ?", (new_status, user_id))

        return jsonify({"ok": True, "is_blocked": bool(new_status)})

    @app.route("/admin/report/<int:scan_id>.pdf")
    @admin_required
    def export_report(scan_id: int):
        with get_db() as conn:
            scan = conn.execute(
                """
                SELECT ms.id, ms.file_name, ms.media_type, ms.file_hash, ms.deepfake_probability,
                       ms.authenticity_score, ms.risk_level, ms.confidence, ms.status, ms.created_at,
                       u.email AS user_email
                FROM MediaScans ms
                LEFT JOIN Users u ON u.id = ms.user_id
                WHERE ms.id = ?
                """,
                (scan_id,),
            ).fetchone()

        if not scan:
            return redirect(url_for("admin_dashboard"))

        pdf_buffer = BytesIO()
        pdf = canvas.Canvas(pdf_buffer)
        pdf.setTitle(f"DeepTrust_Forensic_Report_{scan_id}")

        lines = [
            "DeepTrust AI - Forensic Report",
            f"Report ID: {scan['id']}",
            f"Generated At: {datetime.utcnow().isoformat()} UTC",
            f"User: {scan['user_email'] or 'N/A'}",
            f"File Name: {scan['file_name']}",
            f"Media Type: {scan['media_type']}",
            f"Deepfake Probability: {scan['deepfake_probability']}%",
            f"Authenticity Score: {scan['authenticity_score']}%",
            f"Risk Level: {scan['risk_level']}",
            f"Model Confidence: {scan['confidence']}%",
            f"Status: {scan['status']}",
            f"Timestamp: {scan['created_at']}",
            f"SHA256 Hash: {scan['file_hash']}",
            "Model Version: Prototype-Sim-v1",
        ]

        y = 800
        for line in lines:
            pdf.drawString(50, y, line)
            y -= 24

        pdf.save()
        pdf_buffer.seek(0)

        return send_file(
            pdf_buffer,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"forensic_report_{scan_id}.pdf",
        )

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login_page"))

    return app


def get_db() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS Users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                face_signature TEXT NOT NULL,
                authenticity_score REAL NOT NULL,
                is_blocked INTEGER NOT NULL DEFAULT 0,
                last_login_ip TEXT,
                last_device_fingerprint TEXT,
                last_login_locale TEXT,
                last_login_at DATETIME
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS LoginAttempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                deepfake_probability REAL NOT NULL,
                face_match_score REAL NOT NULL,
                risk_score REAL NOT NULL,
                status TEXT NOT NULL,
                ip_address TEXT,
                device_fingerprint TEXT,
                suspicious_score REAL NOT NULL DEFAULT 0,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES Users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS MediaScans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                file_name TEXT NOT NULL,
                media_type TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                deepfake_probability REAL NOT NULL,
                authenticity_score REAL NOT NULL,
                risk_level TEXT NOT NULL,
                confidence REAL NOT NULL,
                status TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES Users(id)
            )
            """
        )

        ensure_schema_updates(conn)


def ensure_schema_updates(conn: sqlite3.Connection) -> None:
    users_columns = {row["name"] for row in conn.execute("PRAGMA table_info(Users)").fetchall()}
    if "is_blocked" not in users_columns:
        conn.execute("ALTER TABLE Users ADD COLUMN is_blocked INTEGER NOT NULL DEFAULT 0")
    if "last_login_ip" not in users_columns:
        conn.execute("ALTER TABLE Users ADD COLUMN last_login_ip TEXT")
    if "last_device_fingerprint" not in users_columns:
        conn.execute("ALTER TABLE Users ADD COLUMN last_device_fingerprint TEXT")
    if "last_login_locale" not in users_columns:
        conn.execute("ALTER TABLE Users ADD COLUMN last_login_locale TEXT")
    if "last_login_at" not in users_columns:
        conn.execute("ALTER TABLE Users ADD COLUMN last_login_at DATETIME")

    attempts_columns = {row["name"] for row in conn.execute("PRAGMA table_info(LoginAttempts)").fetchall()}
    if "ip_address" not in attempts_columns:
        conn.execute("ALTER TABLE LoginAttempts ADD COLUMN ip_address TEXT")
    if "device_fingerprint" not in attempts_columns:
        conn.execute("ALTER TABLE LoginAttempts ADD COLUMN device_fingerprint TEXT")
    if "suspicious_score" not in attempts_columns:
        conn.execute("ALTER TABLE LoginAttempts ADD COLUMN suspicious_score REAL NOT NULL DEFAULT 0")


def seed_admin_user(app: Flask) -> None:
    email = app.config["ADMIN_EMAIL"].lower()
    password = app.config["ADMIN_PASSWORD"]

    if find_user_by_email(email):
        return

    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO Users (name, email, password_hash, face_signature, authenticity_score)
            VALUES (?, ?, ?, ?, ?)
            """,
            ("System Admin", email, password_hash, "admin-face-signature", 99.9),
        )


def find_user_by_email(email: str):
    with get_db() as conn:
        return conn.execute("SELECT * FROM Users WHERE email = ?", (email,)).fetchone()


def is_allowed_file(filename: str, allowed_extensions: set[str]) -> bool:
    if "." not in filename:
        return False
    extension = filename.rsplit(".", 1)[1].lower()
    return extension in allowed_extensions


def save_uploaded_file(file_storage, prefix: str) -> str:
    secure_name = secure_filename(file_storage.filename)
    extension = secure_name.rsplit(".", 1)[1].lower()
    filename = f"{prefix}_{secrets.token_hex(6)}.{extension}"
    destination = os.path.join(UPLOAD_DIR, filename)
    file_storage.save(destination)
    return destination


def hash_file(file_path: str) -> str:
    file_hash = hashlib.sha256()
    with open(file_path, "rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(8192), b""):
            file_hash.update(chunk)
    return file_hash.hexdigest()


def detect_media_type(filename: str) -> str:
    extension = filename.rsplit(".", 1)[1].lower()
    if extension in ALLOWED_IMAGE_EXT:
        return "image"
    if extension in ALLOWED_VIDEO_EXT:
        return "video"
    return "audio"


def calculate_suspicious_pattern_score(user_id: int) -> float:
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT status FROM LoginAttempts
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT 5
            """,
            (user_id,),
        ).fetchall()

    if not rows:
        return 8.0

    weighted = 0.0
    for row in rows:
        status = row["status"]
        if status in {"high_risk_blocked", "registration_rejected_deepfake"}:
            weighted += 26
        elif status in {"otp_required", "deepfake_detected_warning"}:
            weighted += 15
        else:
            weighted += 4

    return round(min(100.0, weighted / len(rows) * 2), 2)


def calculate_failed_attempts_score(user_id: int) -> float:
    with get_db() as conn:
        total_failed = conn.execute(
            """
            SELECT COUNT(*)
            FROM LoginAttempts
            WHERE user_id = ? AND status = 'failed_credentials'
            ORDER BY id DESC
            LIMIT 5
            """,
            (user_id,),
        ).fetchone()[0]

    return round(min(100.0, total_failed * 20.0), 2)


def save_base64_frame(frame_data: str) -> str:
    if "," in frame_data:
        frame_data = frame_data.split(",", 1)[1]

    image_bytes = base64.b64decode(frame_data)
    filename = f"live_{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}_{secrets.token_hex(5)}.jpg"
    file_path = os.path.join(UPLOAD_DIR, filename)

    with open(file_path, "wb") as frame_file:
        frame_file.write(image_bytes)

    return file_path


def log_attempt(
    user_id,
    deepfake_probability: float,
    face_match_score: float,
    risk_score: float,
    status: str,
    ip_address: str | None = None,
    device_fingerprint: str | None = None,
    suspicious_score: float = 0,
) -> int:
    with get_db() as conn:
        cursor = conn.execute(
            """
            INSERT INTO LoginAttempts (
                user_id, deepfake_probability, face_match_score, risk_score, status,
                ip_address, device_fingerprint, suspicious_score
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                deepfake_probability,
                face_match_score,
                risk_score,
                status,
                ip_address,
                device_fingerprint,
                suspicious_score,
            ),
        )
        return cursor.lastrowid


if __name__ == "__main__":
    flask_app = create_app()
    flask_app.run(debug=True)
