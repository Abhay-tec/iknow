# Simple Flask tracker service
# Requirements: pip install -r requirements.txt

import logging
import uuid
from datetime import datetime
import os
import hashlib
import secrets

from flask import Flask, Response, jsonify, redirect, request
from prometheus_client import CONTENT_TYPE_LATEST, Counter, generate_latest
from twilio.rest import Client
from websocket import create_connection
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_httpauth import HTTPTokenAuth
from marshmallow import Schema, fields, ValidationError
from flask_cors import CORS

app = Flask(__name__)
trackers = {}
otp_cache = {}  # For storing temporary OTPs
screen_shares = {}  # For tracking active screen shares
token_cache = {}  # For storing short-lived tokens

# Security constants
MAX_TRACKERS = 10_000
RATE_LIMIT_PER_MINUTE = 20
RATE_LIMIT_PER_HOUR = 200
OTP_EXPIRY_SECONDS = 300
TOKEN_EXPIRY_SECONDS = 3600

# Twilio credentials (set as environment variables in production)
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "your_sid")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "your_token")
TWILIO_PHONE = os.getenv("TWILIO_PHONE", "+1234567890")

# Screen-share WebSocket endpoint (placeholder)
SCREEN_WS_URL = os.getenv("SCREEN_WS_URL", "wss://screen-sharing-server.com/connect")

# Authentication
auth = HTTPTokenAuth(scheme='Bearer')
API_BEARER_TOKEN = os.getenv("API_BEARER_TOKEN")

# Metrics
TRACK_REQUESTS = Counter(
    "track_requests_total", "Number of tracking requests", ["method", "status"]
)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

# Initialize Twilio client (lazy init to allow running without creds)
try:
    twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
except Exception:
    twilio_client = None

# Rate limiting
limiter_storage = os.getenv("RATELIMIT_STORAGE_URI") or None
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[f"{RATE_LIMIT_PER_MINUTE} per minute"],
    storage_uri=limiter_storage,
)

# CORS
cors_origins = os.getenv("CORS_ORIGINS", "*")
CORS(app, resources={r"/*": {"origins": cors_origins.split(",")}})

CSRF_COOKIE_NAME = "csrf_token"


def _issue_csrf(resp):
    """Ensure a CSRF cookie exists on the response."""
    if request.cookies.get(CSRF_COOKIE_NAME):
        return resp
    token = secrets.token_hex(16)
    resp.set_cookie(
        CSRF_COOKIE_NAME,
        token,
        max_age=60 * 60 * 24 * 365,
        samesite="Lax",
        secure=request.is_secure,
        httponly=False,
    )
    return resp


@app.before_request
def enforce_csrf():
    """Simple double-submit CSRF check for state-changing methods."""
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        sent = request.headers.get("X-CSRF-Token")
        cookie = request.cookies.get(CSRF_COOKIE_NAME)
        if not cookie or sent != cookie:
            return jsonify({"error": "csrf_failed"}), 403


@app.after_request
def add_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=()"
    return _issue_csrf(resp)

def client_ip() -> str:
    """Return best-guess client IP, preferring X-Forwarded-For if present."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr

def is_opted_out() -> bool:
    """Check opt-out via cookie or DNT header."""
    if request.cookies.get("tracking_opt_out") == "true":
        return True
    if request.headers.get("DNT") == "1":
        return True
    return False

def generate_otp() -> str:
    """Generate a random 6-digit OTP."""
    import random
    return ''.join(str(random.randint(0, 9)) for _ in range(6))

def generate_token() -> str:
    """Generate a cryptographically secure token."""
    return secrets.token_hex(32)

def hash_token(token: str) -> str:
    """Hash a token for storage."""
    return hashlib.sha256(token.encode()).hexdigest()

def send_sms(phone: str, message: str) -> bool:
    """Send SMS using Twilio."""
    if not twilio_client:
        logger.error("Twilio client not configured")
        return False
    try:
        twilio_client.messages.create(
            body=message,
            from_=TWILIO_PHONE,
            to=phone
        )
        return True
    except Exception as e:
        logger.error(f"SMS sending failed: {e}")
        return False

# Input validation schemas
class PhoneSchema(Schema):
    phone = fields.Str(required=True)
    code = fields.Str(required=True)

class ScreenShareSchema(Schema):
    tracker_id = fields.Str(required=True)

phone_schema = PhoneSchema()
screen_share_schema = ScreenShareSchema()


@app.route("/", methods=["GET"])
def root():
    """Simple landing route so '/' doesn't 404."""
    return jsonify(
        {
            "status": "ok",
            "message": "Tracker service running",
            "try": {
                "track_post": "/track/demo-user  (POST JSON)",
                "track_get_redirect": "/track/demo-user  (GET)",
                "metrics": "/metrics",
            },
        }
    )


@app.route("/track/<user_id>", methods=["POST", "GET"])
@limiter.limit(f"{RATE_LIMIT_PER_HOUR} per hour")
def track(user_id):
    try:
        if is_opted_out():
            TRACK_REQUESTS.labels(request.method, "opted_out").inc()
            return jsonify({"status": "opted_out"}), 200

        if len(trackers) > MAX_TRACKERS:
            TRACK_REQUESTS.labels(request.method, "rate_limited").inc()
            return jsonify({"error": "rate limit exceeded"}), 429

        tracker_id = str(uuid.uuid4())
        payload = request.get_json(silent=True) or {}

        trackers[tracker_id] = {
            "user": user_id,
            "ip": client_ip(),
            "ua": request.headers.get("User-Agent"),
            "timestamp": datetime.utcnow().isoformat(),
            "data": payload,
        }

        logger.info(
            "tracked user=%s tracker_id=%s ip=%s ua=%s keys=%s",
            user_id,
            tracker_id,
            trackers[tracker_id]["ip"],
            trackers[tracker_id]["ua"],
            list(payload.keys()),
        )

        TRACK_REQUESTS.labels(request.method, "success").inc()

        if request.method == "GET":
            # Preserve existing redirect behavior for GET requests.
            return redirect("https://example.com")

        # Return tracker_id so callers can fetch the data later.
        return jsonify({"tracker_id": tracker_id}), 201
    except Exception as exc:  # noqa: BLE001
        logger.error("Tracking error: %s", exc, exc_info=True)
        TRACK_REQUESTS.labels(request.method, "error").inc()
        return jsonify({"error": "internal error"}), 500

@app.route("/verify-phone", methods=["POST"])
@limiter.limit(f"{RATE_LIMIT_PER_MINUTE} per minute")
def verify_phone():
    """Verify phone number using OTP."""
    try:
        data = phone_schema.load(request.json)
    except ValidationError as err:
        return jsonify(err.messages), 400
        
    phone = data["phone"]
    if not phone:
        return jsonify({"error": "phone number required"}), 400
        
    # Generate and send OTP
    otp = generate_otp()
    if not send_sms(phone, f"Your verification code: {otp}"):
        return jsonify({"error": "failed to send SMS"}), 500
        
    # Store OTP temporarily with expiration
    otp_cache[phone] = {
        "otp": otp,
        "created_at": datetime.utcnow().isoformat(),
        "expiry": datetime.utcnow().timestamp() + OTP_EXPIRY_SECONDS
    }
    return jsonify({"status": "sent"})

@app.route("/validate-otp", methods=["POST"])
@limiter.limit(f"{RATE_LIMIT_PER_MINUTE} per minute")
def validate_otp():
    """Validate the provided OTP."""
    try:
        data = phone_schema.load(request.json)
    except ValidationError as err:
        return jsonify(err.messages), 400
        
    phone = data["phone"]
    code = data["code"]
    
    if not phone or not code:
        return jsonify({"error": "phone and code required"}), 400
        
    cached_data = otp_cache.get(phone)
    if not cached_data:
        return jsonify({"error": "invalid OTP"}), 401
        
    # Check expiration
    if datetime.utcnow().timestamp() > cached_data["expiry"]:
        del otp_cache[phone]
        return jsonify({"error": "OTP expired"}), 401
        
    # Verify OTP
    if cached_data["otp"] != code:
        return jsonify({"error": "invalid OTP"}), 401
        
    # Remove OTP after validation
    del otp_cache[phone]
    return jsonify({"status": "verified"})

@app.route("/start-screen-share", methods=["POST"])
@limiter.limit(f"{RATE_LIMIT_PER_MINUTE} per minute")
def start_screen_share():
    """Start a screen sharing session."""
    try:
        data = screen_share_schema.load(request.json)
    except ValidationError as err:
        return jsonify(err.messages), 400
        
    tracker_id = data["tracker_id"]
    if not tracker_id or tracker_id not in trackers:
        return jsonify({"error": "invalid tracker ID"}), 400
        
    # Create WebSocket connection for screen sharing
    try:
        ws_conn = create_connection(SCREEN_WS_URL)
    except Exception as exc:
        logger.error("Failed to start screen share: %s", exc, exc_info=True)
        return jsonify({"error": "screen share unavailable"}), 503
    
    # Store active screen share with expiration
    screen_shares[tracker_id] = {
        "connection": ws_conn,
        "created_at": datetime.utcnow().isoformat(),
        "expiry": datetime.utcnow().timestamp() + TOKEN_EXPIRY_SECONDS
    }
    
    # Generate and store a token for secure access
    token = generate_token()
    token_hash = hash_token(token)
    token_cache[token_hash] = {
        "tracker_id": tracker_id,
        "created_at": datetime.utcnow().isoformat(),
        "expiry": datetime.utcnow().timestamp() + TOKEN_EXPIRY_SECONDS
    }
    
    return jsonify({"status": "connected", "token": token})

@app.route("/get-info/<tracker_id>")
@limiter.limit(f"{RATE_LIMIT_PER_MINUTE} per minute")
def get_info(tracker_id):
    if API_BEARER_TOKEN:
        provided = request.headers.get("Authorization", "").replace("Bearer ", "")
        if provided != API_BEARER_TOKEN:
            return jsonify({"error": "unauthorized"}), 401
    info = trackers.get(tracker_id)
    if not info:
        TRACK_REQUESTS.labels("GET", "not_found").inc()
        return jsonify({"error": "not found"}), 404
    return jsonify(info)

@app.route("/opt-out", methods=["POST"])
@limiter.limit(f"{RATE_LIMIT_PER_MINUTE} per minute")
def opt_out():
    """Set an opt-out cookie; caller should also stop sending tracking data."""
    resp = jsonify({"status": "opted_out"})
    secure_cookie = request.is_secure or request.headers.get(
        "X-Forwarded-Proto", ""
    ).lower() == "https"
    resp.set_cookie(
        "tracking_opt_out",
        "true",
        max_age=60 * 60 * 24 * 365,
        samesite="Lax",
        secure=secure_cookie,
        httponly=False,
    )
    return resp

@app.route("/metrics")
def metrics():
    """Prometheus scrape endpoint."""
    if API_BEARER_TOKEN:
        provided = request.headers.get("Authorization", "").replace("Bearer ", "")
        if provided != API_BEARER_TOKEN:
            return jsonify({"error": "unauthorized"}), 401
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

if __name__ == "__main__":
    # Do not use debug in production; behind a reverse proxy/HTTPS is recommended.
    app.run(host="0.0.0.0", port=5000, debug=False)
