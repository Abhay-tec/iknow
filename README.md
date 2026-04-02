# Tracker Service

## Setup
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
gunicorn -b 0.0.0.0:5000 main:app
```

## Docker
```bash
docker build -t tracker .
docker run -p 5000:5000 tracker
```

Required env vars for optional features:
- `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_PHONE` for SMS OTP.
- `SCREEN_WS_URL` if you change the screen-share WebSocket endpoint.

## Endpoints
- `POST /track/<user_id>`: store tracking event, returns `tracker_id`.
- `GET /track/<user_id>`: tracks and redirects to `https://example.com`.
- `GET /get-info/<tracker_id>`: retrieve stored event.
- `POST /opt-out`: sets `tracking_opt_out` cookie for 1 year.
- `GET /metrics`: Prometheus metrics.
- `POST /verify-phone`: sends OTP via SMS.
- `POST /validate-otp`: validates OTP.
- `POST /start-screen-share`: placeholder to initiate WebSocket screen-share session.

## HTTPS & Reverse Proxy
- Terminate TLS with Nginx/Load Balancer (Let's Encrypt certbot on Ubuntu: `sudo certbot --nginx -d your.domain.com`).
- Forward headers: `X-Forwarded-For`, `X-Forwarded-Proto`, `Host`.
- Ensure the proxy listens on 80/443 and proxies to `http://127.0.0.1:5000`.

## Privacy
See `PRIVACY.md`. Banner + opt-out implemented in `index.html`; server respects `DNT` and opt-out cookie. Update the contact email and any processors you add.
