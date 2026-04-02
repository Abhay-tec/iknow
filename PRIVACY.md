# Privacy & Data Collection

## What we collect
- User identifier passed in page script (`userId`).
- Device info: screen resolution, timezone, current URL, referrer.
- Network info: IP address (from request or `X-Forwarded-For`), user-agent.
- Timestamp of the request.

## Why we collect it
- Security and abuse monitoring.
- Basic analytics to understand usage and improve reliability.

## How long we keep it
- Stored in-memory only in this sample app; restart clears the data. In production, store only as long as necessary for the stated purposes.

## Sharing
- Data is not shared with third parties in this sample. If you add processors (e.g., log sinks, metrics backends), update this document to list them and the data they receive.

## Your choices
- Cookie banner lets users accept or decline tracking.
- "Do Not Track" (`DNT: 1`) is respected.
- Opt-out endpoint: POST `/opt-out` sets a `tracking_opt_out=true` cookie for one year. When present (or when DNT is set), tracking calls return `{"status": "opted_out"}` and no data is stored.

## Contact
- Add your contact or DPO email here.
