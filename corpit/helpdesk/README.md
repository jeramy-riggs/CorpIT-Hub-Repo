# ITAM HelpDesk Dashboard

A production-ready internal HelpDesk dashboard for ITAM/CorpIT teams, integrating with Okta to provide at-a-glance visibility into SSO application usage, user account health, security events, and actionable support insights.

---

## Architecture Overview

```
┌─────────────┐     ┌────────────────────────────────────┐     ┌────────────┐
│  Browser     │────▶│  nginx (existing, TLS on :443)      │────▶│  Express   │
│  React SPA   │     │  itam.nrpi.local/helpdesk/ ──────── │     │  :3002     │
└─────────────┘     └────────────────────────────────────┘     └─────┬──────┘
                                                              │
                                                   ┌──────────┴──────────┐
                                                   │                     │
                                             ┌─────▼─────┐     ┌────────▼────────┐
                                             │  SQLite    │     │  Okta APIs      │
                                             │  (cache)   │     │  (synced every  │
                                             │  data/     │     │   30 minutes)   │
                                             └───────────┘     └─────────────────┘
```

### Tech Stack

| Layer     | Technology           | Why                                                       |
|-----------|----------------------|-----------------------------------------------------------|
| Frontend  | React 18 + Recharts  | Fast SPA, rich charting, easy to maintain                  |
| Backend   | Express.js (Node 18) | Lightweight, fast, excellent Okta SDK support              |
| Database  | SQLite (better-sqlite3) | Zero-config, fast reads, perfect for caching < 100K rows |
| Auth      | Okta API Token or OAuth 2.0 | Flexible — token for dev, OAuth for production      |
| Proxy     | nginx                | TLS termination (HTTPS 443), caching, standard enterprise choice |
| Process   | systemd              | Auto-restart, journald logging, security hardening        |

### Why This Design

- **SQLite cache** — The dashboard never queries Okta on every page load. A background sync job (cron, every 30 min) pulls data from Okta and stores it locally. Pages load in < 200ms.
- **Single-server deployment** — Runs on one Ubuntu box with zero external dependencies (no Redis, no Postgres, no Docker required).
- **Separation of concerns** — The sync service is independent of the API layer. If Okta is temporarily unreachable, cached data continues to serve.

---

## Features

### Core
- **KPI Summary Cards** — Total/active/locked/suspended users, password status, app count, failed logins
- **User Account Browser** — Searchable, sortable, filterable table with detail modal (assigned apps, activity log)
- **SSO Application Insights** — Most/least/unused apps, sign-on mode breakdown, assignment counts
- **Security & Activity Logs** — Failed logins with IP/geolocation, locked accounts, inactive users
- **Password Expiry Tracking** — Estimated expiry based on last change + policy max age
- **Login Trend Charts** — 7-day success/failure area chart
- **Event Type Heatmap** — Top Okta event types with frequency bars

### HelpDesk-Specific
- Locked-out users widget (immediate action)
- Password expiring soon widget (proactive outreach)
- Inactive user list (license reclamation candidates)
- Failed login log with IP filtering (security investigation)
- Per-user drill-down with assigned apps + recent audit events
- Unused app identification (cost optimization)
- Manual sync trigger from the UI

---

## Dashboard Layout

```
┌─ Sidebar ─────────────────┬─ Main Content ─────────────────────────────────┐
│                           │                                                 │
│  ITAM HelpDesk            │  Page Header                                    │
│  Dashboard v1.0           │                                                 │
│                           │  ┌─── KPI Cards ──────────────────────────────┐ │
│  ○ Overview               │  │ Total │ Active │ Locked │ PW Soon │ Apps   │ │
│  ○ Users                  │  └───────────────────────────────────────────┘ │
│  ○ Applications           │                                                 │
│  ○ Security & Logs        │  ┌─ Login Trend ──────┐ ┌─ User Breakdown ──┐  │
│  ○ Settings               │  │  Area Chart (7d)   │ │  Pie Chart        │  │
│                           │  └────────────────────┘ └───────────────────┘  │
│  [Sync Now]               │                                                 │
│                           │  ┌─ Locked Out ───────┐ ┌─ PW Expiring ─────┐  │
│  Last sync: 5m ago        │  │  Table              │ │  Table            │  │
│  142 users · 38 apps      │  └────────────────────┘ └───────────────────┘  │
└───────────────────────────┴─────────────────────────────────────────────────┘
```

---

## Okta Setup Guide

### A. Quick Start — API Token (Recommended for Initial Testing)

1. Log in to **Okta Admin Console** as a Super Admin or Org Admin.
2. Navigate to **Security → API → Tokens**.
3. Click **Create Token**, name it `HelpDesk Dashboard - Dev`.
4. **Copy the token immediately** — it is only shown once.
5. In your `.env` file:
   ```
   OKTA_ORG_URL=https://auction.okta.com
   OKTA_API_TOKEN=00abc123...your-token-here
   OKTA_AUTH_METHOD=token
   ```
6. The token inherits the permissions of the admin who created it.
   - **Minimum role:** Read-Only Administrator
   - This grants read access to users, apps, logs, and groups.
7. Test: `curl -H "Authorization: SSWS YOUR_TOKEN" https://auction.okta.com/api/v1/org`

### B. Production — OAuth 2.0 Service App

1. In Okta Admin Console, go to **Applications → Create App Integration**.
2. Select **API Services** → Next.
3. Name it `HelpDesk Dashboard`.
4. Under **Client Credentials**, choose **Public key / Private key**.
5. Click **Generate new key** → download the private key as PEM.
6. Note the **Client ID** and the **Key ID (kid)** from the JWKS.
7. Go to **Okta Admin → Security → API** and under the `default` authorization server, grant these scopes to the app:
   - `okta.users.read`
   - `okta.apps.read`
   - `okta.logs.read`
   - `okta.groups.read`
8. In your `.env`:
   ```
   OKTA_ORG_URL=https://auction.okta.com
   OKTA_CLIENT_ID=0oa...your-client-id
   OKTA_PRIVATE_KEY_PATH=./config/okta-private-key.pem
   OKTA_KEY_ID=your-key-id
   OKTA_AUTH_METHOD=oauth
   ```
9. **Protect the PEM file:** `chmod 600 config/okta-private-key.pem`

### C. Recommendation

| Phase          | Method    | Why                                                    |
|----------------|-----------|--------------------------------------------------------|
| Dev / Testing  | API Token | Fast to set up, immediate results, no key management   |
| Production     | OAuth 2.0 | Scoped permissions, no admin-level token, auto-expiry  |

---

## Deployment Guide (Ubuntu 22.04 + nginx)

### 1. Prerequisites

```bash
# Install Node.js 18+
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs nginx build-essential

# Create service user
sudo useradd -r -s /bin/false helpdesk
```

### 2. Deploy the Application

```bash
# Copy project to /opt
sudo mkdir -p /opt/helpdesk-dashboard
sudo cp -r . /opt/helpdesk-dashboard/
cd /opt/helpdesk-dashboard

# Install dependencies
npm run install:all

# Build frontend
npm run build

# Create data + logs directories
mkdir -p data logs
sudo chown -R helpdesk:helpdesk /opt/helpdesk-dashboard

# Configure environment
cp .env.example .env
nano .env  # Fill in your Okta credentials

# Protect secrets
chmod 600 .env
chmod 600 config/okta-private-key.pem  # if using OAuth
```

### 3. Initialize Database

```bash
sudo -u helpdesk node scripts/setup-db.js
```

### 4. Configure nginx

The dashboard runs as a subpath (`/helpdesk/`) on the existing `itam.nrpi.local` site,
reusing the existing TLS certificate at `/etc/ssl/certs/itam.crt`.

```bash
# Back up original nginx config
sudo cp /etc/nginx/sites-enabled/default /etc/nginx/sites-enabled/default.bak

# Deploy merged config (existing ITAM app + HelpDesk dashboard)
sudo cp config/nginx-default-merged.conf /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
```

### 5. Configure systemd

```bash
sudo cp config/helpdesk-dashboard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now helpdesk-dashboard
sudo systemctl status helpdesk-dashboard
```

### 6. Verify

```bash
curl -k https://itam.nrpi.local/helpdesk/api/health
# Should return: {"status":"ok", ...}
```

Then open **https://itam.nrpi.local/helpdesk/** in a browser.

---

## Security Plan

### Secrets Storage
- `.env` file with `chmod 600`, owned by the `helpdesk` user
- PEM keys stored in `config/` with `chmod 600`
- Never committed to git (`.gitignore` enforced)

### Access Control
- systemd runs as a dedicated `helpdesk` user (no root)
- `NoNewPrivileges=true` and `ProtectSystem=strict` in the service unit
- nginx restricts access to the internal network by default (bind to `server_name`)

### Least Privilege
- Okta API Token: create with a **Read-Only Admin** role
- OAuth scopes: only `*.read` scopes, no write access
- SQLite database: read-write only by the service user

### Logging & Audit
- Application logs: `logs/app.log` and `logs/error.log` (rotated at 5 MB, 5 files)
- nginx logs: `/var/log/nginx/helpdesk-access.log`
- systemd journal: `journalctl -u helpdesk-dashboard`
- Sync history stored in the database (`sync_status` table)

### Rate Limiting
- Express rate limiter: 120 requests/minute per IP on `/api/*`
- Helmet.js security headers enabled
- Content Security Policy configured

---

## Known Okta API Limitations

1. **Password expiry** — Okta does not expose a direct `passwordExpiresAt` field for most orgs. This dashboard estimates expiry by adding the configured `PASSWORD_MAX_AGE_DAYS` to the `passwordChanged` timestamp. Adjust this value to match your actual Okta password policy.

2. **App usage activity** — Okta does not provide a "last used" timestamp per app per user. The dashboard uses two complementary approaches:
   - **Assignment count** — apps with 0 assigned users are flagged as unused.
   - **System log events** — `app.auth.*` events indicate actual SSO usage. Apps with no auth events in the configured threshold period are candidates for review.

3. **System Logs retention** — Okta retains system logs for 90 days (varies by plan). The dashboard syncs the last 7 days per cycle but the SQLite cache accumulates historical data.

4. **Rate limits** — Okta imposes rate limits (varies by endpoint and plan). The sync service handles 429 responses with automatic backoff using the `x-rate-limit-reset` header.

---

## Project Structure

```
helpdesk-dashboard/
├── server/                   # Express backend
│   ├── index.js              # Entry point
│   ├── routes/               # API route handlers
│   │   ├── dashboard.js      # KPI summary, charts, action lists
│   │   ├── users.js          # User listing, search, detail
│   │   ├── apps.js           # App listing, usage summary
│   │   └── health.js         # Health check, sync control
│   ├── services/
│   │   ├── okta-client.js    # Okta API client (token + OAuth)
│   │   └── sync-service.js   # Data sync orchestration
│   ├── db/
│   │   └── database.js       # SQLite schema + data access
│   └── utils/
│       └── logger.js         # Winston logger
├── client/                   # React frontend
│   ├── public/index.html
│   └── src/
│       ├── App.js            # Layout, routing, sidebar
│       ├── index.js           # Entry point
│       ├── index.css          # Global styles
│       ├── hooks/useApi.js    # Data fetching + formatting utils
│       └── pages/
│           ├── Dashboard.js   # Overview with KPIs + charts
│           ├── UsersPage.js   # User table + detail modal
│           ├── AppsPage.js    # App insights + listings
│           ├── SecurityPage.js # Logs + security widgets
│           └── SettingsPage.js # Health, connectivity, sync
├── config/
│   ├── nginx-helpdesk.conf   # nginx site config
│   └── helpdesk-dashboard.service # systemd unit
├── scripts/
│   ├── setup-db.js           # DB initialization
│   └── sync-okta.js          # Manual sync
├── .env.example              # Environment template
├── .gitignore
├── package.json
└── README.md
```

---

## Development

```bash
# Install everything
npm run install:all

# Run in dev mode (server + client with hot reload)
npm run dev

# Server runs at http://localhost:3001
# Client dev server at http://localhost:3000 (proxies API to 3001)
```

---

## Environment Variables Reference

| Variable                      | Default          | Description                                    |
|-------------------------------|------------------|------------------------------------------------|
| `PORT`                        | `3001`           | Express server port                            |
| `NODE_ENV`                    | `development`    | Environment mode                               |
| `OKTA_ORG_URL`               | —                | Your Okta org URL                              |
| `OKTA_API_TOKEN`             | —                | API token (for token auth)                     |
| `OKTA_CLIENT_ID`            | —                | OAuth client ID (for oauth auth)               |
| `OKTA_PRIVATE_KEY_PATH`     | —                | Path to PEM private key                        |
| `OKTA_KEY_ID`               | —                | JWK key ID                                     |
| `OKTA_AUTH_METHOD`           | `token`          | `token` or `oauth`                             |
| `SYNC_CRON`                  | `*/30 * * * *`   | Sync schedule (cron expression)                |
| `UNUSED_APP_THRESHOLD_DAYS` | `90`             | Days of inactivity to flag app as unused       |
| `PASSWORD_EXPIRY_WARNING_DAYS` | `14`          | Days before expiry to flag password            |
| `PASSWORD_MAX_AGE_DAYS`     | `90`             | Assumed password policy max age                |
| `SESSION_SECRET`             | —                | Secret for session signing                     |
| `LOG_LEVEL`                  | `info`           | Winston log level                              |
