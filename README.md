# Crowdefik

Control panel for **CrowdSec + Traefik** — built with FastAPI (backend) and React/Vite (frontend).

## Features

- List all Docker services exposed via Traefik
- See which routers have CrowdSec active (effective)
- **Enable / disable CrowdSec protection per router** without touching Docker labels or restarting containers (uses a Traefik file-provider override with a higher-priority router)
- Dashboard: decisions count, alert count, top attacker IPs, attack scenarios
- Decisions and alerts views (CrowdSec LAPI)
- Multi-user with role-based access:
  - **Admin** — full access
  - **Regular user** — sees only routers (and related alerts/decisions) they have been scoped to
- Integration settings page (Traefik URL + basic-auth, CrowdSec LAPI URL + API key) — secrets encrypted in SQLite
- Dark / light / system theme (respects `prefers-color-scheme` + manual override)
- Live dashboard via WebSocket (updates every 10 s)
- 2 h cache on Traefik/Docker data + manual refresh button

---

## Architecture

```
proxy (Docker network)
├── traefik          — reverse proxy
├── crowdsec         — LAPI + AppSec engine
├── crowdefik-backend  — FastAPI (reads Docker socket, calls Traefik & CrowdSec APIs)
└── crowdefik-frontend — Nginx serving React SPA + proxying /api & /ws
```

---

## Prerequisites

1. Docker network `proxy` already exists (same as your Traefik setup).
2. Traefik is using the **file provider** watching `/_data/apps/traefik/config/custom/` (already in your compose).
3. CrowdSec bouncer API key created (see below).

---

## 1 — Create a CrowdSec API key

Inside your CrowdSec container run:

```bash
docker exec crowdsec cscli bouncers add crowdefik-bouncer
```

Copy the generated API key — you will paste it in the Crowdefik Settings page after first login.

---

## 2 — Configure environment variables

```bash
cp .env.example .env
```

Edit `.env`:

```dotenv
CROWDEFIK_JWT_SECRET=<random 64-char string>
CROWDEFIK_APP_SECRET=<another random 32-char string>
CROWDEFIK_BOOTSTRAP_ADMIN_USERNAME=admin
CROWDEFIK_BOOTSTRAP_ADMIN_PASSWORD=<strong password>
```

> **Note:** `BOOTSTRAP_ADMIN_*` is only used on the **first start** when the database is empty. It creates the first admin account automatically.

Generate secure secrets on Linux/macOS:
```bash
openssl rand -hex 32   # run twice — once for JWT_SECRET, once for APP_SECRET
```

---

## 3 — Start

```bash
docker compose up -d --build
```

---

## 4 — Expose with Traefik (HTTPS)

Add labels to the `crowdefik-frontend` service in `docker-compose.yml`:

```yaml
labels:
  traefik.enable: "true"
  traefik.http.routers.crowdefik.rule: Host(`crowdefik.your-domain.tld`)
  traefik.http.routers.crowdefik.entrypoints: https
  traefik.http.routers.crowdefik.tls.certresolver: letsencrypt
  traefik.http.services.crowdefik.loadbalancer.server.port: 80
```

---

## 5 — First login

1. Open `https://crowdefik.your-domain.tld` (or `http://localhost:80` for local dev).
2. Log in with `admin` / the password you set in `.env`.
3. Go to **Settings** and fill in:
   - Traefik API URL: `http://traefik:8080`
   - Traefik basic-auth user/password (if you set one — from your `traefik.http.middlewares.auth.basicauth.users` label)
   - CrowdSec LAPI URL: `http://crowdsec:8080`
   - CrowdSec API key: (from step 1)
4. Save. The dashboard and services page will now populate.

---

## How the CrowdSec toggle works

Crowdefik **never modifies Docker labels**. Instead:

- **Disable CrowdSec on a router** → writes a YAML file in
  `/_data/apps/traefik/config/custom/crowdefik-overrides/<router>.yml`
  containing a new router with **priority = original + 10 000** (minimum 100 000)
  and **no `crowdsec@file` middleware**. Traefik picks it up automatically (file provider hot-reload).
- **Re-enable** → deletes that file. The high-priority router disappears and the original Docker-label router (with CrowdSec) takes over again.

The `crowdsec_effective` flag in the UI reflects reality: label is present **and** no bypass file exists.

---

## User management (Admin page)

- Create users and assign **router scopes** (exact Traefik router name, e.g. `myapp@docker`).
- Scoped users see **only** their routers in the Services page.
- Alerts/Decisions are filtered by a best-effort hostname match (extracted from the router Rule).
- Superusers see everything.

---

## Local development

**Backend:**
```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
CROWDEFIK_DATABASE_URL=sqlite:///./dev.db \
CROWDEFIK_BOOTSTRAP_ADMIN_USERNAME=admin \
CROWDEFIK_BOOTSTRAP_ADMIN_PASSWORD=admin \
uvicorn app.main:app --reload
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev   # proxies /api → http://127.0.0.1:8000
```

---

## Project structure

```
.
├── backend/
│   ├── app/
│   │   ├── api/           — FastAPI routers (auth, routers, dashboard, crowdsec, settings, admin, ws)
│   │   ├── core/          — security (JWT, bcrypt), cache, crypto (Fernet)
│   │   ├── integrations/  — Docker, Traefik, CrowdSec clients + Traefik override writer
│   │   ├── services/      — business logic (router view builder, scope filter)
│   │   ├── models.py      — SQLAlchemy models
│   │   ├── schemas.py     — Pydantic I/O schemas
│   │   ├── db.py          — SQLite session factory
│   │   ├── settings.py    — pydantic-settings config
│   │   └── main.py        — FastAPI app factory + lifespan
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── pages/         — Dashboard, Routers, Alerts, Decisions, Settings, Admin, Login
│   │   ├── components/    — Layout (nav, theme toggle, cache refresh)
│   │   ├── auth.tsx       — AuthContext (JWT in localStorage)
│   │   ├── theme.tsx      — ThemeContext (system/light/dark)
│   │   └── api.ts         — fetch wrapper + WebSocket URL helper
│   ├── nginx.conf
│   └── Dockerfile
├── docker-compose.yml
├── .env.example
└── traefik-docker-compose.yml   — reference Traefik stack
```
