# Zaharia Media Dashboard — Dockerized

This repo contains the Dockerization files for your Unraid dashboard.

## Project structure (expected)
```
zaharia-media-home/
├─ data/                # persists runtime data (mounted as volume)
├─ public/              # static assets (put your index.html here)
├─ app.mjs              # Node backend (Express)
├─ package.json         # (provided in this bundle)
├─ Dockerfile           # (provided in this bundle)
└─ docker-compose.yml   # (provided in this bundle)
```

> Place your existing `app.mjs` and everything under `public/` (including your `index.html`) next to these files.

## How to run (Unraid host or any Docker host)
```bash
docker compose build
docker compose up -d
```

- Open **http://192.168.1.182:8088/** (change the IP if your Unraid has a different LAN address).
- In the Unraid **Docker** tab you’ll see a custom icon and a **WebUI** button pointing to the local URL.

## Environment variables
If your app needs secrets (e.g., PLEX token, SAB API key), add them under `environment:` in `docker-compose.yml` or use a `.env` file and reference with `${VAR}`.

### SMTP (optional)
To enable email delivery for invites and password resets, set:

```
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=username
SMTP_PASS=password
SMTP_FROM=dashboard@example.com
APP_URL=http://192.168.1.182:8088
```

For Gmail, use your app-specific password and set:

```
SMTP_HOST=smtp.gmail.com
SMTP_PORT=465
SMTP_SECURE=true
SMTP_USER=you@gmail.com
SMTP_PASS=your-app-password
SMTP_FROM=you@gmail.com
```

The app will automatically strip any protocol (`smtp://`, `http://`), embedded port, or path from `SMTP_HOST`, default to TLS when using port 465, and enforce STARTTLS on port 587.

Every user must register with a unique email address. Password recovery links are sent to that email, so configure SMTP before inviting users.

## GitHub setup
1. Create a new GitHub repo (private or public).
2. Commit these files plus your `app.mjs`, `public/` contents, and optional `data/` (usually excluded).
3. Push to GitHub.
4. (Optional) Add a CI workflow later to build and push an image to GHCR or Docker Hub.
```

