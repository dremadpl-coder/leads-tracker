# Deploy to the web (Render/Railway/Fly/Deta)

## Option A — Render (recommended: quick & simple)
1. Push this folder to a **GitHub** repo.
2. Create an account at **render.com** → New → Web Service → Connect your repo.
3. Environment:
   - Runtime: Python
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn app:app --timeout 120 --workers 2 --preload`
4. **Environment Variables** (Add in Render dashboard):
   - `SECRET_KEY` = a long random string
   - `ADMIN_EMAIL` = your email (e.g., you@yourcompany.com)
   - `ADMIN_PASSWORD` = a strong password for your first admin login
   - `DATABASE_URL` = Postgres URL (Render Postgres add-on) — or skip to use SQLite for testing
5. Deploy → Open the URL → Login with `ADMIN_EMAIL` and `ADMIN_PASSWORD`.

## Option B — Railway
1. Create a new Railway project from your GitHub repo.
2. Add a **PostgreSQL** plugin and copy its connection URL to `DATABASE_URL` env var.
3. Add the same `SECRET_KEY`, `ADMIN_EMAIL`, `ADMIN_PASSWORD` env vars.
4. Deploy. Railway will give you a public link.

## Option C — Fly.io
1. `fly launch` in this folder (requires Fly CLI), select Python, create app.
2. Provision **fly postgres** and set `DATABASE_URL` secret.
3. Set secrets: `fly secrets set SECRET_KEY=... ADMIN_EMAIL=... ADMIN_PASSWORD=...`
4. Deploy: `fly deploy`.

## Option D — Deta Space (SQLite ok for small teams)
1. Create a new Space app and upload this folder.
2. Start the app. For persistence across restarts, prefer Postgres (external) if you can.

---

### Important
- When `DATABASE_URL` is set, the app uses it (Postgres). Otherwise it falls back to local SQLite.
- First run will auto-create the admin if not present.
- Change default admin credentials after first login via **Users** page.
