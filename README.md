# FlowDroid Dashboard

A Flask dashboard for viewing FlowDroid taint analysis reports and uploading APKs for analysis.

## Deployment Shape

Use a container host for the full app. Vercel is a good fit for static or serverless web apps, but this dashboard runs FlowDroid through Java, needs Android SDK platform files, writes uploaded APKs/reports, and can run longer than a typical request. The included `Dockerfile` packages the Flask app, Java runtime, Android SDK command-line tools, and an Android platform so other users can upload APKs and run analysis through the deployed service.

Groq stays server-side. Users do not need their own API key unless you decide to build that flow later. Set `GROQ_API_KEY` on the deployment provider as a secret environment variable.

For a shared demo, set `DASHBOARD_PASSWORD` too. The app will use HTTP Basic auth with `DASHBOARD_USERNAME`, defaulting to `flowdroid`, so casual visitors cannot burn through your upload capacity or Groq quota.

## Setup

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

## Run

```bash
.venv/bin/python dashboard/app.py
```

Open http://127.0.0.1:5000/.

## Run with Docker

Create a local `.env` from the example:

```bash
cp .env.example .env
```

Set `GROQ_API_KEY` in `.env`, then run:

```bash
docker compose up --build
```

Open http://127.0.0.1:8080/.

## Deploy

Recommended hosts:

- Render: use `render.yaml`, add `GROQ_API_KEY` as a secret, and keep the persistent disk mounted at `/data`.
- Railway/Fly.io/Cloud Run: deploy the Dockerfile, set `GROQ_API_KEY`, and attach persistent storage mounted at `/data` if you want reports to survive restarts.

Useful environment variables:

```bash
GROQ_API_KEY=...
GROQ_MODEL=llama-3.3-70b-versatile
FLOWDROID_DATA_DIR=/data
FLOWDROID_MAX_WORKERS=1
FLOWDROID_MAX_UPLOAD_MB=100
ANDROID_PLATFORMS=/opt/android-sdk/platforms
PORT=8080
DASHBOARD_USERNAME=flowdroid
DASHBOARD_PASSWORD=choose-a-shared-password
```

Keep `FLOWDROID_MAX_WORKERS=1` at first. FlowDroid is CPU and memory heavy, and a single shared Groq key is quota-limited.

## Analysis Notes

APK analysis requires:

- Java available on `PATH`
- Android SDK platforms at `/opt/android-sdk/platforms`
- `GROQ_API_KEY` set in the environment for report summaries and fallback sink classification

Groq has a free tier, but it is not unlimited. As of May 2026, Groq's model docs list `llama-3.3-70b-versatile` pricing at `$0.59` per 1M input tokens and `$0.79` per 1M output tokens, and the free tier is quota/rate-limit based. If this is public, add authentication or rate limiting before sharing widely.
