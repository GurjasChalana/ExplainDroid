# ExplainDroid

A small Flask app for running FlowDroid on Android APKs and explaining privacy leak results.

## What It Does

- Upload an `.apk`
- Run FlowDroid static taint analysis
- Parse detected source-to-sink leaks
- Score each leak by privacy risk
- Generate a short plain-English summary with Groq
- Show ExplainDroid reports in a browser

## Run Locally

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python explaindroid/app.py
```

Open http://127.0.0.1:5000/.

## Run with Docker

```bash
cp .env.example .env
docker compose up --build
```

Set `GROQ_API_KEY` in `.env` before running analysis.

## ExplainDroid Flow

1. Choose an APK file.
2. Click **Run Analysis**.
3. Wait for the analysis to finish.
4. View the report cards showing:
   - app name
   - highest risk level
   - LLM summary
   - source, intermediate method, sink, and risk score for each leak

## Deployment

The app is set up for a simple Docker deployment on Render. Store secrets like `GROQ_API_KEY` and `EXPLAINDROID_PASSWORD` as environment variables, not in the repo.
