# ExplainDroid

ExplainDroid uploads Android APKs, runs FlowDroid privacy analysis, and shows the results in a web dashboard.

## Deployment

This repo is configured for a simple Render free deployment:

- `explaindroid`: Flask web dashboard
- `explaindroid-db`: Render Postgres database
- Cloudflare R2 for S3-compatible storage

There is no separate Render worker in the free setup. When Redis is not configured, the web service starts analysis in an in-process background thread after upload. This is intended for demos and small APKs; large APKs may fail or be interrupted on Render free instances.

## Render Setup

Deploy the repo as a Render Blueprint. `render.yaml` creates the free web service and free Postgres database.

Set these Render environment variables from Cloudflare R2:

```bash
EXPLAINDROID_S3_BUCKET=
EXPLAINDROID_S3_ENDPOINT_URL=
EXPLAINDROID_S3_REGION=auto
EXPLAINDROID_S3_ACCESS_KEY_ID=
EXPLAINDROID_S3_SECRET_ACCESS_KEY=
```

Optional:

```bash
GROQ_API_KEY=
```

Without `GROQ_API_KEY`, analysis still works, but natural-language summaries are unavailable.

## Analysis Flow

1. User uploads an APK from the dashboard.
2. A job is created.
3. FlowDroid analyzes the APK.
4. The dashboard shows the completed report.
