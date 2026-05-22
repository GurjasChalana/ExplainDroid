# ExplainDroid

ExplainDroid runs FlowDroid on Android APKs, stores each analysis as a durable job, and presents privacy leak results in a browser workspace.

## What It Does

- Upload APKs through a scalable upload flow with a 500MB MVP limit.
- Queue analysis jobs instead of running FlowDroid inside the web request.
- Run FlowDroid in a separate worker process.
- Expose FlowDroid tuning knobs for larger and newer APKs.
- Store job/report metadata in Postgres, with SQLite as the local fallback.
- Store APK blobs in S3-compatible object storage when configured, with local disk as the development fallback.
- Delete original APKs after analysis while keeping parsed reports and summaries.

## Local Development

The simplest local path uses SQLite plus the local worker polling fallback:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
EXPLAINDROID_DATA_DIR=. .venv/bin/python -m explaindroid.app
```

In another terminal, run the worker:

```bash
EXPLAINDROID_DATA_DIR=. .venv/bin/python -m explaindroid.worker
```

Open http://127.0.0.1:5000/.

## Local Docker Stack

```bash
cp .env.example .env
docker compose up --build
```

This starts the web service, worker, Postgres, and Redis. Set `GROQ_API_KEY` in `.env` before relying on LLM summaries.

## Larger APKs

ExplainDroid exposes FlowDroid tuning knobs for larger APKs. For local or Render tuning, adjust:

```bash
EXPLAINDROID_MAX_UPLOAD_MB=500
EXPLAINDROID_ANALYSIS_TIMEOUT_SECONDS=1800
EXPLAINDROID_JAVA_MAX_HEAP_MB=4096
EXPLAINDROID_PROCESS_MULTIPLE_DEX=0
EXPLAINDROID_LENIENT_PARSING=1
EXPLAINDROID_FLOWDROID_EXTRA_ARGS=
EXPLAINDROID_FLOWDROID_FALLBACK_ARGS="-ot -nc"
FLOWDROID_JAR_PATH=
```

The repo includes FlowDroid 2.15.1 for newer APK resource-table support and enables lenient parsing by default. If FlowDroid fails while constructing Android callbacks, ExplainDroid retries with `-ot -nc` by default and labels the report as component/no-callback or partial fallback mode. This can salvage some modern APKs, but it may miss flows that depend on callback entry points. Large modern APKs can still fail if FlowDroid/Soot cannot parse their resource tables. In that case, the job is marked failed with a concise compatibility message instead of a misleading zero-leak report.

If an APK targets an SDK level you do not have locally, install the matching Android platform before retrying:

```bash
sdkmanager "platforms;android-36"
```

## Render Deployment

`render.yaml` defines:

- `explaindroid`: the Flask web service on Render's free instance type
- `explaindroid-db`: Render Postgres for durable metadata

The free Blueprint intentionally does not create a separate worker or Redis queue,
because those resources can require billing details. When `REDIS_URL` is absent,
the web service starts analysis in an in-process background thread after upload.
This is useful for demos and small APKs, but it is less reliable than the
web-plus-worker stack because free web services can sleep or be interrupted.
For production use, add a worker service and Redis/Key Value queue.

For Cloudflare R2 or another S3-compatible bucket, configure these secrets on
the web service:

```bash
EXPLAINDROID_S3_BUCKET=
EXPLAINDROID_S3_ENDPOINT_URL=
EXPLAINDROID_S3_REGION=auto
EXPLAINDROID_S3_ACCESS_KEY_ID=
EXPLAINDROID_S3_SECRET_ACCESS_KEY=
```

Cloudflare R2 or AWS S3 both work as long as the endpoint is S3-compatible.

## Analysis Flow

1. The browser requests an upload target from `/api/uploads`.
2. The APK uploads to S3-compatible storage, or local disk in development.
3. The browser calls `/api/uploads/<job_id>/complete`.
4. The job moves to `queued`.
5. The worker runs FlowDroid, parses leaks, summarizes risk, stores the report, and deletes the original APK.
6. The UI polls `/api/jobs` for progress and links to the report detail page when complete.

## Job States

`created`, `uploading`, `queued`, `running_flowdroid`, `parsing`, `summarizing`, `completed`, `failed`, and `timed_out`.
