import json
import os
import threading
import uuid

from flask import Flask, abort, jsonify, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

from . import config, db, queueing, storage


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = config.MAX_UPLOAD_BYTES

config.ensure_data_dirs()
db.init_db()

inline_jobs = set()
inline_jobs_lock = threading.Lock()


def job_payload(job):
    if not job:
        return None
    payload = {
        "id": job["id"],
        "filename": job["filename"],
        "size_bytes": job["size_bytes"],
        "status": job["status"],
        "stage": job["stage"],
        "error_message": job["error_message"],
        "leak_count": job["leak_count"],
        "highest_risk": job["highest_risk"],
        "summary": job["summary"],
        "created_at": job["created_at"],
        "updated_at": job["updated_at"],
        "started_at": job["started_at"],
        "completed_at": job["completed_at"],
        "has_report": bool(job.get("report")),
    }
    return payload


def normalize_leak(leak):
    source_node = leak.setdefault("source_node", {})
    intermediate_node = leak.setdefault("intermediate_node", {})
    sink_node = leak.setdefault("sink_node", {})
    risk_node = leak.setdefault("risk_node", {})

    source_node.setdefault("type", "Source")
    source_node.setdefault("signature", "Unknown source")
    source_node.setdefault("data_category", "UNKNOWN")
    source_node.setdefault("permission", "Not available from saved report")

    intermediate_node.setdefault("type", "Intermediate")
    intermediate_node.setdefault("method", "Unknown method")
    intermediate_node.setdefault("role", "Propagation")

    sink_node.setdefault("type", "Sink")
    sink_node.setdefault("signature", "Unknown sink")
    sink_node.setdefault("sink_category", "UNKNOWN")
    sink_node.setdefault("role", "Data exposure")

    risk_node.setdefault("scores", {})
    scores = risk_node["scores"]
    for key in (
        "sensitive_source", "local_storage", "network", "third_party",
        "multiple_sinks", "encryption", "secure_protocol", "anonymization",
    ):
        scores.setdefault(key, 0)
    risk_node.setdefault("total", sum(scores.values()))
    risk_node.setdefault("level", "R1")
    risk_node.setdefault("label", "Very Low")
    risk_node.setdefault(
        "interpretation",
        f"{source_node['data_category']} reaches {sink_node['sink_category']}.",
    )
    risk_node.setdefault(
        "recommended_action",
        "Review this flow before release.",
    )

    leak.setdefault("context_node", {
        "type": "Context",
        "component": "Unknown component",
        "path_length": 3,
        "operations": [
            intermediate_node.get("role", "Propagation"),
            sink_node.get("role", "Data exposure"),
        ],
        "edge_types": ["FlowsTo", "FlowsTo", "Explains"],
        "permission": source_node.get("permission", "Not available from saved report"),
    })
    return leak


def normalize_report(report):
    if not report:
        return report
    report.setdefault("summary", "No summary is available for this report.")
    report.setdefault("analysis_mode", "default")
    report.setdefault("leak_count", len(report.get("leaks", [])))
    report["leaks"] = [normalize_leak(leak) for leak in report.get("leaks", [])]
    return report


def validate_apk(filename, size_bytes):
    if not filename or not filename.lower().endswith(".apk"):
        return "Only .apk files are supported."
    if size_bytes is not None and size_bytes > config.MAX_UPLOAD_BYTES:
        return f"APK is too large. The MVP limit is {config.MAX_UPLOAD_MB}MB."
    return None


def enqueue_or_run_analysis(job_id):
    enqueue_result = queueing.enqueue_analysis(job_id)
    if enqueue_result.get("queued"):
        return enqueue_result

    with inline_jobs_lock:
        if job_id in inline_jobs:
            return {
                "queued": False,
                "inline": True,
                "reason": "Analysis is already running in the web process",
            }
        inline_jobs.add(job_id)

    def run_inline():
        try:
            from .worker import analyze_job

            analyze_job(job_id)
        except Exception as exc:
            print(f"Inline analysis job {job_id} failed: {exc}")
        finally:
            with inline_jobs_lock:
                inline_jobs.discard(job_id)

    thread = threading.Thread(target=run_inline, daemon=True)
    thread.start()
    return {
        "queued": False,
        "inline": True,
        "reason": "REDIS_URL is not configured; analysis started in the web process",
    }


@app.route("/")
def index():
    db_error = None
    try:
        db.init_db()
        jobs = db.list_jobs()
    except Exception as exc:
        app.logger.exception("Could not load dashboard jobs")
        db_error = f"Could not load jobs: {exc}"
        jobs = []
    current_job = jobs[0] if jobs else None
    active_jobs = [
        job for job in jobs
        if job["status"] not in db.TERMINAL_STATUSES
    ]
    completed_jobs = [
        job for job in jobs
        if job["status"] == "completed"
    ]
    total_leaks = sum(job.get("leak_count") or 0 for job in completed_jobs)
    high_risk = sum(
        1 for job in completed_jobs
        if (job.get("highest_risk") or "R1") >= "R4"
    )
    return render_template(
        "index.html",
        jobs=jobs,
        jobs_payload=[job_payload(job) for job in jobs],
        current_job=current_job,
        active_jobs=active_jobs,
        completed_jobs=completed_jobs,
        total_leaks=total_leaks,
        high_risk=high_risk,
        max_upload_mb=config.MAX_UPLOAD_MB,
        storage_backend=storage.backend_name(),
        redis_enabled=bool(config.REDIS_URL),
        db_error=db_error,
    )


@app.route("/reports/<job_id>")
def report_detail(job_id):
    job = db.get_job(job_id)
    if not job:
        abort(404)
    if not job.get("report"):
        return redirect(url_for("index"))
    return render_template(
        "report.html",
        job=job,
        report=normalize_report(job["report"]),
    )


@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/api/jobs")
def api_jobs():
    try:
        db.init_db()
        return jsonify({"jobs": [job_payload(job) for job in db.list_jobs()]})
    except Exception as exc:
        app.logger.exception("Could not load jobs")
        return jsonify({"error": f"Could not load jobs: {exc}"}), 500


@app.route("/api/jobs/<job_id>")
def api_job(job_id):
    try:
        db.init_db()
        job = db.get_job(job_id)
        if not job:
            return jsonify({"error": "Job not found"}), 404
        return jsonify({"job": job_payload(job), "report": job.get("report")})
    except Exception as exc:
        app.logger.exception("Could not load job %s", job_id)
        return jsonify({"error": f"Could not load job: {exc}"}), 500


@app.route("/api/uploads", methods=["POST"])
def create_upload():
    data = request.get_json(silent=True) or {}
    filename = secure_filename(data.get("filename", ""))
    size_bytes = int(data.get("size_bytes") or 0)
    error = validate_apk(filename, size_bytes)
    if error:
        return jsonify({"error": error}), 400

    job_id = uuid.uuid4().hex
    key = storage.object_key(job_id, filename)
    db.create_job(
        job_id=job_id,
        filename=filename,
        object_key=key,
        storage_backend=storage.backend_name(),
        size_bytes=size_bytes,
    )
    upload_target = storage.create_upload_target(
        key,
        filename,
        config.MAX_UPLOAD_BYTES,
    )
    if upload_target["mode"] in ("local", "server"):
        upload_target["url"] = url_for("upload_blob", job_id=job_id)

    return jsonify({
        "job": job_payload(db.get_job(job_id)),
        "upload": upload_target,
        "complete_url": url_for("complete_upload", job_id=job_id),
        "max_upload_mb": config.MAX_UPLOAD_MB,
    }), 201


@app.route("/api/uploads/<job_id>/blob", methods=["POST", "PUT"])
def upload_blob(job_id):
    job = db.get_job(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404

    content_length = request.content_length or 0
    if content_length > config.MAX_UPLOAD_BYTES:
        return jsonify({"error": f"APK is too large. Limit is {config.MAX_UPLOAD_MB}MB."}), 413

    upload = request.files.get("apk")
    if not upload:
        return jsonify({"error": "Missing APK upload."}), 400

    size_bytes = content_length or 0
    error = validate_apk(job["filename"], size_bytes)
    if error:
        return jsonify({"error": error}), 400

    storage.save_upload(job["object_key"], upload)
    if storage.backend_name() == "local":
        size_bytes = os.path.getsize(storage.local_path_for_key(job["object_key"]))

    db.update_job(job_id, size_bytes=size_bytes)
    return jsonify({"job": job_payload(db.get_job(job_id))})


@app.route("/api/uploads/<job_id>/complete", methods=["POST"])
def complete_upload(job_id):
    job = db.get_job(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    db.update_job(job_id, status="queued", stage="queued")
    enqueue_result = enqueue_or_run_analysis(job_id)
    return jsonify({
        "job": job_payload(db.get_job(job_id)),
        "queue": enqueue_result,
    }), 202


@app.route("/upload", methods=["POST"])
def legacy_upload():
    file = request.files.get("apk")
    if not file or not file.filename:
        return {"error": "Please upload an APK file"}, 400

    filename = secure_filename(file.filename)
    error = validate_apk(filename, request.content_length)
    if error:
        return {"error": error}, 400

    job_id = uuid.uuid4().hex
    key = storage.object_key(job_id, filename)
    db.create_job(job_id, filename, key, "local", request.content_length or 0)
    storage.save_local_upload(key, file)
    db.update_job(job_id, status="queued", stage="queued")
    enqueue_result = enqueue_or_run_analysis(job_id)
    return {
        "status": "queued",
        "job_id": job_id,
        "filename": filename,
        "queue": enqueue_result,
    }, 202


@app.route("/status/<job_id>")
def status(job_id):
    job = db.get_job(job_id)
    if not job:
        return {"status": "unknown"}, 404
    return job_payload(job)


if __name__ == "__main__":
    app.run(
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5000"))
    )
