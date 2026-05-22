import json
import os
import shutil
import uuid

from flask import Flask, abort, jsonify, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

from . import config, db, queueing, storage


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = config.MAX_UPLOAD_BYTES

config.ensure_data_dirs()
db.init_db()


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


@app.route("/")
def index():
    jobs = db.list_jobs()
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
    return jsonify({"jobs": [job_payload(job) for job in db.list_jobs()]})


@app.route("/api/jobs/<job_id>")
def api_job(job_id):
    job = db.get_job(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify({"job": job_payload(job), "report": job.get("report")})


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
    if upload_target["mode"] == "local":
        upload_target["url"] = url_for("upload_local_blob", job_id=job_id)

    return jsonify({
        "job": job_payload(db.get_job(job_id)),
        "upload": upload_target,
        "complete_url": url_for("complete_upload", job_id=job_id),
        "max_upload_mb": config.MAX_UPLOAD_MB,
    }), 201


@app.route("/api/uploads/<job_id>/blob", methods=["POST", "PUT"])
def upload_local_blob(job_id):
    job = db.get_job(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    if storage.backend_name() != "local":
        return jsonify({"error": "Local upload endpoint is disabled"}), 400

    content_length = request.content_length or 0
    if content_length > config.MAX_UPLOAD_BYTES:
        return jsonify({"error": f"APK is too large. Limit is {config.MAX_UPLOAD_MB}MB."}), 413

    path = storage.local_path_for_key(job["object_key"])
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if "apk" in request.files:
        request.files["apk"].save(path)
    else:
        with open(path, "wb") as f:
            shutil.copyfileobj(request.stream, f)
    size_bytes = os.path.getsize(path)
    error = validate_apk(job["filename"], size_bytes)
    if error:
        os.remove(path)
        return jsonify({"error": error}), 400
    db.update_job(job_id, size_bytes=size_bytes)
    return jsonify({"job": job_payload(db.get_job(job_id))})


@app.route("/api/uploads/<job_id>/complete", methods=["POST"])
def complete_upload(job_id):
    job = db.get_job(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    db.update_job(job_id, status="queued", stage="queued")
    enqueue_result = queueing.enqueue_analysis(job_id)
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
    enqueue_result = queueing.enqueue_analysis(job_id)
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
