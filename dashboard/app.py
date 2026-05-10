import threading
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, Response
from concurrent.futures import ThreadPoolExecutor
from hmac import compare_digest
import json
import os
import uuid

app = Flask(__name__)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_DIR = os.environ.get("FLOWDROID_DATA_DIR", PROJECT_ROOT)
UPLOAD_FOLDER = os.path.join(DATA_DIR, "uploads")
REPORTS_FOLDER = os.path.join(DATA_DIR, "reports")
MAX_WORKERS = int(os.environ.get("FLOWDROID_MAX_WORKERS", "1"))
DASHBOARD_USERNAME = os.environ.get("DASHBOARD_USERNAME", "flowdroid")
DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD")

app.config["MAX_CONTENT_LENGTH"] = int(
    os.environ.get("FLOWDROID_MAX_UPLOAD_MB", "100")
) * 1024 * 1024

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)

@app.before_request
def require_auth():
    if request.path == "/health" or not DASHBOARD_PASSWORD:
        return None

    auth = request.authorization
    if (
        auth
        and compare_digest(auth.username, DASHBOARD_USERNAME)
        and compare_digest(auth.password, DASHBOARD_PASSWORD)
    ):
        return None

    return Response(
        "Authentication required",
        401,
        {"WWW-Authenticate": 'Basic realm="FlowDroid Dashboard"'}
    )

@app.route("/")
def index():
    reports = []
    for file in os.listdir(REPORTS_FOLDER):
        if file.endswith(".json"):
            with open(os.path.join(REPORTS_FOLDER, file)) as f:
                reports.append(json.load(f))
    return render_template("index.html", reports=reports)
    
    
analysis_status = {}
analysis_lock = threading.Lock()
executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
import sys
sys.path.insert(0, os.path.dirname(__file__))
from analyze import run as run_analysis_func

@app.route("/health")
def health():
    return {"status": "ok"}

@app.route("/upload", methods=["POST"])
def upload():
    file = request.files.get("apk")

    if not file or not file.filename:
        return {"error": "Please upload an APK file"}, 400
    
    if not file.filename.lower().endswith(".apk"):
        return {"error": "Only .apk files allowed"}, 400
    
    original_filename = secure_filename(file.filename)
    job_id = uuid.uuid4().hex
    filename = f"{job_id}-{original_filename}"
    apk_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(apk_path)
    
    with analysis_lock:
        analysis_status[job_id] = {
            "status": "queued",
            "filename": original_filename
        }
    
    def run_analysis():
        with analysis_lock:
            analysis_status[job_id]["status"] = "running"
        try:
            run_analysis_func(apk_path, original_filename=original_filename)
            with analysis_lock:
                analysis_status[job_id]["status"] = "done"
        except Exception as e:
            print(f"Analysis error: {e}")
            with analysis_lock:
                analysis_status[job_id]["status"] = "error"
    
    executor.submit(run_analysis)
    
    return {"status": "queued", "job_id": job_id, "filename": original_filename}
    
@app.route("/status/<job_id>")
def status(job_id):
    with analysis_lock:
        job = analysis_status.get(job_id)
    if not job:
        return {"status": "unknown"}, 404
    return job
    

if __name__ == "__main__":
    app.run(
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5000"))
    )
