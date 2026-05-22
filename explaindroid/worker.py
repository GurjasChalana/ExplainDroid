import json
import os
import time
import tempfile

from . import config, db, storage
from .analyze import run


def highest_risk(report):
    levels = [
        leak.get("risk_node", {}).get("level", "R1")
        for leak in report.get("leaks", [])
    ]
    return max(levels) if levels else "R1"


def analyze_job(job_id):
    config.ensure_data_dirs()
    db.init_db()
    job = db.get_job(job_id)
    if not job:
        raise RuntimeError(f"Unknown job {job_id}")

    db.update_job(
        job_id,
        status="running_flowdroid",
        stage="running_flowdroid",
        started_at=db.utcnow(),
        error_message=None,
    )

    temp_dir = tempfile.mkdtemp(prefix=f"explaindroid-{job_id}-")
    apk_path = os.path.join(temp_dir, job["filename"])
    try:
        storage.download_to_file(job["object_key"], apk_path)
        db.update_job(job_id, size_bytes=os.path.getsize(apk_path))

        report = run(
            apk_path,
            original_filename=job["filename"],
            timeout_seconds=config.ANALYSIS_TIMEOUT_SECONDS,
            write_report=False,
            stage_callback=lambda stage: db.update_job(
                job_id, status=stage, stage=stage
            ),
        )

        report_path = os.path.join(config.REPORTS_DIR, f"{job_id}.json")
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

        db.update_job(
            job_id,
            status="completed",
            stage="completed",
            leak_count=report.get("leak_count", 0),
            highest_risk=highest_risk(report),
            summary=report.get("summary"),
            report_json=report,
            report_path=report_path,
            completed_at=db.utcnow(),
        )
        storage.delete_object(job["object_key"])
        return {"status": "completed", "job_id": job_id}
    except TimeoutError as exc:
        db.mark_failed(job_id, "timed_out", exc)
        raise
    except Exception as exc:
        db.mark_failed(job_id, "failed", exc)
        raise
    finally:
        if os.path.exists(apk_path):
            os.remove(apk_path)
        if os.path.isdir(temp_dir):
            try:
                os.rmdir(temp_dir)
            except OSError:
                pass


def main():
    config.ensure_data_dirs()
    db.init_db()

    if not config.REDIS_URL:
        print("REDIS_URL is not configured; polling queued jobs from the database.")
        while True:
            job = db.next_queued_job()
            if not job:
                time.sleep(5)
                continue
            try:
                analyze_job(job["id"])
            except Exception as exc:
                print(f"Job {job['id']} failed: {exc}")
            time.sleep(1)

    from redis import Redis
    from rq import Queue, Worker

    redis_conn = Redis.from_url(config.REDIS_URL)
    worker = Worker([Queue(config.QUEUE_NAME, connection=redis_conn)], connection=redis_conn)
    worker.work()


if __name__ == "__main__":
    main()
