import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from urllib.parse import urlparse

from . import config


TERMINAL_STATUSES = {"completed", "failed", "timed_out"}


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def is_postgres():
    return config.DATABASE_URL.startswith(("postgres://", "postgresql://"))


def sqlite_path():
    parsed = urlparse(config.DATABASE_URL)
    if parsed.scheme != "sqlite":
        return os.path.join(config.DATA_DIR, "explaindroid.db")
    if parsed.path in ("", "/"):
        return ":memory:"
    if parsed.path.startswith("//"):
        return parsed.path[1:]
    if parsed.path.startswith("/"):
        return parsed.path[1:]
    return parsed.path


@contextmanager
def connect():
    if is_postgres():
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:
            raise RuntimeError("Install psycopg to use DATABASE_URL with Postgres") from exc

        conn = psycopg.connect(config.DATABASE_URL, row_factory=dict_row)
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()
    else:
        path = sqlite_path()
        if path != ":memory:":
            os.makedirs(os.path.dirname(path), exist_ok=True)
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()


def ph():
    return "%s" if is_postgres() else "?"


def row_to_dict(row):
    if row is None:
        return None
    data = dict(row)
    if data.get("report_json"):
        if isinstance(data["report_json"], str):
            data["report"] = json.loads(data["report_json"])
        else:
            data["report"] = data["report_json"]
    else:
        data["report"] = None
    return data


def init_db():
    if is_postgres():
        ddl = """
        CREATE TABLE IF NOT EXISTS analysis_jobs (
            id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            object_key TEXT NOT NULL,
            storage_backend TEXT NOT NULL,
            size_bytes BIGINT NOT NULL DEFAULT 0,
            status TEXT NOT NULL,
            stage TEXT NOT NULL,
            error_message TEXT,
            leak_count INTEGER NOT NULL DEFAULT 0,
            highest_risk TEXT,
            summary TEXT,
            report_json JSONB,
            report_path TEXT,
            created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL,
            started_at TIMESTAMPTZ,
            completed_at TIMESTAMPTZ
        )
        """
    else:
        ddl = """
        CREATE TABLE IF NOT EXISTS analysis_jobs (
            id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            object_key TEXT NOT NULL,
            storage_backend TEXT NOT NULL,
            size_bytes INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL,
            stage TEXT NOT NULL,
            error_message TEXT,
            leak_count INTEGER NOT NULL DEFAULT 0,
            highest_risk TEXT,
            summary TEXT,
            report_json TEXT,
            report_path TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT
        )
        """
    with connect() as conn:
        conn.execute(ddl)


def create_job(job_id, filename, object_key, storage_backend, size_bytes=0):
    now = utcnow()
    q = ph()
    with connect() as conn:
        conn.execute(
            f"""
            INSERT INTO analysis_jobs (
                id, filename, object_key, storage_backend, size_bytes,
                status, stage, created_at, updated_at
            ) VALUES ({q}, {q}, {q}, {q}, {q}, {q}, {q}, {q}, {q})
            """,
            (
                job_id, filename, object_key, storage_backend, size_bytes,
                "created", "uploading", now, now
            )
        )


def get_job(job_id):
    q = ph()
    with connect() as conn:
        row = conn.execute(
            f"SELECT * FROM analysis_jobs WHERE id = {q}",
            (job_id,)
        ).fetchone()
    return row_to_dict(row)


def list_jobs(limit=50):
    q = ph()
    with connect() as conn:
        rows = conn.execute(
            f"SELECT * FROM analysis_jobs ORDER BY created_at DESC LIMIT {q}",
            (limit,)
        ).fetchall()
    return [row_to_dict(row) for row in rows]


def next_queued_job():
    q = ph()
    with connect() as conn:
        row = conn.execute(
            f"""
            SELECT * FROM analysis_jobs
            WHERE status = {q}
            ORDER BY created_at ASC
            LIMIT 1
            """,
            ("queued",)
        ).fetchone()
    return row_to_dict(row)


def update_job(job_id, **fields):
    if not fields:
        return
    fields["updated_at"] = utcnow()
    q = ph()
    assignments = ", ".join(f"{key} = {q}" for key in fields)
    values = []
    for value in fields.values():
        if isinstance(value, (dict, list)):
            values.append(json.dumps(value))
        else:
            values.append(value)
    values.append(job_id)
    with connect() as conn:
        conn.execute(
            f"UPDATE analysis_jobs SET {assignments} WHERE id = {q}",
            tuple(values)
        )


def delete_job(job_id):
    q = ph()
    with connect() as conn:
        cursor = conn.execute(
            f"DELETE FROM analysis_jobs WHERE id = {q}",
            (job_id,)
        )
        return cursor.rowcount


def mark_failed(job_id, status, message):
    update_job(
        job_id,
        status=status,
        stage=status,
        error_message=str(message)[:2000],
        completed_at=utcnow()
    )
