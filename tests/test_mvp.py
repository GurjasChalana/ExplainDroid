import importlib
import os
import tempfile
import unittest
from unittest import mock


class ExplainDroidMvpTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

        from explaindroid import config, db

        config.DATA_DIR = self.temp_dir.name
        config.UPLOADS_DIR = os.path.join(self.temp_dir.name, "uploads")
        config.REPORTS_DIR = os.path.join(self.temp_dir.name, "reports")
        config.CACHE_DIR = os.path.join(self.temp_dir.name, "cache")
        config.DATABASE_URL = f"sqlite:///{os.path.join(self.temp_dir.name, 'test.db')}"
        config.REDIS_URL = None
        config.MAX_UPLOAD_MB = 500
        config.MAX_UPLOAD_BYTES = 500 * 1024 * 1024
        config.JAVA_BIN = "java"
        config.JAVA_MAX_HEAP_MB = 4096
        config.PROCESS_MULTIPLE_DEX = False
        config.LENIENT_PARSING = True
        config.FLOWDROID_EXTRA_ARGS = ""
        config.FLOWDROID_FALLBACK_ARGS = "-ot -nc"
        config.S3_BUCKET = None
        config.S3_ENDPOINT_URL = None
        config.S3_ACCESS_KEY_ID = None
        config.S3_SECRET_ACCESS_KEY = None
        config.S3_REGION = "auto"
        config.S3_PREFIX = "uploads"
        config.ensure_data_dirs()
        db.init_db()
        self.config = config
        self.db = db

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_job_lifecycle_is_durable(self):
        self.db.create_job("job-1", "demo.apk", "uploads/job-1/demo.apk", "local", 123)
        self.db.update_job("job-1", status="queued", stage="queued")
        self.db.update_job(
            "job-1",
            status="completed",
            stage="completed",
            leak_count=2,
            highest_risk="R4",
            summary="Two risky flows.",
            report_json={"app": "demo.apk", "leak_count": 2, "leaks": []},
        )

        job = self.db.get_job("job-1")
        self.assertEqual(job["status"], "completed")
        self.assertEqual(job["leak_count"], 2)
        self.assertEqual(job["report"]["app"], "demo.apk")

    def test_next_queued_job_returns_oldest_queued_job(self):
        self.db.create_job("job-1", "one.apk", "uploads/job-1/one.apk", "local", 1)
        self.db.create_job("job-2", "two.apk", "uploads/job-2/two.apk", "local", 1)
        self.db.update_job("job-2", status="queued", stage="queued")

        job = self.db.next_queued_job()
        self.assertEqual(job["id"], "job-2")

    def test_parse_output_extracts_leak_count(self):
        from explaindroid.analyze import parse_output

        output = """
        Found 1 leaks
        The sink <android.util.Log: int d(java.lang.String,java.lang.String)> in method <com.example.MainActivity: void send()>
        - $r0 = virtualinvoke $r1.<android.telephony.TelephonyManager: java.lang.String getDeviceId()>()
        """
        report = parse_output(output)
        self.assertEqual(report["leak_count"], 1)
        self.assertEqual(len(report["leaks"]), 1)
        self.assertIn("context_node", report["leaks"][0])
        self.assertIn("interpretation", report["leaks"][0]["risk_node"])

    def test_third_party_sink_adds_risk_points(self):
        from explaindroid.analyze import calculate_risk

        risk = calculate_risk(
            "<android.telephony.TelephonyManager: java.lang.String getDeviceId()>",
            "<com.google.firebase.analytics.FirebaseAnalytics: void logEvent(java.lang.String,android.os.Bundle)>",
            1,
        )

        self.assertEqual(risk["scores"]["third_party"], 4)
        self.assertEqual(risk["scores"]["network"], 3)
        self.assertEqual(risk["total"], 10)
        self.assertEqual(risk["level"], "R5")

    def test_parse_output_sums_partial_component_counts(self):
        from explaindroid.analyze import parse_output

        output = """
        Found 1 leaks for component com.example.One
        Found 2 leaks for component com.example.Two
        The data flow analysis has failed. Error message: callback failure
        """
        report = parse_output(output)
        self.assertEqual(report["leak_count"], 3)

    def test_flowdroid_command_enables_large_apk_options(self):
        from explaindroid.analyze import build_flowdroid_command

        command = build_flowdroid_command("/tmp/app.apk")

        self.assertIn("-Xmx4096m", command)
        self.assertIn("-lp", command)
        self.assertIn("/tmp/app.apk", command)

    def test_flowdroid_resource_failure_is_human_readable(self):
        from explaindroid.analyze import summarize_flowdroid_failure

        message = summarize_flowdroid_failure(
            "The data flow analysis has failed. Error message: "
            "File format violation in type spec table: res1 is not zero offset=0x378152"
        )

        self.assertIn("could not parse", message)
        self.assertIn("resource", message)

    def test_flowdroid_callback_failure_is_human_readable(self):
        from explaindroid.analyze import summarize_flowdroid_failure

        message = summarize_flowdroid_failure(
            "The data flow analysis has failed. Error message: "
            "cannot set body for non-concrete method! "
            "<android.app.Service: android.os.IBinder onBind(android.content.Intent)>"
        )

        self.assertIn("constructing Android callbacks", message)
        self.assertIn("no-callback fallback", message)

    def test_zero_leak_summary_is_conservative(self):
        from explaindroid.analyze import summarize_with_llm

        summary = summarize_with_llm({"app": "demo.apk", "leak_count": 0, "leaks": []})

        self.assertIn("did not detect", summary)
        self.assertIn("does not prove", summary)

    def test_upload_metadata_rejects_large_apk(self):
        app_module = importlib.import_module("explaindroid.app")
        app_module.app.config["TESTING"] = True
        client = app_module.app.test_client()

        response = client.post(
            "/api/uploads",
            json={"filename": "large.apk", "size_bytes": self.config.MAX_UPLOAD_BYTES + 1},
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("too large", response.get_json()["error"])

    def test_upload_metadata_creates_job(self):
        app_module = importlib.import_module("explaindroid.app")
        app_module.app.config["TESTING"] = True
        client = app_module.app.test_client()

        response = client.post(
            "/api/uploads",
            json={"filename": "sample.apk", "size_bytes": 1024},
        )

        self.assertEqual(response.status_code, 201)
        data = response.get_json()
        self.assertEqual(data["job"]["filename"], "sample.apk")
        self.assertEqual(data["upload"]["mode"], "local")

    def test_api_jobs_returns_json_error(self):
        app_module = importlib.import_module("explaindroid.app")
        app_module.app.config["TESTING"] = True
        client = app_module.app.test_client()

        with mock.patch("explaindroid.db.list_jobs", side_effect=RuntimeError("boom")):
            response = client.get("/api/jobs")

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.content_type, "application/json")
        self.assertIn("Could not load jobs", response.get_json()["error"])

    def test_s3_upload_target_uses_server_upload(self):
        from explaindroid import config, storage

        config.S3_BUCKET = "explaindroid-uploads"
        config.S3_ACCESS_KEY_ID = "access-key"
        config.S3_SECRET_ACCESS_KEY = "secret-key"

        target = storage.create_upload_target("uploads/job/app.apk", "app.apk", 1024)

        self.assertEqual(target["mode"], "server")
        self.assertEqual(target["method"], "POST")
        self.assertIsNone(target["url"])

    def test_queue_fallback_starts_inline_analysis(self):
        app_module = importlib.import_module("explaindroid.app")
        with mock.patch("explaindroid.queueing.enqueue_analysis", return_value={
            "queued": False,
            "reason": "REDIS_URL is not configured",
        }), mock.patch("threading.Thread") as thread_class:
            result = app_module.enqueue_or_run_analysis("job-inline")

        self.assertFalse(result["queued"])
        self.assertTrue(result["inline"])
        thread_class.assert_called_once()
        thread_class.return_value.start.assert_called_once()

    def test_legacy_report_json_renders(self):
        app_module = importlib.import_module("explaindroid.app")
        app_module.app.config["TESTING"] = True
        client = app_module.app.test_client()
        self.db.create_job("legacy-1", "legacy.apk", "uploads/legacy-1/legacy.apk", "local", 10)
        self.db.update_job(
            "legacy-1",
            status="completed",
            stage="completed",
            leak_count=1,
            highest_risk="R4",
            report_json={
                "app": "legacy.apk",
                "leak_count": 1,
                "leaks": [{
                    "source_node": {
                        "signature": "android.telephony.TelephonyManager: java.lang.String getDeviceId()",
                        "data_category": "UNIQUE_IDENTIFIER",
                    },
                    "intermediate_node": {
                        "method": "com.example.MainActivity: void send()",
                    },
                    "sink_node": {
                        "signature": "android.util.Log: int d(java.lang.String,java.lang.String)",
                        "sink_category": "LOG",
                    },
                    "risk_node": {
                        "scores": {
                            "sensitive_source": 3,
                            "local_storage": 0,
                            "network": 3,
                            "multiple_sinks": 0,
                        },
                        "total": 6,
                        "level": "R3",
                        "label": "Moderate",
                    },
                }],
                "summary": "Legacy report.",
            },
        )

        response = client.get("/reports/legacy-1")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Privacy flow map", response.data)
        self.assertIn(b"Not available from saved report", response.data)


if __name__ == "__main__":
    unittest.main()
