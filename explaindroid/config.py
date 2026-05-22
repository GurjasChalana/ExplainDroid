import os

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None


if load_dotenv:
    load_dotenv()

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_DIR = os.environ.get("EXPLAINDROID_DATA_DIR", PROJECT_ROOT)
UPLOADS_DIR = os.path.join(DATA_DIR, "uploads")
REPORTS_DIR = os.path.join(DATA_DIR, "reports")
CACHE_DIR = os.path.join(DATA_DIR, "cache")

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    f"sqlite:///{os.path.join(DATA_DIR, 'explaindroid.db')}"
)
REDIS_URL = os.environ.get("REDIS_URL")
QUEUE_NAME = os.environ.get("EXPLAINDROID_QUEUE_NAME", "analysis")

MAX_UPLOAD_MB = int(os.environ.get("EXPLAINDROID_MAX_UPLOAD_MB", "500"))
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024
ANALYSIS_TIMEOUT_SECONDS = int(
    os.environ.get("EXPLAINDROID_ANALYSIS_TIMEOUT_SECONDS", "1800")
)
JAVA_MAX_HEAP_MB = int(os.environ.get("EXPLAINDROID_JAVA_MAX_HEAP_MB", "4096"))
PROCESS_MULTIPLE_DEX = os.environ.get(
    "EXPLAINDROID_PROCESS_MULTIPLE_DEX", "0"
) not in ("0", "false", "False", "no", "No")
LENIENT_PARSING = os.environ.get(
    "EXPLAINDROID_LENIENT_PARSING", "1"
) not in ("0", "false", "False", "no", "No")
FLOWDROID_EXTRA_ARGS = os.environ.get("EXPLAINDROID_FLOWDROID_EXTRA_ARGS", "")
FLOWDROID_FALLBACK_ARGS = os.environ.get(
    "EXPLAINDROID_FLOWDROID_FALLBACK_ARGS", "-ot -nc"
)

S3_BUCKET = os.environ.get("EXPLAINDROID_S3_BUCKET")
S3_ENDPOINT_URL = os.environ.get("EXPLAINDROID_S3_ENDPOINT_URL")
S3_REGION = os.environ.get("EXPLAINDROID_S3_REGION", "auto")
S3_ACCESS_KEY_ID = os.environ.get("EXPLAINDROID_S3_ACCESS_KEY_ID")
S3_SECRET_ACCESS_KEY = os.environ.get("EXPLAINDROID_S3_SECRET_ACCESS_KEY")
S3_PREFIX = os.environ.get("EXPLAINDROID_S3_PREFIX", "uploads")

GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
ANDROID_PLATFORMS = os.environ.get("ANDROID_PLATFORMS", "/opt/android-sdk/platforms/")
JAVA_BIN = os.environ.get("JAVA_BIN", "java")
FLOWDROID_JAR_PATH = os.environ.get("FLOWDROID_JAR_PATH")


def ensure_data_dirs():
    os.makedirs(UPLOADS_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(CACHE_DIR, exist_ok=True)
