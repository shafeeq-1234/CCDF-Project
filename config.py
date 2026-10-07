import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Vercel serverless functions have a read-only filesystem except /tmp.
# Vercel sets VERCEL=1 automatically; redirect all writable paths there.
IS_SERVERLESS = os.environ.get("VERCEL") == "1" or os.environ.get("CYBERTRACE_DATA_DIR") == "/tmp"
DATA_DIR = "/tmp" if IS_SERVERLESS else BASE_DIR
INSTANCE_DIR = os.path.join(DATA_DIR, "instance")
REPORTS_DIR = os.path.join(DATA_DIR, "reports")


class Config:
    SECRET_KEY = os.environ.get("CYBERTRACE_SECRET_KEY", "cybertrace-dev-secret-change-me")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "CYBERTRACE_DATABASE_URI",
        "sqlite:///" + os.path.join(INSTANCE_DIR, "cybertrace.db"),
    )
    INSTANCE_DIR = INSTANCE_DIR
    REPORTS_DIR = REPORTS_DIR
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = int(os.environ.get("CYBERTRACE_MAX_CONTENT_MB", "64")) * 1024 * 1024
    # Max file size (bytes) to hash/read fully in one pass guard; streaming used anyway.
    SCAN_MAX_FILE_SIZE = int(os.environ.get("CYBERTRACE_SCAN_MAX_BYTES", str(1024 * 1024 * 1024)))
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    WTF_CSRF_ENABLED = True
    DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1"
