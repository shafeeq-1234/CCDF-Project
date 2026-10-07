import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get("CYBERTRACE_SECRET_KEY", "cybertrace-dev-secret-change-me")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "CYBERTRACE_DATABASE_URI",
        "sqlite:///" + os.path.join(BASE_DIR, "instance", "cybertrace.db"),
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = int(os.environ.get("CYBERTRACE_MAX_CONTENT_MB", "64")) * 1024 * 1024
    # Max file size (bytes) to hash/read fully in one pass guard; streaming used anyway.
    SCAN_MAX_FILE_SIZE = int(os.environ.get("CYBERTRACE_SCAN_MAX_BYTES", str(1024 * 1024 * 1024)))
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    WTF_CSRF_ENABLED = True
    DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1"
