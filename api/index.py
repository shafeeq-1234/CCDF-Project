"""Vercel serverless entrypoint.

Vercel's Python runtime imports this module and serves the ``app``
variable as the web application. All routes (pages + /api/*) are
handled by the Flask app; vercel.json rewrites every request here.

Note: on Vercel the filesystem is read-only except /tmp, so config.py
redirects the SQLite database and generated PDFs to /tmp when the
VERCEL environment variable is set (Vercel sets it automatically).
Data is therefore ephemeral per deployment instance — expected for a
demo deployment; run locally for persistent storage.
"""
import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import create_app  # noqa: E402

log = logging.getLogger("cybertrace.vercel")

# Vercel rewrites every request to this function (see vercel.json), so the
# WSGI environ may carry the rewrite destination ("/api/index") as PATH_INFO
# instead of the browser's real path. Strip that prefix so Flask routing
# sees "/", "/cases", "/api/dashboard", ... Locally PATH_INFO never has
# the prefix, making this middleware a no-op for local development.
VERCEL_PREFIX = "/api/index"


class FixVercelPath:
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "") or ""
        if path == VERCEL_PREFIX:
            environ["PATH_INFO"] = "/"
            if environ.get("SCRIPT_NAME") == VERCEL_PREFIX:
                environ["SCRIPT_NAME"] = ""
        elif path.startswith(VERCEL_PREFIX + "/"):
            environ["PATH_INFO"] = path[len(VERCEL_PREFIX):]
            if environ.get("SCRIPT_NAME") == VERCEL_PREFIX:
                environ["SCRIPT_NAME"] = ""
        return self.wsgi_app(environ, start_response)


app = create_app()
app.wsgi_app = FixVercelPath(app.wsgi_app)
