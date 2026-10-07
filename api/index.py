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
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import create_app  # noqa: E402

app = create_app()
