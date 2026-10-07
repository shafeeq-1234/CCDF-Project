"""CyberTrace entrypoint — local dev server AND Vercel deployment.

- Local:  ``python server.py``  (runs the Flask dev server)
- Vercel: ``server.py`` is one of Vercel's recognised Flask entrypoints, so
  Vercel detects the ``app`` object below as a framework preset and routes
  every request to it with the original URL path intact. (Do NOT rename this
  file back to ``app.py`` — that name collides with the ``app/`` package and
  crashes the deployment with ``ImportError: cannot import name
  'create_app'``.)

The ``if __name__ == "__main__"`` guard ensures the dev server only starts
for local runs, never when Vercel imports this module.
"""
import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=app.config.get("DEBUG", False))
