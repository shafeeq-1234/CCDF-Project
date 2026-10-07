"""Regression test: JSON API must work with CSRF protection enabled.

HTML forms stay CSRF-protected, but /api/* blueprints are exempt so the
JS frontend (and serverless deployments) can POST without a token.
"""
from app import create_app


def test_api_post_without_csrf_token():
    app = create_app({"TESTING": True})  # CSRF stays enabled (default)
    assert app.config["WTF_CSRF_ENABLED"]
    c = app.test_client()
    r = c.post("/api/cases", json={"title": "CSRF regression probe"})
    assert r.status_code == 201, r.data[:200]
    r2 = c.post("/api/demo/load", json={})
    assert r2.status_code == 201, r2.data[:200]
