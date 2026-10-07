"""Custody + report + metadata tests."""
from app import create_app, db
from app.models.case import Case
from app.services.custody import add_custody_event
from app.services.metadata import extract_metadata


def _app(tmp_path):
    return create_app({"TESTING": True, "WTF_CSRF_ENABLED": False,
                       "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"})


def test_custody_append(tmp_path):
    app = _app(tmp_path)
    with app.app_context():
        c = Case(case_number="CT-T-001", title="t", investigator="tester")
        db.session.add(c)
        db.session.commit()
        e1 = add_custody_event(c.id, actor="tester", action="Evidence Acquired", description="first")
        e2 = add_custody_event(c.id, actor="tester", action="Evidence Reviewed", description="second")
        assert e2.id > e1.id


def test_metadata_text(tmp_path):
    f = tmp_path / "s.log"
    f.write_text("line1\nline2\n")
    m = extract_metadata(str(f), "text/plain", ".log")
    assert "text_size_bytes" in m


def test_report_generation(tmp_path):
    from app.models.evidence import EvidenceSource
    from app.services.reporting import generate_case_report
    app = _app(tmp_path)
    with app.app_context():
        c = Case(case_number="CT-R-001", title="report test", investigator="tester", description="d")
        db.session.add(c)
        db.session.commit()
        out = str(tmp_path / "r.pdf")
        generate_case_report(c, [], [], [], "none", "none", out)
        import os
        assert os.path.exists(out) and os.path.getsize(out) > 1000
