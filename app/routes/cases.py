"""Case management routes."""
import logging
from datetime import datetime, timezone

from flask import Blueprint, jsonify, render_template, request

from app import db
from app.models.case import Case
from app.models.custody import CustodyEvent
from app.services.custody import add_custody_event

log = logging.getLogger(__name__)
cases_bp = Blueprint("cases", __name__)
cases_api = Blueprint("cases_api", __name__)


@cases_bp.route("/cases")
def cases_page():
    return render_template("cases.html")


@cases_bp.route("/cases/<int:case_id>")
def case_detail_page(case_id):
    case = db.session.get(Case, case_id)
    if not case:
        return render_template("base.html", error_message="Case not found."), 404
    return render_template("case_detail.html", case=case)


def _gen_case_number():
    year = datetime.now(timezone.utc).year
    count = db.session.query(Case).count() + 1
    return f"CT-{year}-{count:03d}"


@cases_api.route("/api/cases", methods=["GET"])
def api_list_cases():
    cases = Case.query.order_by(Case.created_at.desc()).all()
    return jsonify([c.to_dict() for c in cases])


@cases_api.route("/api/cases", methods=["POST"])
def api_create_case():
    data = request.get_json(force=True, silent=True) or {}
    title = (data.get("title") or "").strip()
    if not title:
        return jsonify({"error": "Case title is required."}), 400
    case_number = (data.get("case_number") or "").strip() or _gen_case_number()
    if Case.query.filter_by(case_number=case_number).first():
        return jsonify({"error": f"Case number {case_number} already exists."}), 400
    investigator = (data.get("investigator") or "Student Investigator").strip()[:128]
    status = (data.get("status") or "Open").strip()[:32]
    if status not in ("Open", "In Progress", "Closed"):
        status = "Open"
    case = Case(case_number=case_number, title=title[:256],
                description=(data.get("description") or "")[:5000],
                investigator=investigator, status=status)
    db.session.add(case)
    db.session.commit()
    log.info("Case created: %s", case_number)
    return jsonify(case.to_dict()), 201


@cases_api.route("/api/cases/<int:case_id>", methods=["GET"])
def api_get_case(case_id):
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({"error": "Case not found."}), 404
    sources = [
        {"id": s.id, "source_path": s.source_path, "status": s.status,
         "file_count": len(s.files), "acquired_at": s.acquired_at.isoformat() if s.acquired_at else None}
        for s in case.evidence_sources
    ]
    events = [e.to_dict() for e in CustodyEvent.query.filter_by(case_id=case.id).order_by(CustodyEvent.timestamp.asc()).all()]
    d = case.to_dict()
    d["evidence_sources"] = sources
    d["custody_events"] = events
    return jsonify(d)


@cases_api.route("/api/cases/<int:case_id>", methods=["PATCH", "PUT"])
def api_update_case(case_id):
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({"error": "Case not found."}), 404
    data = request.get_json(force=True, silent=True) or {}
    if "title" in data and data["title"].strip():
        case.title = data["title"].strip()[:256]
    if "description" in data:
        case.description = (data["description"] or "")[:5000]
    if "investigator" in data and data["investigator"].strip():
        case.investigator = data["investigator"].strip()[:128]
    if "status" in data and data["status"] in ("Open", "In Progress", "Closed"):
        case.status = data["status"]
    db.session.commit()
    return jsonify(case.to_dict())


@cases_api.route("/api/cases/<int:case_id>", methods=["DELETE"])
def api_delete_case(case_id):
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({"error": "Case not found."}), 404
    db.session.delete(case)
    db.session.commit()
    return jsonify({"ok": True})
