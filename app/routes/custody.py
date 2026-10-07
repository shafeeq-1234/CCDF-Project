"""Chain-of-custody routes (append-only; no edit/delete from UI)."""
from flask import Blueprint, jsonify, render_template, request

from app import db
from app.models.custody import CustodyEvent
from app.services.custody import add_custody_event

custody_bp = Blueprint("custody", __name__)
custody_api = Blueprint("custody_api", __name__)


@custody_bp.route("/custody")
def custody_page():
    return render_template("custody.html")


@custody_api.route("/api/custody", methods=["GET"])
def api_list_custody():
    case_id = request.args.get("case_id", type=int)
    evidence_id = request.args.get("evidence_id", type=int)
    file_id = request.args.get("file_id", type=int)
    q = CustodyEvent.query
    if case_id:
        q = q.filter(CustodyEvent.case_id == case_id)
    if evidence_id:
        q = q.filter(CustodyEvent.evidence_id == evidence_id)
    if file_id:
        q = q.filter(CustodyEvent.file_id == file_id)
    events = q.order_by(CustodyEvent.timestamp.asc()).limit(2000).all()
    return jsonify([e.to_dict() for e in events])


@custody_api.route("/api/custody", methods=["POST"])
def api_add_custody():
    data = request.get_json(force=True, silent=True) or {}
    if not data.get("case_id"):
        return jsonify({"error": "case_id is required."}), 400
    try:
        ev = add_custody_event(
            case_id=int(data["case_id"]),
            evidence_id=int(data["evidence_id"]) if data.get("evidence_id") else None,
            file_id=int(data["file_id"]) if data.get("file_id") else None,
            actor=(data.get("actor") or "Student Investigator")[:128],
            action=(data.get("action") or "Evidence Reviewed")[:64],
            description=(data.get("description") or "")[:2000],
        )
    except Exception as exc:
        return jsonify({"error": f"Cannot record custody event: {exc}"}), 400
    return jsonify(ev.to_dict()), 201
