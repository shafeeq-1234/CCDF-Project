"""Integrity verification routes."""
import logging
from datetime import datetime, timezone

from flask import Blueprint, jsonify, render_template, request

from app import db
from app.models.file_record import FileRecord, IntegrityRecord
from app.services.custody import add_custody_event
from app.services.integrity import verify_file_integrity

log = logging.getLogger(__name__)
integrity_bp = Blueprint("integrity", __name__)
integrity_api = Blueprint("integrity_api", __name__)


@integrity_bp.route("/integrity")
def integrity_page():
    return render_template("integrity.html")


def _verify_one(fr: FileRecord):
    if not fr.integrity or not fr.integrity.original_sha256:
        return {"id": fr.id, "status": "ERROR", "error": "No baseline hash recorded."}
    res = verify_file_integrity(fr.full_path, fr.integrity.original_sha256)
    fr.integrity.current_sha256 = res["current"]
    fr.integrity.status = res["status"]
    fr.integrity.verified_at = datetime.now(timezone.utc)
    db.session.commit()
    add_custody_event(fr.case_id, evidence_id=fr.evidence_source_id, file_id=fr.id,
                      action="Integrity Verified",
                      description=f"Integrity {res['status']} for {fr.relative_path}",
                      prev_hash=res["original"], new_hash=res["current"])
    log.info("Integrity verify file=%s status=%s", fr.id, res["status"])
    return {"id": fr.id, "filename": fr.filename, "status": res["status"],
            "original": res["original"], "current": res["current"], "error": res["error"]}


@integrity_api.route("/api/evidence/<int:file_id>/verify", methods=["POST"])
def api_verify_one(file_id):
    fr = db.session.get(FileRecord, file_id)
    if not fr:
        return jsonify({"error": "File not found."}), 404
    return jsonify(_verify_one(fr))


@integrity_api.route("/api/integrity/verify-all", methods=["POST"])
def api_verify_all():
    data = request.get_json(force=True, silent=True) or {}
    case_id = data.get("case_id")
    q = FileRecord.query
    if case_id:
        q = q.filter(FileRecord.case_id == int(case_id))
    files = q.limit(5000).all()
    results = {"VERIFIED": 0, "MISMATCH": 0, "ERROR": 0}
    details = []
    for fr in files:
        try:
            r = _verify_one(fr)
            results[r["status"]] = results.get(r["status"], 0) + 1
            if r["status"] != "VERIFIED":
                details.append(r)
        except Exception as exc:
            results["ERROR"] += 1
            details.append({"id": fr.id, "status": "ERROR", "error": str(exc)})
    return jsonify({"summary": results, "mismatches": details[:100],
                    "checked": len(files)})
