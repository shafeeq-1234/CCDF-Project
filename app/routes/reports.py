"""Forensic report routes."""
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, jsonify, render_template, request, send_file

from app import db
from app.models.case import Case
from app.models.custody import CustodyEvent
from app.models.file_record import FileRecord
from app.services.custody import add_custody_event
from app.services.reporting import generate_case_report

log = logging.getLogger(__name__)
reports_bp = Blueprint("reports", __name__)
reports_api = Blueprint("reports_api", __name__)
PROJECT_ROOT = Path(__file__).resolve().parents[2]


@reports_bp.route("/reports")
def reports_page():
    cases = Case.query.order_by(Case.created_at.desc()).all()
    return render_template("report.html", cases=cases)


@reports_api.route("/api/reports/<int:case_id>/generate", methods=["POST"])
def api_generate(case_id):
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({"error": "Case not found."}), 404
    data = request.get_json(force=True, silent=True) or {}
    actor = (data.get("actor") or case.investigator or "Student Investigator")[:128]
    files = FileRecord.query.filter_by(case_id=case.id).order_by(FileRecord.relative_path.asc()).all()
    sources = case.evidence_sources
    events = CustodyEvent.query.filter_by(case_id=case.id).order_by(CustodyEvent.timestamp.asc()).all()
    verified = sum(1 for f in files if f.integrity and f.integrity.status == "VERIFIED")
    mismatch = sum(1 for f in files if f.integrity and f.integrity.status == "MISMATCH")
    flagged = sum(1 for f in files if f.analysis and f.analysis.suspicion_score >= 25)
    integrity_summary = f"{verified} verified, {mismatch} mismatch out of {len(files)} files."
    suspicion_summary = f"{flagged} potentially suspicious files out of {len(files)}."
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    fname = f"CyberTrace-{case.case_number}-{ts}.pdf"
    out = str(PROJECT_ROOT / "reports" / fname)
    try:
        generate_case_report(case, sources, files, events, integrity_summary, suspicion_summary, out)
    except Exception as exc:
        log.exception("Report generation failed")
        return jsonify({"error": f"Report generation failed: {exc}"}), 500
    add_custody_event(case.id, actor=actor, action="Report Generated",
                      description=f"Forensic PDF report generated: {fname}")
    log.info("Report generated case=%s file=%s", case_id, fname)
    return jsonify({"filename": fname, "download_url": f"/api/reports/download/{fname}"}), 201


@reports_api.route("/api/reports/download/<path:filename>", methods=["GET"])
def api_download(filename):
    # Secure: only allow files inside reports/ with safe name
    safe = os.path.basename(filename)
    if safe != filename or not safe.lower().endswith(".pdf"):
        return jsonify({"error": "Invalid filename."}), 400
    full = PROJECT_ROOT / "reports" / safe
    if not full.exists():
        return jsonify({"error": "Report not found."}), 404
    return send_file(str(full), as_attachment=True, download_name=safe)
