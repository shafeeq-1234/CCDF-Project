"""Analysis pages + API."""
from flask import Blueprint, jsonify, render_template, request

from app import db
from app.models.file_record import AnalysisRecord, FileRecord

analysis_bp = Blueprint("analysis", __name__)
analysis_api = Blueprint("analysis_api", __name__)


@analysis_bp.route("/analysis")
def analysis_page():
    return render_template("analysis.html", file_id=None)


@analysis_api.route("/api/analysis/suspicious", methods=["GET"])
def api_suspicious():
    case_id = request.args.get("case_id", type=int)
    min_score = request.args.get("min_score", 25, type=int) or 25
    q = db.session.query(FileRecord, AnalysisRecord).join(AnalysisRecord, AnalysisRecord.file_id == FileRecord.id).filter(
        AnalysisRecord.suspicion_score >= min_score)
    if case_id:
        q = q.filter(FileRecord.case_id == case_id)
    q = q.order_by(AnalysisRecord.suspicion_score.desc()).limit(500)
    out = []
    for fr, ar in q.all():
        out.append({"id": fr.id, "filename": fr.filename, "relative_path": fr.relative_path,
                    "extension": fr.extension, "score": ar.suspicion_score,
                    "level": ar.suspicion_level, "reasons": ar.reasons})
    return jsonify(out)


@analysis_api.route("/api/evidence/<int:file_id>/metadata", methods=["GET"])
def api_metadata(file_id):
    fr = db.session.get(FileRecord, file_id)
    if not fr:
        return jsonify({"error": "File not found."}), 404
    return jsonify({m.key: m.value for m in fr.metadata_entries})
