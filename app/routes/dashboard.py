"""Dashboard routes (HTML + JSON API)."""
from flask import Blueprint, jsonify, render_template
from sqlalchemy import func

from app import db
from app.models.case import Case
from app.models.custody import CustodyEvent
from app.models.evidence import EvidenceSource
from app.models.file_record import AnalysisRecord, FileRecord, IntegrityRecord

dashboard_bp = Blueprint("dashboard", __name__)
dashboard_api = Blueprint("dashboard_api", __name__)


@dashboard_bp.route("/")
def index():
    return render_template("dashboard.html")


def _stats():
    total_cases = db.session.query(func.count(Case.id)).scalar() or 0
    total_files = db.session.query(func.count(FileRecord.id)).scalar() or 0
    suspicious = db.session.query(func.count(AnalysisRecord.id)).filter(AnalysisRecord.suspicion_score >= 25).scalar() or 0
    high_crit = db.session.query(func.count(AnalysisRecord.id)).filter(AnalysisRecord.suspicion_score >= 50).scalar() or 0
    verified = db.session.query(func.count(IntegrityRecord.id)).filter(IntegrityRecord.status == "VERIFIED").scalar() or 0
    mismatch = db.session.query(func.count(IntegrityRecord.id)).filter(IntegrityRecord.status == "MISMATCH").scalar() or 0
    custody = db.session.query(func.count(CustodyEvent.id)).scalar() or 0
    return {
        "total_cases": total_cases, "total_files": total_files,
        "suspicious": suspicious, "high_critical": high_crit,
        "verified": verified, "mismatch": mismatch, "custody_events": custody,
    }


@dashboard_api.route("/api/dashboard", methods=["GET"])
def api_dashboard():
    # File-type distribution
    rows = db.session.query(FileRecord.extension, func.count(FileRecord.id)).group_by(FileRecord.extension).all()
    file_types = {"labels": [r[0] or "(none)" for r in rows], "values": [r[1] for r in rows]}
    # Suspicion levels
    lvl_rows = db.session.query(AnalysisRecord.suspicion_level, func.count(AnalysisRecord.id)).group_by(AnalysisRecord.suspicion_level).all()
    lvl_map = {r[0]: r[1] for r in lvl_rows}
    suspicion = {"labels": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                 "values": [lvl_map.get("LOW", 0), lvl_map.get("MEDIUM", 0), lvl_map.get("HIGH", 0), lvl_map.get("CRITICAL", 0)]}
    # Integrity
    int_rows = db.session.query(IntegrityRecord.status, func.count(IntegrityRecord.id)).group_by(IntegrityRecord.status).all()
    int_map = {r[0]: r[1] for r in int_rows}
    integrity = {"labels": list(int_map.keys()) or ["NONE"], "values": list(int_map.values()) or [0]}
    # Size buckets
    files = db.session.query(FileRecord.size).all()
    buckets = {"<1 MB": 0, "1-10 MB": 0, "10-100 MB": 0, ">100 MB": 0}
    for (sz,) in files:
        sz = sz or 0
        if sz < 1024 * 1024:
            buckets["<1 MB"] += 1
        elif sz < 10 * 1024 * 1024:
            buckets["1-10 MB"] += 1
        elif sz < 100 * 1024 * 1024:
            buckets["10-100 MB"] += 1
        else:
            buckets[">100 MB"] += 1
    sizes = {"labels": list(buckets.keys()), "values": list(buckets.values())}
    # Timeline: files per scan day
    tl = db.session.query(func.date(FileRecord.scanned_at), func.count(FileRecord.id)).group_by(func.date(FileRecord.scanned_at)).order_by(func.date(FileRecord.scanned_at)).all()
    timeline = {"labels": [str(r[0]) for r in tl], "values": [r[1] for r in tl]}
    return jsonify({"stats": _stats(), "file_types": file_types, "suspicion": suspicion,
                    "integrity": integrity, "sizes": sizes, "timeline": timeline})
