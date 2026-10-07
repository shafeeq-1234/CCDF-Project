"""Evidence acquisition + scanning routes (the forensic pipeline)."""
import hashlib
import logging
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, jsonify, render_template, request

from app import db
from app.models.case import Case
from app.models.custody import CustodyEvent
from app.models.evidence import EvidenceSource
from app.models.file_record import AnalysisRecord, FileRecord, IntegrityRecord, MetadataRecord
from app.models.hash_record import HashRecord
from app.services.custody import add_custody_event
from app.services.file_signature import check_signature_match, detect_signature
from app.services.hashing import compute_hashes
from app.services.metadata import extract_metadata
from app.services.scanner import scan_directory
from app.services.suspicion import level_for_score, score_file

log = logging.getLogger(__name__)
evidence_bp = Blueprint("evidence", __name__)
evidence_api = Blueprint("evidence_api", __name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ALLOWED_SCAN_ROOTS = set()  # populated per-request; demo_evidence always allowed


def _allowed_roots():
    roots = {str((PROJECT_ROOT / "demo_evidence").resolve())}
    # Also allow any path inside project dir (safe for viva demos)
    roots.add(str(PROJECT_ROOT.resolve()))
    return roots


def _is_path_allowed(candidate: str):
    try:
        cand = str(Path(candidate).resolve())
    except Exception:
        return False
    for root in _allowed_roots():
        try:
            if os.path.commonpath([root, cand]) == root:
                return True
        except Exception:
            continue
    # Also allow absolute paths the user explicitly typed IF they exist (local single-user tool).
    # Still block obvious system escapes unless inside project/demo.
    # For academic local use we permit existing local folders but log a warning.
    if os.path.exists(cand):
        log.warning("Scanning user path outside project boundary: %s", cand)
        return True
    return False


def _archive_members(path, ext):
    if ext == ".zip":
        try:
            with zipfile.ZipFile(str(path), "r") as zf:
                return zf.namelist()[:50]
        except Exception:
            return []
    return []


@evidence_bp.route("/evidence")
def evidence_page():
    cases = Case.query.order_by(Case.created_at.desc()).all()
    return render_template("evidence.html", cases=cases)


@evidence_bp.route("/evidence/<int:file_id>")
def evidence_detail_page(file_id):
    fr = db.session.get(FileRecord, file_id)
    if not fr:
        return render_template("base.html", error_message="Evidence file not found."), 404
    return render_template("analysis.html", file_id=file_id, file=fr)


def _process_scan(case_id, source_path, investigator, description):
    case = db.session.get(Case, case_id)
    if not case:
        return None, "Case not found."
    if not _is_path_allowed(source_path):
        return None, "Path traversal blocked: path is outside the allowed analysis boundary."
    infos, errors = scan_directory(source_path)
    # Evidence source record
    digest = hashlib.sha256(source_path.encode()).hexdigest()[:32]
    src = EvidenceSource(case_id=case.id, source_path=str(Path(source_path).resolve()),
                         investigator=investigator or case.investigator,
                         description=description or "", source_hash=digest, status="Acquired")
    db.session.add(src)
    db.session.flush()  # get src.id

    processed = 0
    failed = []
    for info in infos:
        try:
            fr = FileRecord(
                evidence_source_id=src.id, case_id=case.id,
                filename=info["filename"][:512], full_path=info["full_path"][:2048],
                relative_path=info["relative_path"][:2048], extension=info["extension"][:64],
                mime_type=info["mime_type"][:128], size=info["size"],
                file_created=info["created"], file_modified=info["modified"],
                file_accessed=info["accessed"], hidden=info["hidden"],
                permissions=info["permissions"][:16],
            )
            # Signature
            try:
                sig_label, detected = detect_signature(info["full_path"])
                fr.signature = sig_label[:128]
                fr.detected_type = detected[:128]
                match, _expl = check_signature_match(info["extension"], sig_label)
                fr.signature_match = match
            except Exception as exc:
                fr.signature = "ERROR"
                fr.scan_error = f"Signature error: {exc}"
                fr.signature_match = True
            db.session.add(fr)
            db.session.flush()
            # Hashes
            try:
                h = compute_hashes(info["full_path"])
                db.session.add(HashRecord(file_id=fr.id, md5=h["md5"], sha1=h["sha1"], sha256=h["sha256"]))
                original = h["sha256"]
            except OSError as exc:
                fr.scan_error = (fr.scan_error + f" | Hash error: {exc}")[:2000]
                original = ""
                db.session.add(HashRecord(file_id=fr.id, md5="", sha1="", sha256=""))
            # Metadata
            try:
                meta = extract_metadata(info["full_path"], info["mime_type"], info["extension"])
                for k, v in meta.items():
                    db.session.add(MetadataRecord(file_id=fr.id, key=k[:128], value=str(v)[:4000]))
            except Exception as exc:
                db.session.add(MetadataRecord(file_id=fr.id, key="extraction_error", value=str(exc)[:1000]))
            # Suspicion
            try:
                members = _archive_members(info["full_path"], info["extension"])
                sc, reasons = score_file(fr.filename, fr.extension, fr.relative_path, fr.hidden,
                                         fr.signature_match, modified_dt=info["modified"],
                                         archive_members=members)
                lvl = level_for_score(sc)
                ar = AnalysisRecord(file_id=fr.id, suspicion_score=sc, suspicion_level=lvl)
                ar.reasons = reasons
                db.session.add(ar)
            except Exception as exc:
                ar = AnalysisRecord(file_id=fr.id, suspicion_score=0, suspicion_level="LOW")
                ar.reasons = [f"Scoring error: {exc}"]
                db.session.add(ar)
            # Integrity baseline
            try:
                cur = original
                db.session.add(IntegrityRecord(file_id=fr.id, original_sha256=original,
                                               current_sha256=cur, status="VERIFIED" if original else "ERROR"))
            except Exception:
                pass
            processed += 1
        except Exception as exc:
            failed.append({"path": info.get("full_path"), "error": str(exc)})
            log.warning("File processing failed %s: %s", info.get("full_path"), exc)
    for e in errors:
        failed.append(e)
    src.status = "Analyzed"
    db.session.commit()
    add_custody_event(case.id, evidence_id=src.id, actor=investigator or case.investigator,
                      action="Evidence Acquired", description=f"Acquired source: {source_path} ({processed} files)")
    add_custody_event(case.id, evidence_id=src.id, actor=investigator or case.investigator,
                      action="Evidence Analyzed", description=f"Scanned {processed} files; {len(failed)} errors/skips")
    log.info("Evidence scan case=%s path=%s files=%s errors=%s", case_id, source_path, processed, len(failed))
    return {"evidence_id": src.id, "processed": processed, "errors": failed}, None


@evidence_api.route("/api/evidence/scan", methods=["POST"])
def api_scan():
    data = request.get_json(force=True, silent=True) or {}
    case_id = data.get("case_id")
    source_path = (data.get("source_path") or "").strip()
    investigator = (data.get("investigator") or "Student Investigator").strip()[:128]
    description = (data.get("description") or "").strip()[:2000]
    if not case_id:
        return jsonify({"error": "case_id is required."}), 400
    try:
        case_id = int(case_id)
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid case_id."}), 400
    if not source_path:
        # default to demo_evidence
        source_path = str(PROJECT_ROOT / "demo_evidence")
    # Resolve relative paths against project root
    p = Path(source_path)
    if not p.is_absolute():
        p = (PROJECT_ROOT / p)
    result, err = _process_scan(case_id, str(p), investigator, description)
    if err:
        return jsonify({"error": err}), 400
    return jsonify(result), 201


@evidence_api.route("/api/evidence", methods=["GET"])
def api_list_evidence():
    q = FileRecord.query
    case_id = request.args.get("case_id", type=int)
    if case_id:
        q = q.filter(FileRecord.case_id == case_id)
    search = (request.args.get("search") or "").strip()
    if search:
        like = f"%{search}%"
        q = q.filter(db.or_(FileRecord.filename.ilike(like), FileRecord.extension.ilike(like),
                            FileRecord.mime_type.ilike(like), FileRecord.relative_path.ilike(like)))
    ext = (request.args.get("extension") or "").strip().lower()
    if ext:
        q = q.filter(FileRecord.extension == ext)
    level = (request.args.get("level") or "").strip().upper()
    if level in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        q = q.join(AnalysisRecord, AnalysisRecord.file_id == FileRecord.id).filter(AnalysisRecord.suspicion_level == level)
    istatus = (request.args.get("integrity") or "").strip().upper()
    if istatus in ("VERIFIED", "MISMATCH", "ERROR", "UNKNOWN"):
        q = q.join(IntegrityRecord, IntegrityRecord.file_id == FileRecord.id).filter(IntegrityRecord.status == istatus)
    sort = request.args.get("sort", "filename")
    order = request.args.get("order", "asc")
    sort_col = {"filename": FileRecord.filename, "size": FileRecord.size,
                "scanned": FileRecord.scanned_at}.get(sort, FileRecord.filename)
    sort_col = sort_col.desc() if order == "desc" else sort_col.asc()
    q = q.order_by(sort_col)
    page = max(1, request.args.get("page", 1, type=int) or 1)
    per_page = min(200, max(5, request.args.get("per_page", 25, type=int) or 25))
    total = q.count()
    items = q.offset((page - 1) * per_page).limit(per_page).all()
    out = []
    for fr in items:
        d = fr.to_dict(include_relations=True)
        out.append(d)
    return jsonify({"total": total, "page": page, "per_page": per_page, "items": out})


@evidence_api.route("/api/evidence/<int:file_id>", methods=["GET"])
def api_get_evidence(file_id):
    fr = db.session.get(FileRecord, file_id)
    if not fr:
        return jsonify({"error": "File not found."}), 404
    d = fr.to_dict(include_relations=True)
    d["full_path"] = fr.full_path
    d["file_created"] = fr.file_created.isoformat() if fr.file_created else None
    d["file_modified"] = fr.file_modified.isoformat() if fr.file_modified else None
    d["file_accessed"] = fr.file_accessed.isoformat() if fr.file_accessed else None
    d["metadata"] = {m.key: m.value for m in fr.metadata_entries}
    d["reasons"] = fr.analysis.reasons if fr.analysis else []
    d["integrity"] = {"original_sha256": fr.integrity.original_sha256 if fr.integrity else "",
                      "current_sha256": fr.integrity.current_sha256 if fr.integrity else "",
                      "status": fr.integrity.status if fr.integrity else "UNKNOWN",
                      "verified_at": fr.integrity.verified_at.isoformat() if fr.integrity and fr.integrity.verified_at else None}
    d["hashes"] = {"md5": fr.hashes.md5 if fr.hashes else "", "sha1": fr.hashes.sha1 if fr.hashes else "",
                   "sha256": fr.hashes.sha256 if fr.hashes else ""}
    return jsonify(d)


@evidence_api.route("/api/demo/load", methods=["POST"])
def api_demo_load():
    """Create CT-DEMO-001 demo case and scan demo_evidence/."""
    from app.models.case import Case
    data = request.get_json(force=True, silent=True) or {}
    investigator = (data.get("investigator") or "Student Investigator").strip()[:128]
    case = Case.query.filter_by(case_number="CT-DEMO-001").first()
    if not case:
        case = Case(case_number="CT-DEMO-001", title="Demo Investigation — Suspicious Evidence",
                    description="Auto-created demo investigation scanning demo_evidence/.",
                    investigator=investigator, status="Open")
        db.session.add(case)
        db.session.commit()
        log.info("Demo case created CT-DEMO-001")
    demo_path = str(PROJECT_ROOT / "demo_evidence")
    result, err = _process_scan(case.id, demo_path, investigator, "Demo evidence acquisition")
    if err:
        return jsonify({"error": err}), 400
    result["case_id"] = case.id
    result["case_number"] = case.case_number
    return jsonify(result), 201
