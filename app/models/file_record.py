"""File, metadata, analysis and integrity records."""
import json
from datetime import datetime, timezone

from app import db


def _utcnow():
    return datetime.now(timezone.utc)


class FileRecord(db.Model):
    __tablename__ = "file_records"

    id = db.Column(db.Integer, primary_key=True)
    evidence_source_id = db.Column(db.Integer, db.ForeignKey("evidence_sources.id"), nullable=False, index=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False, index=True)
    filename = db.Column(db.String(512), nullable=False)
    full_path = db.Column(db.String(2048), nullable=False)
    relative_path = db.Column(db.String(2048), nullable=False)
    extension = db.Column(db.String(64), default="", index=True)
    mime_type = db.Column(db.String(128), default="", index=True)
    size = db.Column(db.Integer, default=0)
    file_created = db.Column(db.DateTime, nullable=True)
    file_modified = db.Column(db.DateTime, nullable=True)
    file_accessed = db.Column(db.DateTime, nullable=True)
    hidden = db.Column(db.Boolean, default=False)
    permissions = db.Column(db.String(16), default="")
    signature = db.Column(db.String(128), default="")
    detected_type = db.Column(db.String(128), default="")
    signature_match = db.Column(db.Boolean, default=True)
    scan_error = db.Column(db.Text, default="")
    scanned_at = db.Column(db.DateTime, default=_utcnow)

    hashes = db.relationship("HashRecord", backref="file", cascade="all, delete-orphan", lazy=True, uselist=False)
    metadata_entries = db.relationship("MetadataRecord", backref="file", cascade="all, delete-orphan", lazy=True)
    analysis = db.relationship("AnalysisRecord", backref="file", cascade="all, delete-orphan", lazy=True, uselist=False)
    integrity = db.relationship("IntegrityRecord", backref="file", cascade="all, delete-orphan", lazy=True, uselist=False)

    def to_dict(self, include_relations=False):
        d = {
            "id": self.id,
            "evidence_source_id": self.evidence_source_id,
            "case_id": self.case_id,
            "filename": self.filename,
            "relative_path": self.relative_path,
            "extension": self.extension,
            "mime_type": self.mime_type,
            "size": self.size,
            "hidden": self.hidden,
            "signature": self.signature,
            "detected_type": self.detected_type,
            "signature_match": self.signature_match,
            "scan_error": self.scan_error,
        }
        if include_relations:
            d["sha256"] = self.hashes.sha256 if self.hashes else None
            d["md5"] = self.hashes.md5 if self.hashes else None
            d["sha1"] = self.hashes.sha1 if self.hashes else None
            d["suspicion_score"] = self.analysis.suspicion_score if self.analysis else 0
            d["suspicion_level"] = self.analysis.suspicion_level if self.analysis else "LOW"
            d["integrity_status"] = self.integrity.status if self.integrity else "UNKNOWN"
        return d


class MetadataRecord(db.Model):
    __tablename__ = "metadata_records"

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey("file_records.id"), nullable=False, index=True)
    key = db.Column(db.String(128), nullable=False)
    value = db.Column(db.Text, default="")


class AnalysisRecord(db.Model):
    __tablename__ = "analysis_records"

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey("file_records.id"), nullable=False, unique=True, index=True)
    suspicion_score = db.Column(db.Integer, default=0)
    suspicion_level = db.Column(db.String(16), default="LOW", index=True)
    reasons_json = db.Column(db.Text, default="[]")
    analyzed_at = db.Column(db.DateTime, default=_utcnow)

    @property
    def reasons(self):
        try:
            return json.loads(self.reasons_json or "[]")
        except Exception:
            return []

    @reasons.setter
    def reasons(self, value):
        self.reasons_json = json.dumps(value or [])


class IntegrityRecord(db.Model):
    __tablename__ = "integrity_records"

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey("file_records.id"), nullable=False, unique=True, index=True)
    original_sha256 = db.Column(db.String(128), default="")
    current_sha256 = db.Column(db.String(128), default="")
    status = db.Column(db.String(32), default="UNKNOWN", index=True)
    verified_at = db.Column(db.DateTime, default=_utcnow)
