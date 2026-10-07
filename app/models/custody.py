"""Chain-of-custody event model (append-only)."""
from datetime import datetime, timezone

from app import db


def _utcnow():
    return datetime.now(timezone.utc)


class CustodyEvent(db.Model):
    __tablename__ = "custody_events"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False, index=True)
    evidence_id = db.Column(db.Integer, db.ForeignKey("evidence_sources.id"), nullable=True, index=True)
    file_id = db.Column(db.Integer, db.ForeignKey("file_records.id"), nullable=True)
    actor = db.Column(db.String(128), nullable=False, default="Student Investigator")
    action = db.Column(db.String(64), nullable=False, index=True)
    description = db.Column(db.Text, default="")
    prev_hash = db.Column(db.String(128), default="")
    new_hash = db.Column(db.String(128), default="")
    timestamp = db.Column(db.DateTime, default=_utcnow, index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "file_id": self.file_id,
            "actor": self.actor,
            "action": self.action,
            "description": self.description,
            "prev_hash": self.prev_hash,
            "new_hash": self.new_hash,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }
