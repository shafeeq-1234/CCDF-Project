"""Evidence source model."""
from datetime import datetime, timezone

from app import db


def _utcnow():
    return datetime.now(timezone.utc)


class EvidenceSource(db.Model):
    __tablename__ = "evidence_sources"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False, index=True)
    source_path = db.Column(db.String(1024), nullable=False)
    acquired_at = db.Column(db.DateTime, default=_utcnow)
    investigator = db.Column(db.String(128), default="Student Investigator")
    description = db.Column(db.Text, default="")
    source_hash = db.Column(db.String(128), default="")
    status = db.Column(db.String(32), default="Acquired")

    files = db.relationship("FileRecord", backref="evidence_source", cascade="all, delete-orphan", lazy=True)

    def to_dict(self):
        return {
            "id": self.id,
            "case_id": self.case_id,
            "source_path": self.source_path,
            "acquired_at": self.acquired_at.isoformat() if self.acquired_at else None,
            "investigator": self.investigator,
            "description": self.description,
            "source_hash": self.source_hash,
            "status": self.status,
            "file_count": len(self.files) if self.files is not None else 0,
        }
