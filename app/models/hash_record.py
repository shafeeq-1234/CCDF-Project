"""Hash record model."""
from datetime import datetime, timezone

from app import db


def _utcnow():
    return datetime.now(timezone.utc)


class HashRecord(db.Model):
    __tablename__ = "hash_records"

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey("file_records.id"), nullable=False, unique=True, index=True)
    md5 = db.Column(db.String(64), default="")
    sha1 = db.Column(db.String(64), default="")
    sha256 = db.Column(db.String(128), default="")
    calculated_at = db.Column(db.DateTime, default=_utcnow)
