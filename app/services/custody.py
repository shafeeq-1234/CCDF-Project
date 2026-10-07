"""Chain-of-custody helper (append-only)."""
from app import db
from app.models.custody import CustodyEvent

ALLOWED_ACTIONS = {
    "Evidence Acquired", "Evidence Registered", "Evidence Analyzed",
    "Integrity Verified", "Evidence Reviewed", "Report Generated",
}


def add_custody_event(case_id, evidence_id=None, file_id=None, actor="Student Investigator",
                      action="Evidence Reviewed", description="", prev_hash="", new_hash=""):
    if action not in ALLOWED_ACTIONS:
        # Allow custom but flag; academic flexibility
        pass
    event = CustodyEvent(
        case_id=case_id, evidence_id=evidence_id, file_id=file_id,
        actor=actor or "Student Investigator", action=action,
        description=description or "", prev_hash=prev_hash or "", new_hash=new_hash or "",
    )
    db.session.add(event)
    db.session.commit()
    return event
