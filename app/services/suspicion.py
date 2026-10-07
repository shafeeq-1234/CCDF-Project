"""Explainable rule-based suspicion scoring (0-100)."""
from datetime import datetime, timezone
from pathlib import Path

EXECUTABLE_EXTS = {".exe", ".dll", ".sys", ".scr", ".com", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".apk"}
SCRIPT_EXTS = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".py", ".sh", ".pl", ".rb"}
ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".tar", ".gz"}

SUSPICIOUS_DIRS = {"temp", "tmp", "appdata", "startup", "system32", "windows", "suspicious_samples", "__macosx"}
SUSPICIOUS_KEYWORDS = {"invoice", "payment", "urgent", "free", "crack", "keygen", "password", "bank", "verify", "login"}

# Configurable weights
WEIGHTS = {
    "executable_extension": 20,
    "script_extension": 15,
    "double_extension": 30,
    "signature_mismatch": 30,
    "hidden_file": 10,
    "suspicious_location": 10,
    "unusual_filename": 10,
    "recent_modification": 5,
    "archive_with_executable": 15,
}


def level_for_score(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def _is_double_extension(filename: str) -> bool:
    parts = filename.split(".")
    # e.g. invoice.pdf.exe -> ['invoice','pdf','exe'] => double extension
    if len(parts) >= 3:
        # last part is executable-ish or any second extension present
        return True
    return False


def score_file(filename, extension, relative_path, hidden, signature_match,
               modified_dt=None, archive_members=None, now=None):
    """Return (score:int 0-100, reasons:list[str]).

    Pure function — easy to explain in viva and to unit test.
    """
    now = now or datetime.now(timezone.utc)
    ext = (extension or "").lower()
    reasons = []
    score = 0

    def add(key, reason):
        nonlocal score
        score += WEIGHTS.get(key, 0)
        reasons.append(reason)

    if ext in EXECUTABLE_EXTS and ext not in SCRIPT_EXTS:
        add("executable_extension", f"Executable extension '{ext}' (+{WEIGHTS['executable_extension']})")
    if ext in SCRIPT_EXTS:
        add("script_extension", f"Potentially suspicious script extension '{ext}' (+{WEIGHTS['script_extension']})")
    if _is_double_extension(filename):
        add("double_extension", f"Double extension in filename '{filename}' (+{WEIGHTS['double_extension']})")
    if signature_match is False:
        add("signature_mismatch", f"File-signature mismatch detected (+{WEIGHTS['signature_mismatch']})")
    if hidden:
        add("hidden_file", f"Hidden file (+{WEIGHTS['hidden_file']})")

    lowered_path = (relative_path or "").lower().replace("\\", "/")
    if any(d in lowered_path.split("/") for d in SUSPICIOUS_DIRS):
        add("suspicious_location", f"Suspicious location in path (+{WEIGHTS['suspicious_location']})")

    stem = Path(filename).stem.lower() if filename else ""
    if any(k in stem or k in filename.lower() for k in SUSPICIOUS_KEYWORDS) and (
        ext in EXECUTABLE_EXTS or _is_double_extension(filename)
    ):
        add("unusual_filename", f"Unusual/enticing filename '{filename}' (+{WEIGHTS['unusual_filename']})")

    if modified_dt is not None:
        try:
            mod = modified_dt
            if mod.tzinfo is None:
                mod = mod.replace(tzinfo=timezone.utc)
            delta = (now - mod).total_seconds()
            if 0 <= delta < 24 * 3600:
                add("recent_modification", f"Very recent modification (+{WEIGHTS['recent_modification']})")
        except Exception:
            pass

    if archive_members:
        for member in archive_members:
            m = str(member).lower()
            if any(m.endswith(e) for e in (".exe", ".dll", ".bat", ".ps1", ".scr", ".com")):
                add("archive_with_executable", f"Archive contains potentially executable entry '{member}' (+{WEIGHTS['archive_with_executable']})")
                break

    score = max(0, min(100, score))
    return score, reasons
