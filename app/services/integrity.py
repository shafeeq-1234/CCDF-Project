"""Integrity verification service."""
from app.services.hashing import sha256_of_file


def verify_file_integrity(file_path, original_sha256):
    """Recompute SHA-256 and compare with original.

    Returns dict(status, original, current, changed:bool, error).
    Status: VERIFIED | MISMATCH | ERROR.
    """
    try:
        current = sha256_of_file(file_path)
    except FileNotFoundError:
        return {"status": "ERROR", "original": original_sha256, "current": "",
                "changed": True, "error": "File not found — may have been moved or deleted."}
    except OSError as exc:
        return {"status": "ERROR", "original": original_sha256, "current": "",
                "changed": True, "error": f"Cannot read file: {exc}"}
    if current == original_sha256:
        return {"status": "VERIFIED", "original": original_sha256, "current": current,
                "changed": False, "error": ""}
    return {"status": "MISMATCH", "original": original_sha256, "current": current,
            "changed": True,
            "error": "Hash mismatch detected — the file contents have changed since the recorded hash."}
