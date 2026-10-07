"""File-signature (magic-byte) analysis service.

Detects actual file type from magic bytes and compares with declared extension.
Never executes files — only reads leading bytes.
"""
from pathlib import Path

# Magic-byte table: (offset, magic bytes, detected label)
SIGNATURES = [
    (0, b"%PDF", "PDF", [".pdf"]),
    (0, b"\x89PNG\r\n\x1a\n", "PNG", [".png"]),
    (0, b"\xff\xd8\xff", "JPEG", [".jpg", ".jpeg", ".jfif"]),
    (0, b"GIF87a", "GIF", [".gif"]),
    (0, b"GIF89a", "GIF", [".gif"]),
    (0, b"PK\x03\x04", "ZIP", [".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk"]),
    (0, b"PK\x05\x06", "ZIP-EMPTY", [".zip"]),
    (0, b"PK\x07\x08", "ZIP-SPANNED", [".zip"]),
    (0, b"MZ", "PE-EXECUTABLE", [".exe", ".dll", ".sys", ".scr", ".com"]),
    (0, b"\x7fELF", "ELF-EXECUTABLE", ["", ".elf", ".so", ".bin"]),
    (0, b"#!/bin/bash", "SHELL-SCRIPT", [".sh"]),
    (0, b"#!/usr/bin/env", "SCRIPT-SHEBANG", [".sh", ".py"]),
    (0, b"BM", "BMP", [".bmp"]),
    (0, b"II*\x00", "TIFF", [".tif", ".tiff"]),
    (0, b"MM\x00*", "TIFF", [".tif", ".tiff"]),
    (0, b"RIFF", "RIFF/WAV/AVI", [".wav", ".avi", ".webp"]),
    (0, b"\x1f\x8b", "GZIP", [".gz", ".tgz"]),
    (0, b"BZh", "BZIP2", [".bz2"]),
    (0, b"%!PS", "POSTSCRIPT", [".ps", ".eps"]),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE-DOC", [".doc", ".xls", ".ppt", ".msi"]),
    (0, b"{\n", "JSON-OBJECT?", [".json"]),
    (0, b"MThd", "MIDI", [".mid", ".midi"]),
    (0, b"ID3", "MP3", [".mp3"]),
    (0, b"\xff\xfb", "MP3", [".mp3"]),
    (0, b"OggS", "OGG", [".ogg", ".oga"]),
    (0, b"fLaC", "FLAC", [".flac"]),
    (0, b"\x00\x00\x01\xba", "MPEG", [".mpg", ".mpeg"]),
]

TEXT_EXTENSIONS = {
    ".txt", ".log", ".csv", ".json", ".xml", ".html", ".htm", ".md",
    ".py", ".js", ".ps1", ".bat", ".sh", ".c", ".cpp", ".java", ".sql",
}


def detect_signature(file_path):
    """Return (signature_label, detected_type). Reads max 64 bytes header."""
    try:
        with open(file_path, "rb") as fh:
            header = fh.read(64)
    except OSError:
        return ("UNREADABLE", "unknown")
    if not header:
        return ("EMPTY-FILE", "empty")
    for _offset, magic, label, _exts in SIGNATURES:
        if header.startswith(magic):
            return (label, label)
    # Heuristic: printable ASCII => text
    try:
        sample = header[:512]
        text_chars = sum(1 for b in sample if 32 <= b <= 126 or b in (9, 10, 13))
        if len(sample) > 0 and text_chars / len(sample) > 0.85:
            return ("TEXT", "TEXT")
    except Exception:
        pass
    return ("UNKNOWN-BINARY", "unknown")


def expected_extensions_for(signature_label):
    for _off, _magic, label, exts in SIGNATURES:
        if label == signature_label:
            return exts
    if signature_label == "TEXT":
        return sorted(TEXT_EXTENSIONS)
    return []


def check_signature_match(declared_ext: str, signature_label: str):
    """Compare declared extension vs detected signature.

    Returns (match: bool, explanation: str).
    Text-like and unknown signatures are treated leniently to avoid false flags.
    """
    ext = (declared_ext or "").lower()
    if not ext:
        return (True, "No extension declared; signature recorded only.")
    if signature_label in ("EMPTY-FILE", "UNREADABLE"):
        return (True, f"Signature '{signature_label}' — no mismatch flagged.")
    if signature_label == "UNKNOWN-BINARY":
        # Only flag if extension claims a well-known magic-byte format
        known_magic_exts = {".pdf", ".png", ".jpg", ".jpeg", ".gif", ".zip", ".exe", ".dll"}
        if ext in known_magic_exts:
            return (False, f"Potential file-type mismatch: declared '{ext}' but magic bytes unrecognised.")
        return (True, "Binary content with no recognised signature; no mismatch flagged.")
    expected = [e.lower() for e in expected_extensions_for(signature_label)]
    if not expected:
        return (True, "Signature has no extension mapping; no mismatch flagged.")
    if ext in expected:
        return (True, f"Extension '{ext}' matches detected signature '{signature_label}'.")
    # TEXT detected but code/script/txt-like extensions are fine
    if signature_label == "TEXT" and ext in TEXT_EXTENSIONS:
        return (True, f"Extension '{ext}' consistent with TEXT content.")
    return (False, f"Potential file-type mismatch: declared '{ext}' but detected '{signature_label}'.")
