"""Metadata extraction — safe, read-only, per file type."""
import mimetypes
import zipfile
from pathlib import Path


def _safe_str(value, limit=500):
    if value is None:
        return ""
    s = str(value)
    return s[:limit]


def extract_metadata(file_path, mime_type="", extension=""):
    """Return dict of metadata key->value. Never raises; returns {} on failure."""
    meta = {}
    try:
        p = Path(file_path)
        ext = (extension or p.suffix).lower()
        meta["extension"] = ext
        meta["mime_type"] = mime_type or mimetypes.guess_type(str(p))[0] or "application/octet-stream"

        if ext in (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp"):
            meta.update(_image_metadata(file_path))
        elif ext == ".pdf":
            meta.update(_pdf_metadata(file_path))
        elif ext == ".docx":
            meta.update(_docx_metadata(file_path))
        elif ext in (".zip",):
            meta.update(_zip_metadata(file_path))
        elif ext in (".txt", ".log", ".csv", ".md", ".json", ".xml"):
            meta.update(_text_metadata(file_path))
    except Exception as exc:  # never crash a scan
        meta["extraction_error"] = _safe_str(exc)
    return meta


def _image_metadata(file_path):
    out = {}
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS
        with Image.open(file_path) as img:
            out["image_format"] = _safe_str(img.format)
            out["width"] = str(img.width)
            out["height"] = str(img.height)
            out["mode"] = _safe_str(img.mode)
            try:
                exif = img.getexif()
                if exif:
                    count = 0
                    for tag_id, value in exif.items():
                        tag = TAGS.get(tag_id, str(tag_id))
                        if tag in ("GPSInfo", "Make", "Model", "DateTime", "Software"):
                            out[f"exif_{tag}"] = _safe_str(value)
                            count += 1
                            if count >= 10:
                                break
                    out["exif_entries"] = str(len(exif))
            except Exception:
                pass
    except Exception as exc:
        out["image_error"] = _safe_str(exc)
    return out


def _pdf_metadata(file_path):
    out = {}
    try:
        from pypdf import PdfReader
        reader = PdfReader(str(file_path))
        out["page_count"] = str(len(reader.pages))
        info = reader.metadata
        if info:
            for key in ("author", "creator", "producer", "title", "subject", "creation_date", "modification_date"):
                try:
                    val = getattr(info, key, None)
                    if val:
                        out[f"pdf_{key}"] = _safe_str(val)
                except Exception:
                    continue
    except Exception as exc:
        out["pdf_error"] = _safe_str(exc)
    return out


def _docx_metadata(file_path):
    out = {}
    try:
        from docx import Document
        doc = Document(str(file_path))
        core = doc.core_properties
        mapping = {
            "author": core.author, "last_modified_by": core.last_modified_by,
            "created": core.created, "modified": core.modified,
            "revision": core.revision, "title": core.title, "subject": core.subject,
        }
        for k, v in mapping.items():
            if v:
                out[f"docx_{k}"] = _safe_str(v)
        out["paragraph_count"] = str(len(doc.paragraphs))
    except Exception as exc:
        out["docx_error"] = _safe_str(exc)
    return out


def _zip_metadata(file_path):
    out = {}
    try:
        with zipfile.ZipFile(str(file_path), "r") as zf:
            names = zf.namelist()
            out["archive_entries"] = str(len(names))
            total = 0
            for info in zf.infolist():
                total += info.file_size
                if total > 10**12:
                    break
            out["archive_uncompressed_size"] = str(total)
            out["archive_entry_names"] = _safe_str(", ".join(names[:20]), limit=1000)
    except Exception as exc:
        out["archive_error"] = _safe_str(exc)
    return out


def _text_metadata(file_path):
    out = {}
    try:
        p = Path(file_path)
        size = p.stat().st_size
        out["text_size_bytes"] = str(size)
        # Count lines safely (first 1 MB only)
        lines = 0
        with open(file_path, "rb") as fh:
            chunk = fh.read(1024 * 1024)
            lines = chunk.count(b"\n")
        out["approx_lines_first_mb"] = str(lines)
    except Exception as exc:
        out["text_error"] = _safe_str(exc)
    return out
