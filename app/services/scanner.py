"""Evidence directory scanner — recursive, read-only, defensive."""
import mimetypes
import os
import stat
from datetime import datetime, timezone
from pathlib import Path


def _to_utc(ts):
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except Exception:
        return None


def is_hidden(path: Path) -> bool:
    try:
        if os.name == "nt":
            import ctypes
            attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
            if attrs != -1:
                return bool(attrs & 2)  # FILE_ATTRIBUTE_HIDDEN
            return path.name.startswith(".")
        return path.name.startswith(".")
    except Exception:
        return path.name.startswith(".")


def resolve_safe(root: Path, candidate: Path):
    """Ensure candidate stays inside root (path-traversal guard)."""
    try:
        root_r = root.resolve()
        cand_r = candidate.resolve() if candidate.exists() else (root_r / candidate.relative_to(root_r) if _is_relative(candidate, root_r) else root_r)
        # os.path.commonpath approach
        if os.path.commonpath([str(root_r), str(cand_r)]) != str(root_r):
            return None
        return cand_r
    except Exception:
        return None


def _is_relative(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except Exception:
        try:
            # fallback for string paths
            return os.path.commonpath([str(parent), str(child)]) == str(parent)
        except Exception:
            return False


def scan_directory(root_path, max_file_size=None):
    """Recursively enumerate files under root_path.

    Returns (file_infos:list[dict], errors:list[dict]).
    Never follows directory symlinks; never escapes root; never raises on bad files.
    Each file_info: filename, full_path, relative_path, extension, mime_type, size,
      created, modified, accessed, hidden, permissions.
    """
    root = Path(root_path)
    errors = []
    infos = []
    if not root.exists():
        return [], [{"path": str(root_path), "error": "Evidence path does not exist."}]
    if not root.is_dir():
        return [], [{"path": str(root_path), "error": "Evidence path is not a directory."}]

    root_resolved = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root_resolved, topdown=True, followlinks=False):
        # Prune symlinked dirs & anything escaping root
        pruned = []
        for d in list(dirnames):
            full = Path(dirpath) / d
            try:
                if full.is_symlink():
                    pruned.append(d)
                    continue
                # traversal guard
                if os.path.commonpath([str(root_resolved), str(full.resolve())]) != str(root_resolved):
                    pruned.append(d)
            except Exception as exc:
                errors.append({"path": str(full), "error": f"Directory check failed: {exc}"})
                pruned.append(d)
        for d in pruned:
            dirnames.remove(d)

        for fname in filenames:
            fpath = Path(dirpath) / fname
            try:
                # Skip symlinked files that point outside root
                if fpath.is_symlink():
                    try:
                        target = fpath.resolve()
                        if os.path.commonpath([str(root_resolved), str(target)]) != str(root_resolved):
                            errors.append({"path": str(fpath), "error": "Skipped symlink escaping evidence root."})
                            continue
                    except Exception:
                        errors.append({"path": str(fpath), "error": "Broken symlink skipped."})
                        continue
                try:
                    rel = fpath.relative_to(root_resolved)
                except ValueError:
                    errors.append({"path": str(fpath), "error": "Path traversal blocked."})
                    continue
                try:
                    st = fpath.stat()
                except OSError as exc:
                    errors.append({"path": str(fpath), "error": f"Cannot stat file: {exc}"})
                    continue
                if max_file_size and st.st_size > max_file_size:
                    errors.append({"path": str(fpath), "error": f"File exceeds scan limit ({st.st_size} bytes). Hashed/skipped carefully."})
                ext = fpath.suffix.lower()
                mime, _ = mimetypes.guess_type(fname)
                try:
                    hidden = is_hidden(fpath)
                except Exception:
                    hidden = fname.startswith(".")
                try:
                    perms = oct(stat.S_IMODE(st.st_mode))
                except Exception:
                    perms = ""
                infos.append({
                    "filename": fname,
                    "full_path": str(fpath),
                    "relative_path": str(rel),
                    "extension": ext,
                    "mime_type": mime or "application/octet-stream",
                    "size": st.st_size,
                    "created": _to_utc(getattr(st, "st_ctime", None)),
                    "modified": _to_utc(getattr(st, "st_mtime", None)),
                    "accessed": _to_utc(getattr(st, "st_atime", None)),
                    "hidden": hidden,
                    "permissions": perms,
                })
            except Exception as exc:  # per-file guard
                errors.append({"path": str(fpath), "error": f"Unexpected scan error: {exc}"})
    return infos, errors
