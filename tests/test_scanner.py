"""Scanner tests incl. traversal protection."""
from app.services.scanner import scan_directory


def test_scan_basic(tmp_path):
    (tmp_path / "a.txt").write_text("hi")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "b.log").write_text("log")
    infos, errors = scan_directory(str(tmp_path))
    names = {i["filename"] for i in infos}
    assert {"a.txt", "b.log"} <= names


def test_scan_missing_dir(tmp_path):
    infos, errors = scan_directory(str(tmp_path / "nope"))
    assert infos == [] and errors


def test_scan_skips_escaping_symlink(tmp_path):
    import os
    if os.name == "nt":
        return  # symlink privilege often unavailable on Windows CI
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    root = tmp_path / "root"
    root.mkdir()
    try:
        (root / "evil").symlink_to(outside)
    except OSError:
        return
    infos, _ = scan_directory(str(root))
    assert all("evil" not in i["filename"] for i in infos)
