"""Integrity tests."""
from app.services.integrity import verify_file_integrity
from app.services.hashing import sha256_of_file


def test_verify_ok(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"data123")
    orig = sha256_of_file(str(f))
    res = verify_file_integrity(str(f), orig)
    assert res["status"] == "VERIFIED"


def test_mismatch_detected(tmp_path):
    f = tmp_path / "y.bin"
    f.write_bytes(b"aaa")
    res = verify_file_integrity(str(f), "0" * 64)
    assert res["status"] == "MISMATCH"
    assert "changed" in res["error"].lower()


def test_missing_file():
    res = verify_file_integrity("C:/definitely/not/here.bin", "0" * 64)
    assert res["status"] == "ERROR"
