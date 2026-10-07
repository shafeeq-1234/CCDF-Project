"""Hashing tests."""
from pathlib import Path

from app.services.hashing import compute_hashes, sha256_of_bytes


def test_sha256_known_vector():
    assert sha256_of_bytes(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_compute_hashes_tmp(tmp_path):
    p = tmp_path / "a.txt"
    p.write_bytes(b"hello cybertrace")
    h = compute_hashes(str(p))
    assert len(h["md5"]) == 32
    assert len(h["sha1"]) == 40
    assert len(h["sha256"]) == 64
