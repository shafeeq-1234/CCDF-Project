"""Cryptographic hashing service — MD5, SHA-1, SHA-256 with chunked reads."""
import hashlib

CHUNK_SIZE = 65536


def compute_hashes(file_path, chunk_size=CHUNK_SIZE):
    """Compute MD5, SHA-1, SHA-256 for a file via streaming reads.

    Returns dict with hex digests. Raises OSError on read failure.
    SHA-256 is the primary integrity hash for CyberTrace.
    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def sha256_of_file(file_path):
    h = hashlib.sha256()
    with open(file_path, "rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_of_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
