"""Suspicion + signature tests."""
from app.services.file_signature import check_signature_match, detect_signature
from app.services.suspicion import level_for_score, score_file


def test_double_exe_scores_high():
    score, reasons = score_file("invoice.pdf.exe", ".exe", "suspicious_samples/invoice.pdf.exe",
                                False, False, modified_dt=None)
    assert score >= 50
    assert level_for_score(score) in ("HIGH", "CRITICAL")
    assert any("Double" in r for r in reasons)


def test_benign_txt_low(tmp_path):
    f = tmp_path / "notes.txt"
    f.write_text("hello")
    from app.services.file_signature import detect_signature
    sig, _ = detect_signature(str(f))
    match, _ = check_signature_match(".txt", sig)
    score, _ = score_file("notes.txt", ".txt", "documents/notes.txt", False, match)
    assert score < 25 and level_for_score(score) == "LOW"


def test_signature_mismatch(tmp_path):
    f = tmp_path / "fake.jpg"
    f.write_text("plain text, not jpeg")
    sig, _ = detect_signature(str(f))
    match, msg = check_signature_match(".jpg", sig)
    assert match is False
    assert "mismatch" in msg.lower()
