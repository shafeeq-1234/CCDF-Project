"""Generate safe demo evidence dataset (harmless dummy files only)."""
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "demo_evidence"


def wtext(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def main():
    # Documents
    wtext(ROOT / "documents" / "report.txt", "CyberTrace demo report.\nThis is a harmless academic test file.\n" * 10)
    wtext(ROOT / "documents" / "notes.txt", "Investigation notes line.\n" * 30)
    wtext(ROOT / "documents" / "timeline.csv", "date,event\n2026-01-01,acquired\n2026-01-02,analysed\n")
    wtext(ROOT / "documents" / "readme.md", "# Demo evidence\nHarmless files for forensic testing.\n")
    # PDF (minimal valid)
    try:
        from pypdf import PdfWriter
        pdf_path = ROOT / "documents" / "report.pdf"
        pdf_path.parent.mkdir(parents=True, exist_ok=True)
        writer = PdfWriter()
        writer.add_blank_page(width=595, height=842)
        writer.add_blank_page(width=595, height=842)
        with open(pdf_path, "wb") as fh:
            writer.write(fh)
    except Exception:
        wtext(ROOT / "documents" / "report.pdf", "%PDF-1.4 harmless demo\n")
    # DOCX
    try:
        from docx import Document
        p = ROOT / "documents" / "sample.docx"
        p.parent.mkdir(parents=True, exist_ok=True)
        doc = Document()
        doc.add_heading("CyberTrace Demo Document", 1)
        doc.add_paragraph("Harmless academic test document for metadata extraction.")
        core = doc.core_properties
        core.author = "Student Investigator"
        core.title = "Demo DOCX"
        doc.save(str(p))
    except Exception:
        wtext(ROOT / "documents" / "sample.docx", "harmless placeholder")
    for i in range(3):
        wtext(ROOT / "documents" / f"memo_{i+1}.txt", f"Memo {i+1} harmless content.\n" * 20)
    # Images via Pillow
    try:
        from PIL import Image
        imgdir = ROOT / "images"
        imgdir.mkdir(parents=True, exist_ok=True)
        for name, color in [("sample.jpg", "red"), ("sample.png", "blue"), ("photo1.jpg", "green"), ("diagram.png", "orange")]:
            img = Image.new("RGB", (320, 200), color=color)
            img.save(str(imgdir / name))
    except Exception:
        wtext(ROOT / "images" / "sample.txt", "image placeholder")
    # Logs
    wtext(ROOT / "logs" / "system.log", "".join(f"2026-01-0{(i%9)+1} 10:00:0{i%10} INFO systemd service started\n" for i in range(60)))
    wtext(ROOT / "logs" / "access.log", "".join(f'192.168.1.{(i%20)+1} - - GET /page{i} 200\n' for i in range(60)))
    wtext(ROOT / "logs" / "auth.log", "".join(f"Jan {(i%28)+1} 12:00:00 host sshd: Accepted session {i}\n" for i in range(40)))
    # Archives
    arch = ROOT / "archives"
    arch.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(str(arch / "sample.zip"), "w") as zf:
        zf.writestr("inner_readme.txt", "Harmless archive content.\n" * 20)
        zf.writestr("inner_data.csv", "a,b\n1,2\n3,4\n")
    with zipfile.ZipFile(str(arch / "backup.zip"), "w") as zf:
        zf.writestr("notes.txt", "backup notes harmless\n")
    # Suspicious samples — HARMLESS dummies to trigger rules only
    susp = ROOT / "suspicious_samples"
    susp.mkdir(parents=True, exist_ok=True)
    wtext(susp / "invoice.pdf.exe", "HARMLESS DUMMY FILE for forensic rule testing. Not executable code.\n")
    wtext(susp / "image.jpg.exe", "HARMLESS DUMMY FILE for forensic rule testing. Not executable code.\n")
    wtext(susp / "hidden_script.ps1", "# HARMLESS dummy PowerShell-named text file.\n# No malicious commands. For detection-rule testing only.\nWrite-Host 'hello'\n")
    wtext(susp / ".hidden_payload.txt", "Harmless hidden-file test.\n")
    wtext(susp / "payment_details.pdf.exe", "HARMLESS DUMMY double-extension test file.\n")
    wtext(susp / "fake_image.jpg", "This is actually plain text, not a JPEG — signature mismatch test.\n")
    # Misc extra to push over 20 files
    wtext(ROOT / "misc_data.json", '{"case": "demo", "harmless": true}\n')
    wtext(ROOT / "runme.bat", "@echo off\nREM harmless dummy batch text for rule testing\n echo hello\n")
    print(f"Demo dataset written under {ROOT}")
    print(f"Total files: {sum(1 for _ in ROOT.rglob('*') if _.is_file())}")


if __name__ == "__main__":
    main()
