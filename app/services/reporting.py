"""Forensic PDF report generation with ReportLab."""
import os
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def _table(data, col_widths=None):
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2332")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return t


def generate_case_report(case, evidence_sources, file_records, custody_events, integrity_summary, suspicion_summary, output_path):
    """Build a professional academic forensic PDF. Returns output_path."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    doc = SimpleDocTemplate(output_path, pagesize=A4, topMargin=0.6 * inch, bottomMargin=0.6 * inch)
    styles = getSampleStyleSheet()
    story = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    story.append(Paragraph("CYBERTRACE", styles["Title"]))
    story.append(Paragraph("Digital Forensic Evidence Analysis and Chain-of-Custody Report", styles["Heading2"]))
    story.append(Paragraph("Generated for academic and controlled forensic analysis purposes. "
                           "This report is not a legal certification of authenticity.", styles["Normal"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("1. Case Information", styles["Heading2"]))
    story.append(_table([
        ["Field", "Value"],
        ["Case Number", case.case_number],
        ["Title", case.title],
        ["Investigator", case.investigator],
        ["Status", case.status],
        ["Created", str(case.created_at)],
        ["Description", (case.description or "")[:1000]],
    ], col_widths=[1.6 * inch, 5.0 * inch]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("2. Evidence Sources", styles["Heading2"]))
    rows = [["ID", "Source Path", "Acquired", "Status", "Files"]]
    for ev in evidence_sources:
        rows.append([str(ev.id), (ev.source_path or "")[:80], str(ev.acquired_at), ev.status, str(len(ev.files))])
    story.append(_table(rows))
    story.append(Spacer(1, 12))

    story.append(Paragraph("3. File Inventory (first 100)", styles["Heading2"]))
    rows = [["File", "Size", "SHA-256 (short)", "Suspicion"]]
    for fr in file_records[:100]:
        sha = fr.hashes.sha256[:16] + "..." if fr.hashes and fr.hashes.sha256 else "-"
        lvl = fr.analysis.suspicion_level if fr.analysis else "LOW"
        score = fr.analysis.suspicion_score if fr.analysis else 0
        rows.append([(fr.relative_path or fr.filename)[:60], str(fr.size), sha, f"{lvl} ({score})"])
    story.append(_table(rows))
    story.append(Spacer(1, 12))

    story.append(Paragraph("4. Suspicious Evidence", styles["Heading2"]))
    story.append(Paragraph(f"Summary: {suspicion_summary}", styles["Normal"]))
    rows = [["File", "Score", "Level", "Reasons"]]
    flagged = [f for f in file_records if f.analysis and f.analysis.suspicion_score >= 25]
    for fr in flagged[:50]:
        rows.append([(fr.relative_path or fr.filename)[:50], str(fr.analysis.suspicion_score),
                     fr.analysis.suspicion_level, (", ".join(fr.analysis.reasons[:4]))[:120]])
    if len(rows) == 1:
        rows.append(["-", "-", "-", "No medium+ suspicion files."])
    story.append(_table(rows))
    story.append(Spacer(1, 12))

    story.append(Paragraph("5. Integrity Verification", styles["Heading2"]))
    story.append(Paragraph(f"Summary: {integrity_summary}", styles["Normal"]))
    story.append(Paragraph("SHA-256 is used as the primary integrity verification mechanism.", styles["Normal"]))
    rows = [["File", "Original (short)", "Current (short)", "Status"]]
    for fr in file_records[:100]:
        if fr.integrity:
            o = (fr.integrity.original_sha256 or "")[:16]
            c = (fr.integrity.current_sha256 or "")[:16]
            rows.append([(fr.relative_path or fr.filename)[:50], o, c, fr.integrity.status])
    if len(rows) == 1:
        rows.append(["-", "-", "-", "No integrity records."])
    story.append(_table(rows))
    story.append(Spacer(1, 12))

    story.append(Paragraph("6. Chain of Custody", styles["Heading2"]))
    rows = [["Timestamp", "Action", "Actor", "Description"]]
    for ev in custody_events:
        rows.append([str(ev.timestamp), ev.action, ev.actor, (ev.description or "")[:100]])
    if len(rows) == 1:
        rows.append(["-", "-", "-", "No custody events."])
    story.append(_table(rows))
    story.append(Spacer(1, 12))

    story.append(Paragraph("7. Conclusion", styles["Heading2"]))
    story.append(Paragraph(
        "This report summarises read-only forensic analysis (enumeration, metadata, hashing, "
        "file-signature checks, rule-based suspicion scoring, integrity verification, and chain-of-custody logging). "
        "Files labelled 'potentially suspicious' are heuristic flags only and were never executed. "
        "Integrity results reflect hash equality at verification time, not attribution of any change.",
        styles["Normal"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"Generated by CyberTrace on {now}.", styles["Normal"]))

    doc.build(story)
    return output_path
