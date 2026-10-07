# CyberTrace — Digital Forensic Evidence Analysis and Chain-of-Custody System

Academic CCDF project: a **real working** local web app for forensic evidence acquisition,
file enumeration, metadata extraction, hashing (MD5/SHA-1/**SHA-256 primary**),
file-signature checks, rule-based suspicion scoring, integrity verification,
chain-of-custody logging, dashboard charts, and PDF reporting.

> Academic / controlled-analysis use only. "Potentially suspicious" is a heuristic flag —
> never confirmed malware. Files are never executed. Hashing proves integrity, not authenticity.

## Features
- Case management (CT-YYYY-NNN), evidence acquisition (read-only folder scan)
- Recursive enumeration: name, paths, ext, MIME, size, timestamps, hidden, permissions
- Streaming MD5/SHA-1/SHA-256; SHA-256 baseline stored per file
- Metadata: images (Pillow + EXIF), PDF (pypdf), DOCX (python-docx), ZIP, text
- Magic-byte signature vs extension → "Potential file-type mismatch"
- Explainable suspicion score 0–100 (LOW/MEDIUM/HIGH/CRITICAL) with reasons
- Integrity re-verify (VERIFIED / MISMATCH with before/after hashes)
- Append-only chain of custody timeline
- Dashboard with 5 Chart.js graphs from live DB data + searchable/sortable tables
- ReportLab PDF forensic report + "Load Demo Investigation" one-click demo

## Architecture
```
DIGITAL EVIDENCE → Acquisition → Enumeration → Metadata + Hashing → Analysis
 (suspicion + signature) → Integrity → Chain of Custody → Dashboard/Reports
```

## Tech stack
Python 3.11+, Flask, SQLAlchemy, SQLite, Bootstrap 5, Chart.js, Pillow, pypdf,
python-docx, ReportLab, pytest.

## Project structure
See `/app` (models/routes/services/templates/static), `/tests`, `/demo_evidence`, `/reports`, `app.py`, `config.py`.

## Installation
```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
# source venv/bin/activate
pip install -r requirements.txt
```

## Running
```bash
python app.py
# open http://127.0.0.1:5000
```
Database auto-creates at `instance/cybertrace.db`. Copy `.env.example` to `.env` to override secret/debug.

## Demo workflow (viva, ~3 minutes)
1. Open `/` → Dashboard.
2. Cases → **Load Demo Investigation** (creates CT-DEMO-001, scans `demo_evidence/`, ~25 files).
3. Evidence → search/filter/sort, click e.g. `invoice.pdf.exe` → score ~85 CRITICAL with reasons, SHA-256, metadata.
4. Integrity → Verify All → all VERIFIED; edit a demo file manually → re-verify → ⚠ MISMATCH with before/after.
5. Custody → timeline; Reports → Generate → Download PDF.

## Testing
```bash
pytest -q
```

## Security considerations
Read-only scans, no symlink escape, path-traversal guard, per-file error isolation,
no execution of evidence, parameterised ORM queries, CSRF on forms (API exempt),
size limits via config, no secrets in repo, no stack traces in production.

## Limitations
Heuristic — not a certified forensic tool; no deleted-file recovery, no disk imaging,
no timeline carving; signature table covers common types; large repos may need pagination.

## Future enhancements
Timeline visualisation, YARA-style rule packs (opt-in), multi-user auth, export CSV/JSON,
hash-set lookup, deduplication view.

## Deploying to Vercel (demo / evaluation hosting)

The repo includes `api/index.py` (serverless Flask handler) and `vercel.json`
(rewrite all requests to the handler, 60 s function timeout).

```bash
git add api/index.py vercel.json config.py app/__init__.py app/routes/reports.py tests/test_csrf_api.py
git commit -m "Add Vercel serverless deployment support"
git push
# then: Vercel dashboard → Add New Project → import this repo → Deploy
```

No extra configuration is needed. Vercel auto-detects Python from
`requirements.txt`. Optional environment variable for production:
`CYBERTRACE_SECRET_KEY` (random string for session signing).

Serverless caveats (important for viva/demo):
- The filesystem is read-only except `/tmp`, so the app automatically stores
  the SQLite database and generated PDFs under `/tmp` when `VERCEL=1` is set.
- Data is **ephemeral**: each cold start / instance gets a fresh empty
  database. Click **Load Demo Investigation** after every fresh visit to
  repopulate the demo case.
- For persistent local use (full chain-of-custody history), run `python app.py`
  locally instead — the local SQLite file persists normally.

## Academic disclaimer
Built for coursework demonstration and IEEE-style reporting (metrics, tables, charts from real runs).
Do not present as legally certified forensic software.
