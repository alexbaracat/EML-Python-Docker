<h1 align="center">📧 Dockerized EML Inspector</h1>

<p align="center">
  <em>Drop in a suspicious <code>.eml</code> file (or a ZIP of them) and get an instant, explainable phishing-risk breakdown, with no email client required.</em>
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white" />
  <img alt="Flask" src="https://img.shields.io/badge/Flask-3-000000?logo=flask&logoColor=white" />
  <img alt="Docker" src="https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white" />
  <img alt="SQLite" src="https://img.shields.io/badge/SQLite-SQLAlchemy-003B57?logo=sqlite&logoColor=white" />
</p>

---

## Overview

**Dockerized EML Inspector** is a lightweight Flask web app that helps analysts and curious users triage suspicious emails. Upload a single `.eml` file or a ZIP full of them, and the app parses the message, checks its authentication headers, extracts links and attachments, and produces a **risk score with plain-English reasons**, all in the browser and packaged to run anywhere with Docker.

## Features

- **Single or batch analysis**: upload one `.eml`, or a `.zip` and every `.eml` inside is analysed (macOS `__MACOSX` / `._` junk is skipped automatically).
- **Explainable risk score**: Low / Medium / High, with the specific reasons that contributed to the score.
- **Header forensics**: From, Reply-To, Return-Path, Subject, Date, plus SPF, DKIM and DMARC results parsed from `Authentication-Results`. Flags a Reply-To domain that differs from the From domain.
- **Link analysis**: extracts every URL from the body and flags URL shorteners (`bit.ly`, `tinyurl.com`, …) and suspicious TLDs (`.ru`, `.xyz`, `.top`, …).
- **Attachment forensics**: file-type detection, risk rating by extension, and **MD5 / SHA-1 / SHA-256** hashes with a one-click **VirusTotal** lookup link.
- **Safe attachment export**: download any attachment, or all of them as a ZIP, for offline analysis in a sandbox.
- **Full message views**: rendered body, raw header fields, and raw MIME source.
- **Batch dashboard**: per-file table (subject, sender, attachment count, risk level and score) with drill-down into each message.
- **Drag-and-drop UI**: a clean, responsive interface with live counters for emails inspected and high-risk emails flagged.

## How the risk score works

Each signal adds points; the total maps to a level (`≥ 60` High, `≥ 30` Medium, otherwise Low).

| Signal                                    | Points |
| ----------------------------------------- | -----: |
| High-risk attachment (`.exe`, `.js`, `.ps1`, `.lnk`, `.html`, …) | +25 |
| SPF / DKIM / DMARC `fail` or `softfail`   | +15 each |
| Reply-To domain differs from From domain  | +15 |
| Medium-risk attachment (Office docs, `.zip`, `.rar`, macro-enabled files) | +10 |
| URL shortener or suspicious TLD in a link | +8 each |
| SPF / DKIM / DMARC missing or unknown     | +5 each |

> This is a heuristic triage aid, not a verdict. Always confirm suspicious files with a proper malware sandbox or scanner.

## Tech stack

| Layer      | Technology                                               |
| ---------- | -------------------------------------------------------- |
| Backend    | Python 3.12, Flask, Flask-SQLAlchemy, Flask-Login        |
| Parsing    | Python standard library (`email`, `zipfile`, `hashlib`)  |
| Frontend   | Jinja2 templates, vanilla JavaScript, custom CSS         |
| Storage    | SQLite                                                   |
| Deployment | Docker (`python:3.12-slim`)                              |

## Getting started

### Run with Docker (recommended)

```bash
git clone https://github.com/alexbaracat/EML-Python-Docker.git
cd EML-Python-Docker

docker build -t eml-inspector .
docker run --rm -p 8000:8000 -e SECRET_KEY="change-me" eml-inspector
```

Open <http://localhost:8000> and upload an `.eml` or `.zip`.

### Run locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

## Project structure

```text
EML-Python-Docker/
├── app.py              # Flask app: parsing, risk scoring, routes
├── Dockerfile          # python:3.12-slim image, exposes port 8000
├── requirements.txt    # Flask, Flask-SQLAlchemy, Flask-Login
├── templates/
│   ├── index.html      # Upload UI, batch table and analysis results
│   ├── login.html      # Sign-in page (in progress)
│   └── signup.html     # Sign-up page (in progress)
└── static/
    └── index.css
```

## Routes

| Method | Route                                  | Purpose                                      |
| ------ | -------------------------------------- | -------------------------------------------- |
| GET    | `/`                                    | Upload page and dashboard                    |
| POST   | `/upload`                              | Analyse a single `.eml` or a `.zip` batch    |
| GET    | `/batch/<batch_id>/<index>`            | View one email from a batch                  |
| GET    | `/download_attachment/<req_id>/<i>`    | Download one attachment                      |
| GET    | `/download_attachments/<req_id>`       | Download all attachments as a ZIP            |

## Privacy and safety notes

- Analysis happens on your own machine or container. Nothing is sent to third parties; VirusTotal links just open a hash lookup in your browser.
- Results and attachments are held **in memory** and are cleared when the app restarts.
- Attachments are never executed. Still, handle downloaded files as untrusted.
- Set a strong `SECRET_KEY` environment variable before exposing the app to anyone else.

## Roadmap

- [ ] Finish user accounts (login / sign-up with SSO)
- [ ] Persistent scan history
- [ ] Optional VirusTotal API lookups
- [ ] Export analysis reports (PDF / JSON)
- [ ] Screenshots and a live demo

## Author

**Alexandre Baracat**: [GitHub](https://github.com/alexbaracat)
