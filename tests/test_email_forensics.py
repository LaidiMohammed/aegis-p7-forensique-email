"""Tests unitaires — P7 Analyse forensique post-phishing (mocks — sans shell).

- parse_email : extraction From/Subject/Received/URLs/IPs/pièces jointes
- extract_iocs : détection typosquatting, URLs suspectes, IPs sources, mots-clés, pièces jointes
- compute_score : score 0-100 + niveau
- run_audit : pipeline complet
- generate_report : md + pdf
- main : smoke exit 0
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import email_forensics_main as m
from src import generate_report as rep

SAMPLE_EMAIL = """From: security@m1crosoft-support.com
To: victim@example.com
Subject: Urgent: Suspicious Login Detected
Date: Mon, 20 Nov 2026 10:00:00 +0100
Received: from [192.168.1.100] (unknown [10.0.2.15])
 by mail.example.com with SMTP
Received: from mail.example.com ([203.0.113.5])
 by mx.google.com with ESMTP

Hello,

We detected a suspicious login on your account.
Please verify your account immediately: http://secure-login.m1crosoft.com/verify

Best regards,
Security Team
"""


def test_parse_email():
    import tempfile
    f = Path(tempfile.mkdtemp()) / "test.eml"
    f.write_text(SAMPLE_EMAIL, encoding="utf-8")
    out = m.parse_email(str(f))
    assert out["sender"] == "security@m1crosoft-support.com"
    assert out["subject"] == "Urgent: Suspicious Login Detected"
    assert "192.168.1.100" in out["received_ips"]
    assert "203.0.113.5" in out["received_ips"]
    assert any("secure-login.m1crosoft.com" in u for u in out["urls"])


def test_extract_iocs_typosquatting():
    parsed = {
        "sender": "security@m1crosoft-support.com",
        "urls": ["http://secure-login.m1crosoft.com/verify"],
        "received_ips": ["203.0.113.5"],
        "suspicious_keywords": ["urgent", "verify"],
        "attachments": [{"filename": "invoice.exe", "size": 12345, "sha256": "abcdef123456"}],
    }
    iocs = m.extract_iocs(parsed)
    types = [ioc["type"] for ioc in iocs]
    assert "domain" in types
    assert "url" in types
    assert "ip" in types
    assert "keyword" in types
    assert "attachment" in types


def test_compute_score():
    iocs = [
        {"risk": "critique"}, {"risk": "critique"}, {"risk": "élevé"},
        {"risk": "moyen"}, {"risk": "faible"},
    ]
    s = m.compute_score(iocs)
    assert 0 <= s["score"] <= 100
    assert s["level"] in ("Critique", "Élevé", "Moyen", "Faible")


def test_run_audit_structure(tmp_path):
    f = tmp_path / "test.eml"
    f.write_text(SAMPLE_EMAIL, encoding="utf-8")
    out = m.run_audit(str(f))
    assert "file" in out and "parsed" in out and "iocs" in out and "score" in out
    assert out["parsed"]["sender"] == "security@m1crosoft-support.com"


def test_main_smoke(tmp_path):
    f = tmp_path / "test.eml"
    f.write_text(SAMPLE_EMAIL, encoding="utf-8")
    assert m.main(["--file", str(f), "--json"]) == 0


def test_generate_report_produces_files(tmp_path):
    data = {
        "file": "test.eml",
        "parsed": {
            "sender": "security@m1crosoft-support.com",
            "subject": "Urgent: Suspicious Login Detected",
            "urls": ["http://secure-login.m1crosoft.com/verify"],
            "attachments": [{"filename": "invoice.exe", "size": 12345, "sha256": "abc123"}],
        },
        "iocs": [
            {"type": "url", "value": "http://secure-login.m1crosoft.com/verify", "risk": "critique", "reason": "Lien de phishing potentiel"},
            {"type": "ip", "value": "203.0.113.5", "risk": "moyen", "reason": "IP source"},
        ],
        "score": {"score": 65, "level": "Élevé", "ioc_count": 2},
    }
    md = rep.build_markdown(data)
    assert "testuser123" not in md
    assert "secure-login.m1crosoft.com" in md
    out = tmp_path / "r.pdf"
    rep.build_pdf(md, out)
    assert out.exists() and out.stat().st_size > 400


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
