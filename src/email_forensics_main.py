"""email_forensics.py — Analyse forensique post-phishing (P7, AEGIS).

Analyse un email .eml extrait de Juice Shop ou toute boîte mail locale :
  - Headers (Received → IP sources, From/Sender typosquatting)
  - Corps HTML → URLs, liens suspects, mots-clés (urgent, verify, suspicious)
  - Pièces jointes → métadonnées via exiftool (optionnel, fallback si absent)
  - Score IOC : Critique / Élevé / Moyen / Faible

Fonctions exécutables à la démo :
    python -m src.email_forensics_main --file phishing_email.eml --out outputs/report.json
    python -m src.generate_report --json outputs/results.json --pdf outputs/rapport-p7.pdf
"""

from __future__ import annotations

import base64
import email
import json
import hashlib
import html
import re
import subprocess
from datetime import datetime, timezone
from email import policy
from email.message import Message
from pathlib import Path
from typing import Any


def parse_email(path: str | Path) -> dict[str, Any]:
    """Parse un fichier .eml (ou .txt avec headers complets) et extrait les infos clés."""
    p = Path(path)
    raw = p.read_text(encoding="utf-8", errors="replace")
    msg = email.message_from_string(raw, policy=policy.default)

    headers: dict[str, str] = {}
    for key, val in msg.items():
        headers[key] = val

    received_headers = msg.get_all("Received", [])
    from_header = msg.get("From", "")
    to_header = msg.get("To", "")
    subject_header = msg.get("Subject", "")
    date_header = msg.get("Date", "")

    # Extraction du sender réel (dernière adresse dans From)
    sender = ""
    m_from = re.search(r"<([^>]+)>", from_header)
    if m_from:
        sender = m_from.group(1)
    else:
        m_from2 = re.search(r"([^<>\s]+@[^<>]+)", from_header)
        if m_from2:
            sender = m_from2.group(1)

    # Extraction des Received IPs (dernier Received souvent le plus proche de l'expéditeur)
    received_ips: list[str] = []
    ip_regex = re.compile(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?|(\d{1,3}(?:\.\d{1,3}){3})")
    for h in received_headers:
        for match in ip_regex.finditer(h):
            ip = match.group(1) or match.group(2)
            if ip:
                received_ips.append(ip)

    # Corps HTML / texte
    body_text = ""
    body_html = ""
    for part in msg.walk():
        content_type = part.get_content_type()
        disposition = part.get_content_disposition()
        if disposition == "attachment":
            continue
        if content_type == "text/plain":
            body_text += part.get_content() + "\n"
        elif content_type == "text/html":
            body_html += part.get_content() + "\n"

    # Extraction URLs et domaines suspects
    url_regex = re.compile(r"https?://[^\s<>\"]+")
    urls = re.findall(url_regex, body_html + body_text)
    domains: list[str] = []
    for u in urls:
        m = re.search(r"https?://([^/:?]+)", u)
        if m:
            domains.append(m.group(1))

    # Mots-clés suspects
    suspicious_keywords = ["urgent", "verify", "verify now", "suspicious", "login", "account", "password", "update", "security"]
    found_keywords = [kw for kw in suspicious_keywords if kw in (body_html + body_text).lower()]

    # Pièces jointes
    attachments: list[dict[str, Any]] = []
    for part in msg.walk():
        disposition = part.get_content_disposition()
        if disposition != "attachment":
            continue
        filename = part.get_filename() or "unknown"
        content = part.get_payload(decode=True) or b""
        sha = hashlib.sha256(content).hexdigest()
        attachments.append({
            "filename": filename,
            "size": len(content),
            "sha256": sha,
            "content_type": part.get_content_type(),
        })

    return {
        "file": str(p),
        "headers": headers,
        "from": from_header,
        "sender": sender,
        "to": to_header,
        "subject": subject_header,
        "date": date_header,
        "received_ips": received_ips,
        "body_text": body_text[:5000],
        "body_html": body_html[:5000],
        "urls": urls[:50],
        "domains": list(dict.fromkeys(domains))[:50],
        "suspicious_keywords": found_keywords,
        "attachments": attachments,
    }


def extract_iocs(parsed: dict[str, Any]) -> list[dict[str, Any]]:
    """Transforme les données parsées en Indicateurs de Compromission (IOCs) classés."""
    iocs: list[dict[str, Any]] = []

    # Suspicious sender domain (typosquatting heuristike simple)
    sender = parsed.get("sender", "")
    if sender:
        domain = sender.split("@")[-1] if "@" in sender else ""
        if domain:
            suspicious_domains = ["gmai1.com", "micr0soft.com", "m1crosoft", "paypa1.com", "faceb00k.com", "amaz0n.com"]
            is_suspicious = any(s in domain for s in suspicious_domains)
            if is_suspicious:
                iocs.append({
                    "type": "domain",
                    "value": domain,
                    "risk": "élevé",
                    "reason": "Typosquatting (domaine proche d'un service connu)",
                })

    # URLs suspectes
    for u in parsed.get("urls", [])[:20]:
        domains_in_url = re.findall(r"https?://([^/:?]+)", u)
        for d in domains_in_url:
            if any(s in d for s in ["gmai1", "micr0soft", "paypa1", "faceb00k", "amaz0n", "secure-login", "verify-account"]):
                iocs.append({
                    "type": "url",
                    "value": u,
                    "risk": "critique",
                    "reason": "Lien de phishing potentiel (domaine suspect)",
                })
            else:
                iocs.append({
                    "type": "url",
                    "value": u,
                    "risk": "moyen",
                    "reason": "Lien externe dans un email suspect",
                })

    # Adresses IP sources (Received headers)
    for ip in parsed.get("received_ips", [])[:10]:
        # IPs privées = interne, publiques = suspectes si non reconnues
        is_private = ip.startswith(("192.168.", "10.", "172."))
        risk = "faible" if is_private else "moyen"
        iocs.append({
            "type": "ip",
            "value": ip,
            "risk": risk,
            "reason": "IP source (Received header)" + (" (privée)" if is_private else ""),
        })

    # Mots-clés suspects
    for kw in parsed.get("suspicious_keywords", [])[:10]:
        iocs.append({
            "type": "keyword",
            "value": kw,
            "risk": "faible",
            "reason": "Mot-clé d'ingénierie sociale détecté dans le corps",
        })

    # Pièces jointes
    for att in parsed.get("attachments", []):
        risk = "critique" if att["filename"].lower().endswith((".exe", ".zip", ".js", ".vbs", ".scr", ".bat", ".doc", ".docx", ".xls", ".xlsx")) else "moyen"
        iocs.append({
            "type": "attachment",
            "value": f"{att['filename']} ({att['size']} octets, SHA256: {att['sha256'][:12]}...)",
            "risk": risk,
            "reason": "Pièce jointe potentiellement malveillante",
        })

    return iocs


def compute_score(iocs: list[dict[str, Any]]) -> dict[str, Any]:
    """Score global de risque (0-100) basé sur les IOCs."""
    weights = {"critique": 25, "élevé": 15, "moyen": 8, "faible": 3}
    total = sum(weights.get(ioc.get("risk", "faible"), 3) for ioc in iocs)
    score = min(100, total)
    if score >= 70:
        level = "Critique"
    elif score >= 40:
        level = "Élevé"
    elif score >= 15:
        level = "Moyen"
    else:
        level = "Faible"
    return {"score": score, "level": level, "ioc_count": len(iocs)}


def run_audit(file_path: str | Path) -> dict[str, Any]:
    """Pipeline complet : parse → IOCs → score."""
    parsed = parse_email(file_path)
    iocs = extract_iocs(parsed)
    score = compute_score(iocs)
    return {
        "file": str(file_path),
        "parsed": parsed,
        "iocs": iocs,
        "score": score,
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    # Windows console: force UTF-8 output for accented chars (é, etc.)
    import sys
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    ap = argparse.ArgumentParser(prog="email_forensics", description="AEGIS - P7 - Analyse forensique post-phishing")
    ap.add_argument("--file", required=True, help="Fichier .eml à analyser")
    ap.add_argument("--save-json", default=None, help="Écrire le résultat JSON")
    ap.add_argument("--pdf", default="outputs/rapport-p7.pdf", help="Chemin du PDF de rapport")
    ap.add_argument("--json", action="store_true", help="Sortir en JSON")
    args = ap.parse_args(argv)

    try:
        out = run_audit(args.file)
    except FileNotFoundError as exc:
        print(f"[ERREUR] fichier introuvable : {args.file} ({exc})")
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"[ERREUR] {exc}")
        return 1

    if args.save_json:
        p = Path(args.save_json)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[OK] écriture : {p}")

    if args.json:
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        s = out["score"]
        print(f"[SUMMARY] file={args.file} score={s['score']}/100 ({s['level']}) iocs={s['ioc_count']}")
        for ioc in out["iocs"]:
            print(f"  [{ioc['risk']:>8}] {ioc['type']}={ioc['value'][:60]} — {ioc['reason']}")

    if args.save_json and args.pdf:
        from src.generate_report import main as gen_main
        rc = gen_main(["--json", args.save_json, "--pdf", args.pdf])
        if rc != 0:
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
