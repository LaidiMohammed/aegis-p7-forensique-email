"""generate_report.py — Génère le PDF du rapport P7 — Analyse forensique post-phishing.

Contenu : IOCs, score, score par IOC, recommandations, export PDF pro.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def build_markdown(data: dict) -> str:
    iocs = data.get("iocs", [])
    score = data.get("score", {})
    parsed = data.get("parsed", {})

    lines = [
        "# P7 — Analyse forensique post-phishing (OWASP Juice Shop / laboratoire local)",
        "",
        f"- **Fichier analysé :** `{parsed.get('file', '-')}`",
        f"- **Score de risque :** **{score.get('score', 0)}/100 — {score.get('level', '?')}**",
        f"- **IOCs détectés :** {score.get('ioc_count', 0)}",
        f"- **Expéditeur :** {parsed.get('sender', '-')}",
        f"- **Sujet :** {parsed.get('subject', '-')}",
        f"- **Date :** {parsed.get('date', '-')}",
        "",
        "## 1. Indicateurs de Compromission (IOCs)",
        "",
        "| Type | Valeur | Risque | Raison |",
        "|---|---|---|---|",
    ]
    for ioc in iocs[:30]:
        lines.append(f"| {ioc.get('type', '-')} | {ioc.get('value', '-')} | {ioc.get('risk', '-')} | {ioc.get('reason', '-')} |")
    if not iocs:
        lines.append("- Aucun IOC détecté.")

    lines += [
        "",
        "## 2. Preuves (pièces jointes)",
        "",
    ]
    for att in parsed.get("attachments", [])[:20]:
        lines.append(f"- **{att.get('filename', '-')}** ({att.get('size', '-')} octets, SHA256 : `{att.get('sha256', '-')[:16]}...`)")

    lines += [
        "",
        "## 3. Recommandations",
        "- Ne jamais cliquer sur les liens suspects provenant d'expéditeurs inconnus.",
        "- Vérifier l'adresse d'expédition (typosquatting : micr0soft.com vs microsoft.com).",
        "- Bloquer les IPs sources suspectes au pare-feu.",
        "- Analyser les pièces jointes en sandbox avant ouverture.",
        "- Former les utilisateurs à reconnaître les emails d'urgence / mot de passe.",
        "",
        f"## 4. Exécutions à montrer au prof :",
        f"- `python -m src.email_forensics_main --file phishing_email.eml --save-json outputs/results.json`",
        f"- `python -m src.generate_report --json outputs/results.json --pdf outputs/rapport-p7.pdf`",
    ]
    return "\n".join(lines)


def build_pdf(markdown: str, out_path: Path) -> None:
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer

    def esc(t: str) -> str:
        return t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(str(out_path), pagesize=LETTER, topMargin=0.5 * inch, bottomMargin=0.5 * inch,
                            leftMargin=0.75 * inch, rightMargin=0.75 * inch)
    styles = getSampleStyleSheet()
    story = []
    for line in markdown.split("\n"):
        if not line.strip():
            story.append(Spacer(1, 6))
            continue
        if line.startswith("# "):
            story.append(Paragraph(esc(line[2:]), styles["h1"]))
        elif line.startswith("## "):
            story.append(Paragraph(esc(line[3:]), styles["h2"]))
        else:
            story.append(Paragraph(esc(line), styles["Normal"]))
    doc.build(story)
    print(f"[OK] PDF écrit : {out_path} ({out_path.stat().st_size} octets)")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="generate_report", description="Génère le rapport P7 — Forensique post-phishing")
    ap.add_argument("--json", type=Path, default=None, help="Fichier JSON du résultat d'analyse")
    ap.add_argument("--pdf", type=Path, default=Path("outputs/rapport-p7.pdf"))
    args = ap.parse_args(argv)
    data = json.loads(args.json.read_text(encoding="utf-8")) if args.json else {
        "file": "n/a", "parsed": {}, "iocs": [], "score": {"score": 0, "level": "?"}}
    md = build_markdown(data)
    args.pdf.parent.mkdir(parents=True, exist_ok=True)
    (args.pdf.parent / "report.md").write_text(md, encoding="utf-8")
    build_pdf(md, args.pdf)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
