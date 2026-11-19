# AEGIS — P7 — Analyse forensique post-phishing

[![Vercel](https://img.shields.io/badge/Vercel-aegis-p7--blue?logo=vercel)](https://aegis-p7-forensique-email.vercel.app)
[![Tests](https://img.shields.io/badge/Tests-passing-brightgreen)]

Analyse forensique post-phishing — PFE P13 style AEGIS (Master 1 Sécurité informatique).

## Infos rapides

| Élément | Valeur |
|---|---|
| **GitHub** | https://github.com/LaidiMohammed/aegis-p7-forensique-email |
| **Vercel** | https://aegis-p7-forensique-email.vercel.app |
| **Stacks** | email stdlib, exiftool CLI, reportlab |
| **Type** | fg |
| **Ethique** | Labo local, anti-GPU, anti-cloud, stand-alone |

## Install

```bash
pip install -r requirements.txt
make install  # (venv)
```

## Smoke & tests (démo à la prof)

```bash
make smoke   # ou: scripts/run_smoke.sh
make test
```

## Fonctions à exécuter à la démo

Voir [`docs/ETHICS.md`](docs/ETHICS.md), [`docs/SPEC.md`](docs/SPEC.md).
