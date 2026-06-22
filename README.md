---
title: "UTMStack Lab — Guide et Procédures de déploiement | DoIt4Everyone"
description: "UTMStack v11.2.8 Community Edition — Procédures de déploiement pour lab PME Suisse : installation VMware, Suricata, CrowdSec, SOAR automatisé, OPNsense, audit NTLM & migration Kerberos."
permalink: /
---


# 🛡️ UTMStack Lab — Guide et Procédures de déploiement


**UTMStack v11.2.8 Community Edition**  
*Environnement de lab — Consultant IT indépendant — Suisse 🇨🇭*

[![GitHub Pages](https://img.shields.io/badge/GitHub%20Pages-Disponible-brightgreen)](https://doit4everyone.github.io/utmstack-lab/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## 📖 Documentation en ligne

👉 **[Accéder à la documentation complète](https://doit4everyone.github.io/utmstack-lab/)**

🇬🇧 *English version — coming soon*

---

## 🗂️ Contenu

| Guide | Description |
|-------|-------------|
| [01 — Installation & Architecture](docs/01-installation.md) | Installation VMware, bug DHCP critique, optimisations lab |
| [02 — Intégration Suricata](docs/02-suricata.md) | Pipeline OPNsense → UTMStack port 7019, syslog-ng |
| [03 — Intégration CrowdSec](docs/03-crowdsec.md) | Décisions CrowdSec → UTMStack, whitelist Azure |
| [04 — Dashboards](docs/04-dashboards.md) | Visualisations Suricata & CrowdSec dans UTMStack |
| [05 — SOAR & Automatisation](docs/05-soar.md) | Réponse automatique aux incidents via playbooks UTMStack |
| [06 — SOC AI](docs/06-soc-ai.md) | Analyse automatique des alertes — Mistral AI, Gemini |
| [07 — Règles Suricata avancées](docs/07-custom-rules.md) | NF Rules networkforensic.dk, IPS drop mode, threat hunting |
| [08 — Audit NTLM & Migration Kerberos](docs/08-ntlm-audit.md) | 🆕 WEF, GPO, Intune, roadmap Phase 1→3 — Server 2025 |

| Annexe | Description |
|--------|-------------|
| [Migration OPNsense 26.1](docs/06-migration-checklist.md) | Checklist post-migration OPNsense 25.7 → 26.1 |
| [Scripts WEF NTLM](scripts/) | Deploy-WEF-NTLM-GPO.ps1, Intune, Detect, ntlm-subscription.xml |

---

## 🖥️ Environnement de lab

- **UTMStack** v11.2.8 Community Edition — Ubuntu 24.04 LTS
- **Hôte** : HP ProDesk 400 G2 Mini, i7-6700, 32 GB RAM
- **Hyperviseur** : VMware Workstation
- **Firewall / IDS** : OPNsense 26.1 + Suricata 8.0.5
- **Active Directory** : Windows Server 2025 — 2 DC, 2 sites AD
- **Agents** : DC01-MAIN-SITE, DC01-RM, gest-srv, MDM-BLAISE-871 (Win 11 24H2)
- **SOC AI** : Mistral AI — analyse d'alertes assistée

---

## ☕ Soutenir le projet

Ces guides représentent des dizaines d'heures de tests en environnements réels.

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/R5R31YHNIB)

---

ℹ️ *Références et aide à la rédaction assistées par IA, avec validation humaine finale.*
