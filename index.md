---
title: "UTMStack Lab — Guide et Procédures de déploiement | DoIt4Everyone"
description: "UTMStack v11.2.11 Community Edition — Procédures de déploiement pour lab PME Suisse : installation VMware, Suricata, CrowdSec, SOAR automatisé, OPNsense, audit NTLM & migration Kerberos."
lang: fr
permalink: /
---
<style>
  header, footer { display: none !important; }
  .wrapper {
    max-width: 900px !important;
    margin: 0 auto !important;
    float: none !important;
    position: relative !important;
    padding: 40px 20px !important;
    font-family: "Helvetica Neue", Helvetica, Arial, sans-serif !important;
    font-size: 1.1em !important;
  }
  section {
    width: 100% !important;
    float: none !important;
    margin: 0 !important;
    padding-top: 0 !important;
  }
  h1, h2 { text-align: center; }
  table { width: 100%; display: table; margin: 20px 0; }
</style>

# UTMStack Lab — Guide et Procédures de déploiement

UTMStack v11.2.11 Community Edition — Procédures de déploiement pour lab PME Suisse. Installation VMware, Suricata, CrowdSec, SOAR, OPNsense.

[![GitHub Pages](https://img.shields.io/badge/GitHub%20Pages-Disponible-brightgreen)](https://doit4everyone.github.io/utmstack-lab/) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://doit4everyone.github.io/utmstack-lab/LICENSE)

---

## 📖 À propos

Ce site documente le déploiement complet d'un lab **UTMStack v11.2.11 Community Edition** dans un environnement simulant une infrastructure PME, incluant l'intégration Suricata IDS, CrowdSec, l'automatisation SOAR pour la réponse automatique aux incidents, et l'audit NTLM en préparation de la migration vers Kerberos (roadmap Microsoft 2025-2027).

Toutes les procédures sont testées et validées en conditions réelles sous VMware Workstation, avec OPNsense comme firewall/IDS.

> ℹ️ **UTMStack est un SIEM** — il centralise, corrèle et analyse les événements de sécurité. Un SIEM ne remplace pas un antivirus/EDR (protection des endpoints) ni une solution de conformité et protection des données (type Microsoft Purview). Ces outils sont complémentaires : le SIEM agit au niveau réseau et infrastructure, l'EDR protège les machines de l'intérieur.

---

## 🗂️ Procédures

| Guide | Description |
| --- | --- |
| [01 — Installation & Architecture](https://doit4everyone.github.io/utmstack-lab/docs/01-installation.html) | Installation VMware, bug DHCP critique, optimisations lab |
| [02 — Intégration Suricata](https://doit4everyone.github.io/utmstack-lab/docs/02-suricata.html) | Pipeline OPNsense → UTMStack port 7019, syslog-ng |
| [03 — Intégration CrowdSec](https://doit4everyone.github.io/utmstack-lab/docs/03-crowdsec.html) | Décisions CrowdSec → UTMStack, whitelist Azure/Cloudflare + réseaux internes |
| [04 — Dashboards](https://doit4everyone.github.io/utmstack-lab/docs/04-dashboards.html) | Visualisations Suricata & CrowdSec dans UTMStack |
| [05 — SOAR & Automatisation](https://doit4everyone.github.io/utmstack-lab/docs/05-soar.html) | Réponse automatique aux incidents via playbooks UTMStack ⚠️ *v0.1* |
| [06 — SOC AI](https://doit4everyone.github.io/utmstack-lab/docs/06-soc-ai.html) | Analyse automatique des alertes — architecture backend, limites du prompt natif |
| [07 — Règles Suricata avancées](https://doit4everyone.github.io/utmstack-lab/docs/07-custom-rules.html) | suricata-update, NF Rules networkforensic.dk, IPS drop mode, CINS, 🆕 règle custom DVR/IoT (r00ts3c) avec persistance double (boot + cron nocturne) |
| [08 — Audit NTLM & Migration Kerberos](https://doit4everyone.github.io/utmstack-lab/docs/08-ntlm-audit.html) | WEF, GPO, Intune, dashboard SIEM, roadmap Phase 1→3 — Server 2025 |
| [09 — Pipeline SOC augmenté par IA locale](https://doit4everyone.github.io/utmstack-lab/docs/09-pipeline-llm.html) | Ollama + n8n, tri déterministe, threat intelligence, heartbeat de supervision, comparatif LLM (Sonnet/DeepSeek-R1/Mistral) + variante cloud optionnelle |

---

## 🔧 Guides disponibles

### 🔧 Installation & Architecture

[→ Installation UTMStack v11 sous VMware Workstation](https://doit4everyone.github.io/utmstack-lab/docs/01-installation.html)

Configuration VM, procédure d'installation, optimisations post-install, ports importants v11.2.x.

### 🔍 Intégration Suricata (OPNsense)

[→ Pipeline OPNsense → UTMStack](https://doit4everyone.github.io/utmstack-lab/docs/02-suricata.html)

Architecture syslog-ng, parseur natif port 7019, persistance des services OPNsense.

### 🛡️ Intégration CrowdSec

[→ CrowdSec → UTMStack](https://doit4everyone.github.io/utmstack-lab/docs/03-crowdsec.html)

Forwarding des décisions vers UTMStack, bouncer OPNsense, whitelist Azure/Cloudflare étendue aux réseaux internes du lab, dashboard.

### 📊 Dashboards UTMStack

[→ Création des dashboards Suricata & CrowdSec](https://doit4everyone.github.io/utmstack-lab/docs/04-dashboards.html)

Visualisations OpenSearch, index v11-log-suricata-*, champs géolocalisation, threat map.

### ⚡ SOAR & Automatisation

[→ Playbooks automatiques — Réponse aux incidents](https://doit4everyone.github.io/utmstack-lab/docs/05-soar.html)

Clé SSH SYSTEM, script soar_ban.sh OPNsense, déduplication, compatibilité Microsoft Defender for Endpoint.

### 📋 Règles Suricata avancées

[→ suricata-update & NF Rules networkforensic.dk](https://doit4everyone.github.io/utmstack-lab/docs/07-custom-rules.html)

suricata-update (ptrules, stamus/lateral, tgreen/hunting), règles NF Scanners en drop IPS, CINS Active Threat Intelligence, règle custom bloquant une exploitation DVR/IoT active (signature `r00ts3c-owned-you`), découverte et correction de la réinitialisation nocturne native d'OPNsense sur les règles custom.

### 🔐 Audit NTLM & Migration Kerberos

[→ Phase 1 complète : audit, WEF, scripts, dashboard](https://doit4everyone.github.io/utmstack-lab/docs/08-ntlm-audit.html)

Déploiement de l'audit NTLM via Windows Event Forwarding (WEF) en self-subscription locale. Scripts prêts à l'emploi pour GPO et Intune, corrections terrain Server 2025, cas d'étude réplication AD inter-sites utilisant NTLM par design. [Scripts sur GitHub](https://github.com/doit4everyone/utmstack-lab/tree/main/scripts).

### 🤖 Pipeline SOC augmenté par IA locale

[→ Ollama + n8n — de l'idée au pipeline fiable, en 12 versions](https://doit4everyone.github.io/utmstack-lab/docs/09-pipeline-llm.html)

Retour d'expérience complet sur la construction d'un pipeline de résumé quotidien assisté par LLM, avec un pipeline local (Ollama) comme socle de référence : pourquoi le classement signal/bruit doit rester déterministe (pas confié au LLM), enrichissement automatique via AbuseIPDB/GreyNoise/OTX/ThreatFox, corrélation temporelle sur 30 jours, et détection de panne silencieuse transformée en alerte SIEM native. Comparatif honnête Llama 3.1 8B / Mistral NeMo 12B / Qwen 2.5 14B en local, puis confrontation sans garde-fou entre Claude Sonnet 5, DeepSeek-R1 (14B/32B) et Mistral Large — avec les hallucinations et erreurs d'interprétation observées montrées telles quelles, y compris quand elles trompent le modèle le plus fiable du lot. Une **variante cloud optionnelle** (Mistral, hébergement UE, coût mensuel négligeable) est documentée en complément du pipeline local, jamais à sa place. [Guide de déploiement pas à pas](https://doit4everyone.github.io/utmstack-lab/docs/09-pipeline-llm-deploiement.html) et [workflows n8n sur GitHub](https://github.com/doit4everyone/utmstack-lab/tree/main/scripts).

---

## 📅 Roadmap documentation

| Volume | Contenu | Statut |
| --- | --- | --- |
| V1 | Installation & Architecture | 🟢 Publié |
| V2 | Configuration SIEM — Agents, sources de logs, règles, intégrations Azure/M365 | 📋 Planifié |
| V3 | Modules complémentaires — SOC AI, OPNsense stack, Pipeline IA locale (Ollama + n8n) | 🟢 Publié |
| V4 | SOAR & Incident Response — Tests Red Team Kali | 🟡 En cours |
| V5 | Red Team / Validation Kali | 📋 Planifié |

---

## 🖥️ Environnement de lab

| Composant | Détail |
| --- | --- |
| **SIEM** | UTMStack v11.2.11 Community Edition |
| **Hôte** | Serveur HPE G9 — 64 GB RAM |
| **Hyperviseur** | VMware Workstation |
| **Firewall / IDS** | OPNsense 26.1.11 + Suricata 8.0.5 |
| **OS SIEM** | Ubuntu 24.04 LTS |
| **Active Directory** | Windows Server 2025 — Topologie multi-sites (2 DC, 2 sites AD) |
| **Agents** | DC01-MAIN-SITE (10.100.1.1), DC01-RM (10.100.2.1), gest-srv (10.100.1.16), MDM-BLAISE-871 (Win 11 24H2) |

---

## 🔩 Stack technique

- **IDS** : Suricata 8.0.5 sur OPNsense — règles Emerging Threats Open + NF Rules + règles custom (blocage actif d'exploitations DVR/IoT ciblées)
- **HIDS** : CrowdSec + bouncer OPNsense — blocage temps réel, whitelist étendue (cloud légitime + réseaux internes)
- **SOAR** : UTMStack Incident Response + SSH → CrowdSec
- **Logs** : syslog-ng → Agent UTMStack → OpenSearch
- **WEF** : Windows Event Forwarding — collecte NTLM/Operational → ForwardedEvents
- **SOC AI** : analyse d'alertes assistée — architecture backend documentée (voir chapitre 06)
- **Pipeline IA** : Ollama (Llama 3.1 8B / Qwen 2.5 14B, local, socle de référence) + n8n — tri déterministe, enrichissement AbuseIPDB/GreyNoise/OTX/ThreatFox, heartbeat de supervision → alerte SIEM native ; variante cloud optionnelle documentée avec Mistral Large (hébergement UE) (voir chapitre 09)

---

## 📎 Documents annexes

| Document | Description |
| --- | --- |
| [Checklist Migration OPNsense 26.1](https://doit4everyone.github.io/utmstack-lab/docs/06-migration-checklist.html) | Points de vigilance post-migration OPNsense 25.7 → 26.1 |
| [Réduction du bruit — Règles de corrélation UTMStack](https://doit4everyone.github.io/utmstack-lab/docs/correlation-rules-tuning.html) | Alert fatigue, diagnostic OpenSearch/PostgreSQL, 7 fixes de règles de corrélation, dérive d'ID entre versions, automatisation double (boot + cron horaire), checklist post-update |
| [Workflows Pipeline IA (GitHub)](https://github.com/doit4everyone/utmstack-lab/tree/main/scripts) | JSON n8n (rapport quotidien, à la demande, consultation webhook), scripts heartbeat systemd, Modelfiles Ollama |
| [Scripts WEF NTLM (GitHub)](https://github.com/doit4everyone/utmstack-lab/tree/main/scripts) | Deploy-WEF-NTLM-GPO.ps1, Intune, Detect, ntlm-subscription.xml |

---

## ☕ Soutenir le projet

Ces guides représentent des dizaines d'heures de tests en environnements réels.

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/R5R31YHNIB)

---

ℹ️ *Références et aide à la rédaction assistées par IA, avec validation humaine finale.*

This project is maintained by [doit4everyone](https://github.com/doit4everyone)
