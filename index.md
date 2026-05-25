---
title: "UTMStack Lab — Guide et Procédures de déploiement | DoIt4Everyone"
description: "UTMStack v11.2.8 Community Edition — Procédures de déploiement pour lab PME Suisse : installation VMware, Suricata, CrowdSec, SOAR automatisé, OPNsense."
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

# 🛡️ UTMStack Lab — Guide et Procédures de déploiement

**UTMStack v11.2.8 Community Edition**  
*Environnement de lab — Consultant IT indépendant — Suisse 🇨🇭*

[![GitHub Pages](https://img.shields.io/badge/GitHub%20Pages-Disponible-brightgreen)](https://doit4everyone.github.io/utmstack-lab/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## 📖 À propos

Ce site documente le déploiement complet d'un lab **UTMStack v11.2.8 Community Edition** dans un environnement de lab simulant une infrastructure PME, incluant l'intégration Suricata IDS, CrowdSec, et l'automatisation SOAR pour la réponse automatique aux incidents.

Toutes les procédures sont testées et validées en conditions réelles sur un HP ProDesk 400 G2 Mini sous VMware Workstation, avec OPNsense comme firewall/IDS.

> ℹ️ **UTMStack est un SIEM** — il centralise, corrèle et analyse les événements de sécurité. Un SIEM ne remplace pas un antivirus/EDR (protection des endpoints) ni une solution de conformité et protection des données (type Microsoft Purview). Ces outils sont complémentaires : le SIEM agit au niveau réseau et infrastructure, l'EDR protège les machines de l'intérieur.

---

## 🗂️ Procédures

| Guide | Description |
|-------|-------------|
| [01 — Installation & Architecture](docs/01-installation.md) | Installation VMware, bug DHCP critique, optimisations lab |
| [02 — Intégration Suricata](docs/02-suricata.md) | Pipeline OPNsense → UTMStack port 7019, syslog-ng |
| [03 — Intégration CrowdSec](docs/03-crowdsec.md) | Décisions CrowdSec → UTMStack, whitelist Azure |
| [04 — Dashboards](docs/04-dashboards.md) | Visualisations Suricata & CrowdSec dans UTMStack |
| [05 — SOAR & Automatisation](docs/05-soar.md) | Réponse automatique aux incidents via playbooks UTMStack ⚠️ *v0.1* |
| [06 — SOC AI](docs/06-soc-ai.md) | Analyse automatique des alertes — Mistral AI, Gemini, création d'incidents |

---

## 🔧 Guides disponibles

### 🔧 Installation & Architecture
[→ Installation UTMStack v11 sous VMware Workstation](docs/01-installation.md)

Configuration VM, procédure d'installation, optimisations post-install, ports importants v11.2.8.

### 🔍 Intégration Suricata (OPNsense)
[→ Pipeline OPNsense → UTMStack](docs/02-suricata.md)

Architecture syslog-ng, parseur natif port 7019, persistance des services OPNsense.

### 🛡️ Intégration CrowdSec
[→ CrowdSec → UTMStack](docs/03-crowdsec.md)

Forwarding des décisions vers UTMStack, bouncer OPNsense, whitelist Azure, dashboard.

### 📊 Dashboards UTMStack
[→ Création des dashboards Suricata & CrowdSec](docs/04-dashboards.md)

Visualisations OpenSearch, index v11-log-suricata-*, champs géolocalisation, threat map.

### ⚡ SOAR & Automatisation
[→ Playbooks automatiques — Réponse aux incidents](docs/05-soar.md)

Clé SSH SYSTEM, script soar_ban.sh OPNsense, déduplication, compatibilité Microsoft Defender for Endpoint.

---

## 📅 Roadmap documentation

| Volume | Contenu | Statut |
|--------|---------|--------|
| V1 | Installation & Architecture | 🟢 Publié |
| V2 | Configuration SIEM — Agents, sources de logs, règles | 📋 Planifié |
| V3 | Modules complémentaires — SOC AI, OPNsense stack | 🟡 En cours |
| V4 | SOAR & Incident Response — Tests Red Team Kali | 🟡 En cours |
| V5 | Red Team / Validation Kali | 📋 Planifié |

---

## 🖥️ Environnement de lab

| Composant | Détail |
|-----------|--------|
| **SIEM** | UTMStack v11.2.8 Community Edition |
| **Hôte** | HP ProDesk 400 G2 Mini — i7-6700 — 32 GB RAM |
| **Hyperviseur** | VMware Workstation |
| **Firewall / IDS** | OPNsense 26.1 + Suricata 7.x |
| **OS SIEM** | Ubuntu 24.04 LTS |
| **Agents** | Windows Server 2022 — gest-srv (10.100.1.16), DC01 (10.100.1.1) |

---

## 🔩 Stack technique

- **IDS** : Suricata 7.x sur OPNsense — règles Emerging Threats Open
- **HIDS** : CrowdSec + bouncer OPNsense — blocage temps réel
- **SOAR** : UTMStack Incident Response + SSH → CrowdSec
- **Logs** : syslog-ng → Agent UTMStack → OpenSearch
- **SOC AI** : Mistral AI — analyse d'alertes assistée

---

## 📎 Documents annexes

| Document | Description |
|----------|-------------|
| [Checklist Migration OPNsense 26.1](docs/06-migration-checklist.md) | Points de vigilance post-migration OPNsense 25.7 → 26.1 |

---

## ☕ Soutenir le projet

Ces guides représentent des dizaines d'heures de tests en environnements réels.

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/R5R31YHNIB)

---

ℹ️ *Références et aide à la rédaction assistées par IA, avec validation humaine finale.*
