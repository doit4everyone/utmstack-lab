---
title: "UTMStack Lab — Guide de déploiement | DoIt4Everyone"
description: "UTMStack v11.2.8 Community Edition — Guide de déploiement pour lab PME Suisse. Installation VMware, Suricata, CrowdSec, SOAR."
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
  }
  h1, h2 { text-align: center; }
  table { width: 100%; display: table; margin: 20px 0; }
</style>

# UTMStack Lab 🛡️

**Guide de déploiement UTMStack v11.2.8 Community Edition**
*Environnement de lab — Consultant IT indépendant — Suisse 🇨🇭*

> 🇬🇧 [English version available](index.en.md)

---

## 📋 Table des matières

1. [Environnement de lab](#environnement-de-lab)
2. [Guides disponibles](#guides-disponibles)
   - [Installation & Architecture](#-installation--architecture)
   - [Intégration Suricata](#-intégration-suricata-opnsense)
   - [Intégration CrowdSec](#-intégration-crowdsec)
   - [Dashboards UTMStack](#-dashboards-utmstack)
   - [SOAR & Automatisation](#-soar--automatisation)
   - [Checklist post-migration OPNsense](#-checklist-post-migration-opnsense)
3. [Roadmap documentation](#roadmap-documentation)
4. [Soutenir le projet](#soutenir-le-projet)

---

## Environnement de lab

| Composant | Détails |
|-----------|---------|
| **UTMStack** | v11.2.8 Community Edition |
| **Hôte physique** | HP ProDesk 400 G2 Mini, i7-6700, 32 GB RAM |
| **Hyperviseur** | VMware Workstation |
| **Firewall** | OPNsense 26.1 |
| **OS UTMStack** | Ubuntu 24.04 |
| **Agents Windows** | gest-srv (10.100.1.16), DC01 (10.100.1.1) |

---

## ✅ Guides disponibles

### 🔧 Installation & Architecture
[→ Installation UTMStack v11 sous VMware Workstation](01-installation.md)

Configuration VM, procédure d'installation, optimisations post-install, ports importants.

### 🔍 Intégration Suricata (OPNsense)
[→ Pipeline OPNsense → UTMStack](02-suricata.md)

Architecture syslog, parseur natif port 7019, services OPNsense, rotation de fichiers.

### 🛡️ Intégration CrowdSec
[→ CrowdSec → UTMStack](03-crowdsec.md)

Script de forwarding des décisions, service persistant, dashboard CrowdSec.

### 📊 Dashboards UTMStack
[→ Création des dashboards Suricata & CrowdSec](04-dashboards.md)

Visualisations OpenSearch, index v11-log-suricata-*, champs géolocalisation.

### ⚡ SOAR & Automatisation
[→ Playbooks automatiques CrowdSec](05-soar.md)

Règles de corrélation YAML, flows SOAR, ban automatique via SSH.

### 📋 Checklist post-migration OPNsense
[→ OPNsense 26.1 — Points de vigilance](06-migration-checklist.md)

GUI port 8081, TLS static key OpenVPN, syslog-ng restart hook.

---

## 📅 Roadmap documentation

| Volume | Contenu | Pages | Statut |
|--------|---------|-------|--------|
| V1 | Installation & Architecture | ~35p | 🟡 En cours |
| V2 | Configuration SIEM | ~45p | 📋 Planifié |
| V3 | Modules complémentaires | ~40p | 📋 Planifié |
| V4 | SOAR & Incident Response | ~30p | 📋 Planifié |
| V5 | Red Team / Validation Kali | ~70p | 📋 Planifié |

---

## ☕ Soutenir le projet

Ces guides représentent des dizaines d'heures de tests en environnements réels.

👉 [![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/R5R31YHNIB)

---

ℹ️ *Références et aide à la rédaction assistées par IA, avec validation humaine finale.*

Hosted on GitHub Pages — Theme by [orderedlist](https://github.com/orderedlist)
