---
title: "UTMStack Lab — Guide et Procédures de déploiement | DoIt4Everyone"
description: "UTMStack v11.2.8 Community Edition — Procédures de déploiement pour lab PME Suisse : installation VMware, Suricata, CrowdSec, SOAR automatisé, OPNsense."
lang: fr
permalink: /
---
<style>
  /* 1. On cache le header et le footer du thème */
  header, footer { display: none !important; }

  /* 2. On réinitialise le conteneur principal pour le centrage et la typographie */
  .wrapper {
    max-width: 900px !important;
    margin: 0 auto !important;
    float: none !important; 
    position: relative !important;
    padding: 40px 20px !important;
    
    /* Typographie moderne et lisible */
    font-family: "Helvetica Neue", Helvetica, Arial, sans-serif !important;
    font-size: 1.1em !important;
  }

  /* 3. On force la section de texte à prendre toute la largeur */
  section {
    width: 100% !important;
    float: none !important;
    margin: 0 !important;
    padding-top: 0 !important;
  }

  /* Centrage des titres principaux */
  h1, h2 { text-align: center; }
</style>

# 🛡️ UTMStack Lab — Guide et Procédures de déploiement

# **UTMStack v11.2.8 Community Edition**  
# *Environnement de lab — Consultant IT indépendant — Suisse 🇨🇭*

[![GitHub Pages](https://img.shields.io/badge/GitHub%20Pages-Disponible-brightgreen)](https://doit4everyone.github.io/utmstack-lab/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## 📖 À propos

Ce site documente le déploiement complet d'un lab UTMStack v11.2.8 Community Edition dans un environnement de lab PME, incluant l'intégration Suricata, CrowdSec, et l'automatisation SOAR.

Toutes les procédures sont testées et validées en conditions réelles sur un HP ProDesk 400 G2 Mini sous VMware Workstation, avec OPNsense comme firewall.

---

## 🗂️ Procédures

| Guide | Description |
|-------|-------------|
| [01 — Installation & Architecture](docs/01-installation.md) | Installation VMware, bug DHCP critique, optimisations lab |
| [02 — Intégration Suricata](docs/02-suricata.md) | Pipeline OPNsense → UTMStack port 7019 |
| [03 — Intégration CrowdSec](docs/03-crowdsec.md) | Décisions CrowdSec → UTMStack, whitelist Azure |
| [04 — Dashboards](docs/04-dashboards.md) | Visualisations Suricata & CrowdSec dans UTMStack |
| [05 — SOAR & Automatisation](docs/05-soar.md) | Ban automatique CrowdSec via playbooks UTMStack |

---

## 📎 Documents annexes

| Document | Description |
|----------|-------------|
| [Checklist Migration OPNsense 26.1](docs/06-migration-checklist.md) | Points de vigilance post-migration OPNsense 25.7 → 26.1 |

---

## 🖥️ Environnement de lab

| Composant | Détail |
|-----------|--------|
| **SIEM** | UTMStack v11.2.8 Community Edition |
| **Hôte** | HP ProDesk 400 G2 Mini — i7-6700 — 32 GB RAM |
| **Hyperviseur** | VMware Workstation |
| **Firewall** | OPNsense 26.1 |
| **OS SIEM** | Ubuntu 24.04 LTS |
| **Agent** | Windows Server 2022 (gest-srv) |

---

## 🔧 Stack technique

- **IDS** : Suricata 7.x sur OPNsense — règles ET Open
- **HIDS** : CrowdSec + bouncer OPNsense
- **SOAR** : UTMStack Incident Response + SSH → CrowdSec
- **Logs** : syslog-ng → Agent UTMStack → OpenSearch

---

## ☕ Soutenir le projet

Si ces procédures vous ont été utiles :

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/R5R31YHNIB)

---

ℹ️ *Références et aide à la rédaction assistées par IA, avec validation humaine finale.*
