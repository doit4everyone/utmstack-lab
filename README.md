---
title: "UTMStack Lab — Guide et Procédures de déploiement | DoIt4Everyone"
description: "UTMStack v11.2.8 Community Edition — Procédures de déploiement pour lab PME Suisse : installation VMware, Suricata, CrowdSec, SOAR automatisé, OPNsense."
lang: fr
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

# 🛡️ UTMStack Lab — Guide et Procédures de déploiement


**UTMStack v11.2.8 Community Edition**  
*Environnement de lab — Consultant IT indépendant — Suisse 🇨🇭*

[![GitHub Pages](https://img.shields.io/badge/GitHub%20Pages-Disponible-brightgreen)](https://doit4everyone.github.io/utmstack-lab/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## 📖 Documentation en ligne

👉 **[Accéder à la documentation complète](https://doit4everyone.github.io/utmstack-lab/)**

🇬🇧 **[English version](https://doit4everyone.github.io/utmstack-lab/index.en.html)**

---

## 🗂️ Contenu

| Guide | Description |
|-------|-------------|
| [Installation](docs/01-installation.md) | Installation VMware, bug DHCP, optimisations |
| [Suricata](docs/02-suricata.md) | Pipeline OPNsense → UTMStack port 7019 |
| [CrowdSec](docs/03-crowdsec.md) | Intégration décisions → UTMStack |
| [Dashboards](docs/04-dashboards.md) | Visualisations Suricata & CrowdSec |
| [SOAR](docs/05-soar.md) | Ban automatique via playbooks |
| [Migration OPNsense 26.1](docs/06-migration-checklist.md) | Checklist post-migration |

---

## 🖥️ Environnement de lab

- **UTMStack** v11.2.8 Community Edition
- **Hôte** : HP ProDesk 400 G2 Mini, i7-6700, 32 GB RAM
- **Hyperviseur** : VMware Workstation
- **Firewall** : OPNsense 26.1
- **OS** : Ubuntu 24.04

---

## ☕ Soutenir le projet

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/R5R31YHNIB)

---

ℹ️ *Références et aide à la rédaction assistées par IA, avec validation humaine finale.*
