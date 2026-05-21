---
title: "UTMStack Lab — Deployment Guide | DoIt4Everyone"
description: "UTMStack v11.2.8 Community Edition — Deployment guide for lab environment. Swiss SME IT consultant. VMware, Suricata, CrowdSec, SOAR."
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

**UTMStack v11.2.8 Community Edition — Deployment Guide**
*Lab environment — Independent IT Consultant — Switzerland 🇨🇭*

> 🇫🇷 [Version française disponible](index.md)

---

## 📋 Table of Contents

1. [Lab Environment](#lab-environment)
2. [Available Guides](#available-guides)
   - [Installation & Architecture](#-installation--architecture)
   - [Suricata Integration](#-suricata-integration-opnsense)
   - [CrowdSec Integration](#-crowdsec-integration)
   - [UTMStack Dashboards](#-utmstack-dashboards)
   - [SOAR & Automation](#-soar--automation)
   - [OPNsense Post-Migration Checklist](#-opnsense-post-migration-checklist)
3. [Documentation Roadmap](#documentation-roadmap)
4. [Support the Project](#support-the-project)

---

## Lab Environment

| Component | Details |
|-----------|---------|
| **UTMStack** | v11.2.8 Community Edition |
| **Physical Host** | HP ProDesk 400 G2 Mini, i7-6700, 32 GB RAM |
| **Hypervisor** | VMware Workstation |
| **Firewall** | OPNsense 26.1 |
| **UTMStack OS** | Ubuntu 24.04 |
| **Windows Agents** | gest-srv (10.100.1.16), DC01 (10.100.1.1) |

---

## ✅ Available Guides

### 🔧 Installation & Architecture
[→ UTMStack v11 Installation on VMware Workstation](01-installation.md)

VM configuration, installation procedure, post-install optimizations, important ports.

### 🔍 Suricata Integration (OPNsense)
[→ OPNsense → UTMStack Pipeline](02-suricata.md)

Syslog architecture, native parser port 7019, OPNsense services, file rotation handling.

### 🛡️ CrowdSec Integration
[→ CrowdSec → UTMStack](03-crowdsec.md)

Decision forwarding script, persistent service, CrowdSec dashboard.

### 📊 UTMStack Dashboards
[→ Building Suricata & CrowdSec Dashboards](04-dashboards.md)

OpenSearch visualizations, v11-log-suricata-* index, geolocation fields.

### ⚡ SOAR & Automation
[→ Automated CrowdSec Playbooks](05-soar.md)

YAML correlation rules, SOAR flows, automatic IP banning via SSH.

### 📋 OPNsense Post-Migration Checklist
[→ OPNsense 26.1 — Key Points](06-migration-checklist.md)

GUI port 8081, OpenVPN TLS static key, syslog-ng restart hook.

---

## 📅 Documentation Roadmap

| Volume | Content | Pages | Status |
|--------|---------|-------|--------|
| V1 | Installation & Architecture | ~35p | 🟡 In Progress |
| V2 | SIEM Configuration | ~45p | 📋 Planned |
| V3 | Additional Modules | ~40p | 📋 Planned |
| V4 | SOAR & Incident Response | ~30p | 📋 Planned |
| V5 | Red Team / Kali Validation | ~70p | 📋 Planned |

---

## ☕ Support the Project

These guides represent dozens of hours of testing in real environments.

👉 [![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/R5R31YHNIB)

---

ℹ️ *References and writing assistance provided by AI, with final human validation.*

Hosted on GitHub Pages — Theme by [orderedlist](https://github.com/orderedlist)
