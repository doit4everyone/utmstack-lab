# 🛡️ UTMStack Lab — Guide et Procédures de déploiement

**UTMStack v11.2.12 Community Edition**  
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
| [03 — Intégration CrowdSec](docs/03-crowdsec.md) | Décisions CrowdSec → UTMStack, whitelist Azure/Cloudflare + réseaux internes |
| [04 — Dashboards](docs/04-dashboards.md) | Visualisations Suricata & CrowdSec dans UTMStack |
| [05 — SOAR & Automatisation](docs/05-soar.md) | Réponse automatique aux incidents via playbooks UTMStack |
| [06 — SOC AI](docs/06-soc-ai.md) | Analyse automatique des alertes — architecture backend, limites du prompt natif |
| [07 — Règles Suricata avancées](docs/07-custom-rules.md) | suricata-update, NF Rules networkforensic.dk, IPS drop mode, CINS, règle custom DVR/IoT |
| [08 — Audit NTLM & Migration Kerberos](docs/08-ntlm-audit.md) | WEF, GPO, Intune, dashboard SIEM, roadmap Phase 1→3 — Server 2025 |
| [09 — Pipeline SOC augmenté par IA locale](docs/09-pipeline-llm.md) | Ollama + n8n, tri déterministe, threat intelligence, comparatif LLM |
| [10 — Intégrations agents et sources de logs](docs/10-integrations-agents.md) | Agents Windows/Linux, M365, Azure Event Hub, SOC AI natif |
| [10b — Sysmon — Déploiement et configuration](docs/10-sysmon.md) | Sysmon v15.21, méthode registre ANSSI, WEF self-subscription → UTMStack |
| [11 — Règles de corrélation YAML](docs/11-correlations-yaml.md) | 38 règles custom validées en live — séries W, WD, S, L, M, A — 28 techniques MITRE ATT&CK |

| Annexe | Description |
|--------|-------------|
| [Checklist Migration OPNsense 26.1](docs/06-migration-checklist.md) | Points de vigilance post-migration OPNsense 25.7 → 26.1 |
| [Réduction du bruit — Règles de corrélation](docs/correlation-rules-tuning.md) | Alert fatigue, diagnostic OpenSearch/PostgreSQL, automatisation post-restart |
| [Bibliothèque de règles custom](rules/) | 38 règles YAML (séries W, WD, S, L, M, A) — 28 techniques MITRE ATT&CK |
| [Workflows Pipeline IA](scripts/) | JSON n8n, scripts heartbeat systemd, Modelfiles Ollama |
| [Scripts WEF NTLM](scripts/) | Deploy-WEF-NTLM-GPO.ps1, Intune, Detect, ntlm-subscription.xml |
| [Configurations Sysmon](configs/sysmon/) | sysmon-workstation.xml, sysmon-dc.xml, sysmon-wef-subscription.xml — schéma 4.91 |

---

## 🎯 Règles de corrélation YAML custom

38 règles validées en live dans OpenSearch, organisées par source de logs :

| Série | Dossier | Règles | Techniques MITRE |
|-------|---------|--------|-----------------|
| W — Windows natif | [rules/windows/](rules/windows/) | W1→W7 | Lockout, Pass-the-Hash, Kerberoasting, tâches planifiées, services suspects |
| WD — Windows Defender | [rules/windows-defender/](rules/windows-defender/) | WD1→WD5 | Détection malware, tamper protection, exclusions |
| S — Sysmon via WEF | [rules/sysmon/](rules/sysmon/) | S1→S5 | LOLBAS, injection de processus, NTDS, Run keys |
| L — Linux auditd | [rules/linux/](rules/linux/) | L1→L2 | Brute force SSH, sudo |
| M — Microsoft 365/Entra ID | [rules/microsoft-365/](rules/microsoft-365/) | M2,M5→M8,M10→M12,M14 | OAuth consent, MFA, audit désactivé, DLP, Accès Conditionnel |
| A — Azure Activity Log | [rules/azure/](rules/azure/) | A1→A11 | Attribution de rôle, Key Vault, resource locks, destruction bloquée |

→ [README détaillé de la bibliothèque](rules/README.md)

---

## 🖥️ Environnement de lab

| Composant | Détail |
|-----------|--------|
| **SIEM** | UTMStack v11.2.12 Community Edition |
| **Hôte** | HP Elite Tower 800 G9 — i7-14700, 64 GB RAM |
| **Hyperviseur** | VMware Workstation |
| **Firewall / IDS** | OPNsense 26.1 + Suricata 8.0.5 |
| **OS SIEM** | Ubuntu 24.04 LTS (10.100.1.150) |
| **Active Directory** | Windows Server 2025 — Topologie multi-sites (2 DC, 2 sites AD) |
| **Agents Windows** | DC01-MAIN-SITE, DC01-RM, gest-srv, MDM-BLAISE-871 (Win 11 24H2), WIN11-AD-TESTS (Win 11 24H2) |
| **Agent Linux** | docker-services (Ubuntu 26.04) — n8n, Qdrant, Open WebUI, SearXNG |
| **Microsoft 365** | Entra ID P1, MDE Plan 1 |
| **Azure** | Event Hub + Event Grid — Activity Log + Resource Events |

---

## 🔩 Stack technique

- **IDS** : Suricata 8.0.5 sur OPNsense — Emerging Threats Open + NF Rules + règles custom
- **HIDS** : CrowdSec + bouncer OPNsense — blocage temps réel, whitelist étendue
- **SOAR** : UTMStack Incident Response + SSH → CrowdSec
- **WEF** : Windows Event Forwarding — self-subscription locale : NTLM + Sysmon → ForwardedEvents → UTMStack
- **M365** : API O365 Management — Entra ID, Exchange, SharePoint, MDE endpoint events
- **Azure** : Event Hub (Activity Log + Event Grid) → index `v11-log-azure-*`
- **SOC AI** : module natif UTMStack + pipeline n8n custom (Ollama local)
- **Pipeline IA** : Ollama (Llama 3.1 8B) + n8n — tri déterministe, enrichissement AbuseIPDB/GreyNoise/OTX/ThreatFox
- **Sysmon** : v15.21 schéma 4.91 — méthode registre ANSSI, collecte WEF → UTMStack
- **Règles custom** : 38 règles YAML — 28 techniques MITRE ATT&CK, validées en live dans OpenSearch

---

## ☕ Soutenir le projet

Ces guides représentent des centaines d'heures de tests en environnements réels.

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/R5R31YHNIB)

---

ℹ️ *Références et aide à la rédaction assistées par IA, avec validation humaine finale.*
