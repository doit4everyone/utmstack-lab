# 🛡️ UTMStack Lab : guide et procédures de déploiement

**UTMStack v11.3.0 Community Edition**  
*Environnement de lab, consultant IT indépendant, Suisse 🇨🇭*

[![GitHub Pages](https://img.shields.io/badge/GitHub%20Pages-Disponible-brightgreen)](https://doit4everyone.github.io/utmstack-lab/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## 📖 Documentation en ligne

👉 **[Accéder à la documentation complète](https://doit4everyone.github.io/utmstack-lab/)**

🇬🇧 *English version: coming soon*

> ⚠️ **Mise à jour UTMStack v11.3.0 (novembre 2026).** La v11.3.0 remplace les champs `log.*` par `event.*` : les règles de corrélation écrites pour v11.2 ne se déclenchent plus. La [bibliothèque de règles](rules/) et le [chapitre 11](docs/11-correlations-yaml.md) ont été migrés et revalidés. Les autres chapitres décrivent encore l'état v11.2 et seront révisés progressivement. L'état complet du dépôt pour v11.2 reste disponible dans la release [`v11.2-final`](https://github.com/doit4everyone/utmstack-lab/releases/tag/v11.2-final).

---

## 🗂️ Contenu

| Guide | Description |
|-------|-------------|
| [01 : Installation et architecture](docs/01-installation.md) | Installation VMware, bug DHCP critique, optimisations lab |
| [02 : Intégration Suricata](docs/02-suricata.md) | Pipeline OPNsense → UTMStack port 7019, syslog-ng |
| [03 : Intégration CrowdSec](docs/03-crowdsec.md) | Décisions CrowdSec → UTMStack, whitelist Azure/Cloudflare + réseaux internes |
| [04 : Dashboards](docs/04-dashboards.md) | Visualisations Suricata & CrowdSec dans UTMStack |
| [05 : SOAR et automatisation](docs/05-soar.md) | Réponse automatique aux incidents via playbooks UTMStack |
| [06 : SOC AI](docs/06-soc-ai.md) | Analyse automatique des alertes : architecture backend, limites du prompt natif |
| [07 : Règles Suricata avancées](docs/07-custom-rules.md) | suricata-update, NF Rules networkforensic.dk, IPS drop mode, CINS, règle custom DVR/IoT |
| [08 : Audit NTLM et migration Kerberos](docs/08-ntlm-audit.md) | WEF, GPO, Intune, dashboard SIEM, roadmap Phase 1→3, Server 2025 |
| [09 : Pipeline SOC augmenté par IA locale](docs/09-pipeline-llm.md) | Ollama + n8n, tri déterministe, threat intelligence, comparatif LLM |
| [10 : Intégrations agents et sources de logs](docs/10-integrations-agents.md) | Agents Windows/Linux, M365, Azure Event Hub, SOC AI natif |
| [10b : Sysmon, déploiement et configuration](docs/10-sysmon.md) | Sysmon v15.21, méthode registre ANSSI, WEF self-subscription → UTMStack |
| [11 : Règles de corrélation YAML](docs/11-correlations-yaml.md) | Migration v11.3.0, 48 règles personnalisées (séries W, WD, S, L, M, A et clones de règles natives), 34 techniques MITRE ATT&CK |

| Annexe | Description |
|--------|-------------|
| [Checklist Migration OPNsense 26.1](docs/06-migration-checklist.md) | Points de vigilance après la migration OPNsense 25.7 → 26.1 |
| [Réduction du bruit : règles de corrélation](docs/correlation-rules-tuning.md) | Alert fatigue, diagnostic OpenSearch/PostgreSQL, automatisation post-restart |
| [Bibliothèque de règles personnalisées](rules/) | 48 règles YAML pour v11.3.0, avec leur statut de validation, et les règles retirées |
| [Workflows Pipeline IA](scripts/) | JSON n8n, scripts heartbeat systemd, Modelfiles Ollama |
| [Scripts WEF NTLM](scripts/) | Deploy-WEF-NTLM-GPO.ps1, Intune, Detect, ntlm-subscription.xml |
| [Configurations Sysmon](configs/sysmon/) | sysmon-workstation.xml, sysmon-dc.xml, sysmon-wef-subscription.xml, schéma 4.91 |

---

## 🎯 Règles de corrélation YAML custom

48 règles pour UTMStack v11.3.0, organisées par source de logs. 28 sont validées par un test réel en v11.3.0, 3 en passif ; 5 ne sont pas testables dans le lab ; les 12 règles Azure sont réécrites mais pas encore revalidées. Le statut de chaque règle est dans le [README de la bibliothèque](rules/README.md).

| Série | Dossier | Règles | Techniques MITRE |
|-------|---------|--------|-----------------|
| W : Windows natif | [rules/windows/](rules/windows/) | W1, W3→W7, S5b, clone PowerShell | Verrouillage, Pass-the-Hash, Kerberoasting, tâches planifiées, services suspects, clés Run, PowerShell suspect |
| WD : Windows Defender | [rules/windows-defender/](rules/windows-defender/) | WD1→WD5 | Détection malware, tamper protection, exclusions |
| S : Sysmon via WEF | [rules/sysmon/](rules/sysmon/) | S1→S5 | LOLBAS, accès LSASS, named pipes C2, NTDS, Run keys |
| L : Linux auditd | [rules/linux/](rules/linux/) | L1→L2 | Brute force SSH, sudo |
| M : Microsoft 365/Entra ID | [rules/microsoft-365/](rules/microsoft-365/) | Brute Force, Password Spray, Impossible Travel, Mailbox Activity, M2, M6→M8, M10, M12, M14 | Force brute, pays inhabituel, vol de session, consentement OAuth, audit, étiquetage Purview, accès conditionnel |
| A : Azure Activity Log | [rules/azure/](rules/azure/) | A1→A11 (non revalidées) | Attribution de rôle, Key Vault, verrous de ressources, destruction bloquée |
| Clones et supervision | [rules/suricata/](rules/suricata/), [rules/pipeline/](rules/pipeline/) | Clone 876, heartbeat | Alertes Suricata moyennes hors balayages bloqués, supervision du pipeline SOC |

→ [README détaillé de la bibliothèque](rules/README.md)

---

## 🖥️ Environnement de lab

| Composant | Détail |
|-----------|--------|
| **SIEM** | UTMStack v11.3.0 Community Edition |
| **Hôte** | HP Elite Tower 800 G9, i7-14700, 64 GB RAM |
| **Hyperviseur** | VMware Workstation |
| **Firewall / IDS** | OPNsense 26.1 + Suricata 8.0.5 |
| **OS SIEM** | Ubuntu 24.04 LTS (10.100.1.150) |
| **Active Directory** | Windows Server 2025, topologie multi-sites (2 DC, 2 sites AD) |
| **Agents Windows** | DC01-MAIN-SITE, DC01-RM, gest-srv, un poste géré par Intune (Win 11 24H2), WIN11-AD-TESTS (Win 11 24H2) |
| **Agent Linux** | docker-services (Ubuntu 26.04) : n8n, Qdrant, Open WebUI, SearXNG |
| **Microsoft 365** | Entra ID P1, MDE Plan 1 |
| **Azure** | Event Hub et Event Grid : Activity Log et Resource Events (intégration désactivée pour raison de coût) |

---

## 🔩 Stack technique

- **IDS** : Suricata 8.0.5 sur OPNsense, Emerging Threats Open, NF Rules et règles custom
- **HIDS** : CrowdSec et bouncer OPNsense, blocage en temps réel, whitelist étendue
- **SOAR** : UTMStack Incident Response + SSH → CrowdSec
- **WEF** : Windows Event Forwarding, self-subscription locale : NTLM et Sysmon → ForwardedEvents → UTMStack
- **M365** : API O365 Management : Entra ID, Exchange, SharePoint, événements MDE
- **Azure** : Event Hub (Activity Log + Event Grid) → index `v11-log-azure-*`
- **SOC AI** : module natif UTMStack + pipeline n8n custom (Ollama local)
- **Pipeline IA** : Ollama (Llama 3.1 8B) et n8n, tri déterministe, enrichissement AbuseIPDB/GreyNoise/OTX/ThreatFox
- **Sysmon** : v15.21, schéma 4.91, méthode registre ANSSI, collecte WEF → UTMStack
- **Règles personnalisées** : 48 règles YAML pour v11.3.0, 34 techniques MITRE ATT&CK

---

## ☕ Soutenir le projet

Ces guides représentent des centaines d'heures de tests en environnements réels.

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/R5R31YHNIB)

---

ℹ️ *Références et aide à la rédaction assistées par IA, avec validation humaine finale.*
