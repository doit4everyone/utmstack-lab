---
title: "Intégrations agents et sources de logs — UTMStack v11 | DoIt4Everyone"
description: "Guide complet des intégrations UTMStack v11 : agent Windows, agent Linux, collecteur UTMStack, Microsoft 365, Azure Event Hub, SOC AI natif. Règles de corrélation custom Windows Defender et O365 avec tuning des faux positifs."
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

# Chapitre 10 — Intégrations des agents et sources de logs

> [← Retour à l'index](../)

Ce chapitre documente l'ensemble des sources de logs connectées au SIEM UTMStack dans le lab. L'objectif est d'avoir une visibilité complète sur l'infrastructure : endpoints Windows, serveurs Linux, firewall OPNsense, Microsoft 365 et Azure.

## 📋 Table des matières

1. [Vue d'ensemble des sources de logs](#1-vue-densemble-des-sources-de-logs)
2. [Agent Windows](#2-agent-windows)
   - [2.1 Installation et configuration](#21-installation-et-configuration)
   - [2.2 Canaux collectés par défaut](#22-canaux-collectés-par-défaut)
   - [2.3 Windows Defender — événements collectés](#23-windows-defender--événements-collectés)
3. [Syslog & Suricata (OPNsense)](#3-syslog--suricata-opnsense)
4. [Agent Linux (docker-services)](#4-agent-linux-docker-services)
5. [Collecteur UTMStack (auto-supervision)](#5-collecteur-utmstack-auto-supervision)
6. [Microsoft 365](#6-microsoft-365)
   - [6.1 Prérequis et App Registration](#61-prérequis-et-app-registration)
   - [6.2 Configuration dans UTMStack](#62-configuration-dans-utmstack)
   - [6.3 Dashboards O365 prédéfinis](#63-dashboards-o365-prédéfinis)
   - [6.4 Règles de corrélation O365 natives](#64-règles-de-corrélation-o365-natives)
   - [6.5 Règles custom O365 développées dans ce lab](#65-règles-custom-o365-développées-dans-ce-lab)
   - [6.6 Gaps de détection vs licence](#66-gaps-de-détection-vs-licence)
7. [Intégration Azure (Event Hub)](#7-intégration-azure-event-hub)
   - [7.1 Pourquoi Event Hub et pas Log Analytics](#71-pourquoi-event-hub-et-pas-log-analytics)
   - [7.2 Procédure de configuration](#72-procédure-de-configuration)
   - [7.3 Types d'événements observés](#73-types-dévénements-observés)
   - [7.4 Coûts et nettoyage](#74-coûts-et-nettoyage)
8. [SOC AI natif UTMStack](#8-soc-ai-natif-utmstack)
   - [8.1 Architecture et providers supportés](#81-architecture-et-providers-supportés)
   - [8.2 Connexion à Ollama local](#82-connexion-à-ollama-local)
   - [8.3 Mécanisme de création d'incidents](#83-mécanisme-de-création-dincidents)
   - [8.4 Mécanisme des Echoes](#84-mécanisme-des-echoes)
   - [8.5 Exemple d'analyse — Mistral Small](#85-exemple-danalyse--mistral-small)
   - [8.6 Comparaison SOC AI natif vs Pipeline n8n](#86-comparaison-soc-ai-natif-vs-pipeline-n8n)
9. [Index OpenSearch — Structure des données](#9-index-opensearch--structure-des-données)

---

## 1. Vue d'ensemble des sources de logs

Le lab UTMStack collecte des logs depuis sept sources distinctes, chacune utilisant un mécanisme d'intégration différent.

| Source | Mécanisme | Index OpenSearch | Statut |
|---|---|---|---|
| Agents Windows (5 machines) | Agent UTMStack | `v11-log-wineventlog-*` | ✅ All connected |
| OPNsense / Suricata | Syslog → Agent gest-srv | `v11-log-suricata-*` | ✅ All connected |
| docker-services (Ubuntu) | Agent Linux UTMStack | `v11-log-linux-*` | ✅ All connected |
| UTMStack lui-même | Collecteur UTMStack | `v11-log-utmstack-*` | ✅ All connected |
| Microsoft 365 / Entra ID | API O365 Management | `v11-log-o365-*` | ✅ All connected |
| Azure Activity Log | Event Hub | `v11-log-azure-*` | ✅ All connected |
| Azure Event Grid | Event Hub | `v11-log-azure-*` | ✅ All connected |

> ℹ️ OPNsense (10.100.1.254) remonte deux types de logs distincts : `suricata` (alertes IDS) et `syslog` (logs système OPNsense), tous deux visibles dans Data Sources.

---

## 2. Agent Windows

### 2.1 Installation et configuration

L'agent Windows UTMStack s'installe via un script PowerShell généré automatiquement par l'interface UTMStack. La procédure est identique pour toutes les machines Windows du lab.

**Prérequis :**
- Windows Server 2016 R2 ou supérieur (Windows 11 également supporté)
- Ports 9000, 9001 et 50051 ouverts vers le SIEM (10.100.1.150)
- `curl` disponible sur le système

**Procédure :**

1. Dans UTMStack → **Integrations** → carte **Windows Agent** → **Enabled**
2. Sélectionner la plateforme (**AMD64** ou ARM64) et l'action (**INSTALL**)
3. UTMStack génère un script PowerShell contenant l'IP du SIEM et la clé de connexion

> ⚠️ **Sécurité** : le script généré contient une clé de connexion sensible. Ne jamais le publier ou le partager. Traiter cette clé comme un secret.

4. Exécuter le script en **PowerShell Administrateur** sur la machine cible :

```powershell
# Exemple de structure du script généré (clé masquée)
New-Item -ItemType Directory -Force -Path "C:\Program Files\UTMStack\UTMStack Agent"
curl.exe -k -o "C:\Program Files\UTMStack\UTMStack Agent\utmstack_agent_service_windows_amd64.exe" `
  "https://10.100.1.150:9001/private/dependencies/agent/utmstack_agent_service_windows_amd64.exe"
Start-Process "C:\Program Files\UTMStack\UTMStack Agent\utmstack_agent_service_windows_amd64.exe" `
  -ArgumentList 'install', '10.100.1.150', '***CLÉ_GÉNÉRÉE***', 'yes' -NoNewWindow -Wait
```

Le script crée le service Windows `UTMStackAgent` qui démarre automatiquement. La machine apparaît dans **Data Sources** avec le statut "All connected" dès réception des premiers logs.

> 💡 **Déploiement via GPO** : le script PowerShell peut être déployé via GPO (Computer Configuration → Scripts Startup) pour un déploiement en masse sur plusieurs machines du domaine.

**Machines équipées dans le lab :**

| Machine | IP | OS |
|---|---|---|
| DC01-MAIN-SITE | 10.100.1.1 | Windows Server 2025 |
| DC01-RM | 10.100.2.1 | Windows Server 2025 |
| gest-srv | 10.100.1.16 | Windows Server 2025 |
| MDM-BLAISE-871 | 10.100.2.150 | Windows 11 24H2 |
| WIN11-AD-TESTS | 10.100.1.153 | Windows 11 24H2 |

### 2.2 Canaux collectés par défaut

L'agent UTMStack collecte nativement les canaux Windows suivants sans configuration supplémentaire :

- `Security` — événements d'authentification (4624, 4625, 4648, 4768, 4769...)
- `System` — événements système et services
- `Application` — événements applicatifs
- `Microsoft-Windows-Windows Defender/Operational` — **détections Defender complètes**
- `Microsoft-Windows-Sysmon/Operational` — si Sysmon est installé
- `ForwardedEvents` — événements WEF reçus par le collecteur

> ℹ️ **Découverte importante** : l'agent UTMStack collecte nativement et complètement les événements Windows Defender. Le déploiement WEF (Windows Event Forwarding) n'est donc **pas nécessaire** pour la supervision Defender — contrairement à ce qu'on pourrait supposer initialement.

### 2.3 Windows Defender — événements collectés

#### Event IDs supervisés

| Event ID | Description | Criticité | Testé |
|---|---|---|---|
| 1116 | Malware détecté | HIGH | ✅ EICAR test |
| 1117 | Malware remédiéi (quarantaine/suppression) | INFO | ✅ EICAR test |
| 1118 | Remédiation échouée — malware toujours présent | CRITICAL | ⚠️ Non testé |
| 5001 | Protection temps réel désactivée | HIGH | ⚠️ Bloqué Tamper Protection |
| 5007 | Configuration modifiée (exclusions...) | HIGH | ✅ MDM-BLAISE-871 |
| 5013 | Modification bloquée par Tamper Protection | HIGH | ✅ MDM-BLAISE-871 |

**Comportement multi-événements :** pour une même détection, Defender peut générer plusieurs Event 1116 avec le même `Detection ID` mais des champs `Path` différents. Ce comportement est normal — il reflète les différents moteurs de détection (antivirus classique, SmartScreen). Pour une vue complète d'une détection, grouper par `log.data.Detection ID`.

**Richesse des champs selon le vecteur :** les logs générés lors d'un téléchargement web (via SmartScreen) sont significativement plus riches que les détections sur écriture locale — ils incluent l'URL source, le PID du processus navigateur, et le contexte réseau complet dans `log.data.Path`.

#### Règle native active

La règle native UTMStack **"Windows Defender - Malware Detected (Event 1116)"** fonctionne correctement — aucune règle custom n'est nécessaire pour cet event.

#### Règles custom créées

Quatre règles custom ont été développées pour compléter la couverture native. Elles sont disponibles dans le [dépôt GitHub](https://github.com/doit4everyone/utmstack-lab/tree/main/rules/windows-defender).

**Philosophie de tuning appliquée :** approche défensive — la règle capture large, les faux positifs connus sont exclus chirurgicalement. Cette approche minimise le risque de rater une vraie menace, au prix d'un tuning itératif en production.

| Règle | Event | FP exclus documentés |
|---|---|---|
| windows-defender-exclusion-added.yml | 5007 | WdConfigHash, UX Configuration, DLP Configs, EcsConfigs |
| windows-defender-realtime-disabled.yml | 5001 | — |
| windows-defender-remediation-failed.yml | 1118 | — |
| windows-defender-tamper-protection.yml | 5013 | Changed Type = Ignoré |

**Faux positifs documentés sur Event 5007 :**

| Clé de registre exclue | Source | Raison |
|---|---|---|
| `WdConfigHash` | Toutes machines | Hash de configuration interne, recalculé automatiquement lors des mises à jour Defender |
| `UX Configuration` | Toutes machines | Paramètres d'interface utilisateur Defender, modifiés automatiquement |
| `DLP Configs` | Machines Intune/MDE | Configuration DLP gérée par Intune, modifiée automatiquement |
| `EcsConfigs` | Machines Intune/MDE | Déploiement progressif de fonctionnalités MDE via Edge Configuration Service |

> 💡 **Recommandation SOC** : les faux positifs sur Event 5007 sont spécifiques à l'environnement de gestion (Intune, SCCM, GPO). Dans un environnement différent, d'autres clés de registre peuvent nécessiter des exclusions supplémentaires. La liste ci-dessus sert de base de départ, pas de référence exhaustive. L'approche défensive (exclure les FP connus un par un) est préférable à l'approche offensive (liste blanche de patterns dangereux), car elle garantit de ne pas rater une vraie attaque sur une clé non encore documentée.

---

## 3. Syslog & Suricata (OPNsense)

Le pipeline OPNsense → UTMStack est documenté en détail dans les chapitres 02 et 07. Ce chapitre en fait uniquement référence.

**Architecture résumée :** `Suricata eve.json → syslog-ng (OPNsense) → port 7019 → Agent UTMStack (gest-srv) → OpenSearch`

**Index OpenSearch :** `v11-log-suricata-*` pour les alertes Suricata, `v11-log-generic-*` pour les autres logs syslog.

**Références :**
- [Chapitre 02 — Intégration Suricata](https://doit4everyone.github.io/utmstack-lab/docs/02-suricata.html)
- [Chapitre 07 — Règles Suricata avancées](https://doit4everyone.github.io/utmstack-lab/docs/07-custom-rules.html)

---

## 4. Agent Linux (docker-services)

La VM `docker-services` (10.100.1.10, Ubuntu 26.04) héberge les services du pipeline SOC IA : n8n, Qdrant, Open WebUI, SearXNG. L'agent Linux UTMStack y est déployé pour superviser l'activité système.

### Procédure d'installation

1. Dans UTMStack → **Integrations** → carte **Linux agent** → **Enabled**
2. Sélectionner **Ubuntu / Debian (AMD64)** et l'action **INSTALL**
3. Exécuter le script généré en root sur la machine cible :

```bash
sudo bash -c "apt update -y && apt install wget -y && \
  mkdir -p /opt/utmstack-linux-agent && \
  wget --no-check-certificate -P /opt/utmstack-linux-agent \
  https://10.100.1.150:9001/private/dependencies/agent/utmstack_agent_service_linux_amd64 && \
  chmod -R 755 /opt/utmstack-linux-agent/utmstack_agent_service_linux_amd64 && \
  /opt/utmstack-linux-agent/utmstack_agent_service_linux_amd64 install 10.100.1.150 ***CLÉ*** yes"
```

**Résultat attendu :**

```
Installing UTMStackAgent service ...
Checking server connection ... [OK]
Downloading version info ... [OK]
Configuring agent ... [OK]
Creating service ... [OK]
UTMStackAgent service installed correctly
```

4. Générer du bruit pour activer la source dans UTMStack :

```bash
for i in $(seq 1 10); do logger "UTMStack agent test event $i"; done
```

La machine apparaît dans **Data Sources** avec le type `linux` et le statut "All connected".

**Différences avec l'agent Windows :**

| | Agent Windows | Agent Linux |
|---|---|---|
| Binaire | `utmstack_agent_service_windows_amd64.exe` | `utmstack_agent_service_linux_amd64` |
| Répertoire | `C:\Program Files\UTMStack\UTMStack Agent\` | `/opt/utmstack-linux-agent/` |
| Service | `UTMStackAgent` (Windows Services) | `UTMStackAgent.service` (systemd) |
| Plateformes | AMD64, ARM64 | Ubuntu/Debian AMD64/ARM64, Fedora/RedHat AMD64/ARM64 |

> ℹ️ **Note docker-services** : la machine héberge de nombreuses interfaces réseau virtuelles Docker. UTMStack détecte et enregistre toutes les adresses MAC et IPv6 des interfaces Docker dans le détail de la source — comportement normal, non filtrable.

---

## 5. Collecteur UTMStack (auto-supervision)

Le collecteur UTMStack est un composant distinct de l'agent standard — il est conçu spécifiquement pour superviser la VM SIEM elle-même.

### Procédure d'installation

1. Dans UTMStack → **Integrations** → carte **UTMStack** → **Enabled**

> ⚠️ Ce collecteur ne peut être installé **que sur la VM UTMStack elle-même** (Ubuntu). Ne pas l'installer sur d'autres machines.

2. Sélectionner **Ubuntu 16/18/20+** et l'action **INSTALL**
3. Exécuter le script en root sur la VM UTMStack :

```bash
sudo bash -c "apt update -y && apt install wget -y && \
  mkdir -p /opt/utmstack-collector && \
  wget --no-check-certificate -P /opt/utmstack-collector \
  https://10.100.1.150:9001/private/dependencies/collector/utmstack_collector && \
  chmod -R 755 /opt/utmstack-collector/utmstack_collector && \
  /opt/utmstack-collector/utmstack_collector install 10.100.1.150 ***CLÉ*** yes"
```

4. Cliquer sur **Enable integration** dans l'UI UTMStack

> ⚠️ **Étape obligatoire** : sans ce clic, les fonctionnalités de supervision ne s'activent pas même si le collecteur tourne correctement.

### Fonctionnement

Contrairement à l'agent standard qui collecte des logs syslog, le collecteur UTMStack se connecte directement au daemon Docker et streame en temps réel les logs des 22 conteneurs du stack UTMStack.

**Contenu supervisé :** `agentmanager`, `event-processor-manager`, `event-processor-worker`, `backend`, `frontend`, OpenSearch, PostgreSQL, et tous les autres services du stack.

**Structure des fichiers :**

| Fichier | Rôle |
|---|---|
| `utmstack_collector` | Binaire du collecteur |
| `config.yml` | Configuration |
| `uuid.yml` | Identifiant unique de l'instance |
| `version.json` | Version du collecteur |
| `retention.json` | Politique de rétention |
| `logs/` | Logs du collecteur |
| `logs_process/` | Logs du processus de supervision |

**Service systemd :** `UTMStackCollector.service` (noter la casse — différent de `UTMStackAgent.service`)

**Index OpenSearch :** `v11-log-utmstack-*` avec `dataType: utmstack` et `dataSource: utmstack`.

**Champs notables :** `log.containerName` (nom du conteneur source), `log.args.context`, `log.args.method`, `log.args.path`.

---

## 6. Microsoft 365

### 6.1 Prérequis et App Registration

**Prérequis licence :** Entra ID P1 minimum (inclus dans Microsoft 365 Business Premium). Entra ID P2 ou Microsoft 365 E5 débloque les alertes MDE formelles avec `ThreatName` et l'Impossible Travel natif.

#### Étape 1 — Créer l'App Registration

1. [portal.azure.com](https://portal.azure.com) → **Microsoft Entra ID** → **Inscriptions d'applications** → **+ Nouvelle inscription**
2. Remplir le formulaire :

| Champ | Valeur |
|---|---|
| Nom | `UTMStack O365 Agent` |
| Types de comptes pris en charge | **Locataire unique seulement** |
| URI de redirection | *(laisser vide)* |

3. Cliquer sur **S'inscrire**
4. Noter le **Client ID** (ID d'application) et le **Tenant ID** (ID de l'annuaire) affichés dans la vue d'ensemble

#### Étape 2 — Créer le secret client

Dans l'App Registration → **Certificats et secrets** → **+ Nouveau secret client** :

| Champ | Valeur |
|---|---|
| Description | `UTMStack M365 Integration` |
| Expiration | **730 jours (24 mois)** |

> ⚠️ **Copier immédiatement la valeur du secret** après création — elle ne sera plus visible après avoir quitté la page. En cas d'oubli, il faudra en créer un nouveau.

#### Étape 3 — Ajouter les permissions API

Dans l'App Registration → **API autorisées** → **+ Ajouter une autorisation** :

**Office 365 Management APIs → Autorisations d'application :**

| Permission | Type | Rôle |
|---|---|---|
| `ActivityFeed.Read` | Application | Lecture des logs d'activité O365 |
| `ActivityFeed.ReadDlp` | Application | Lecture des events DLP |

**Microsoft Graph → Autorisations déléguées :**

| Permission | Type |
|---|---|
| `SecurityAlert.Read.All` | Déléguée |
| `SecurityAlert.ReadWrite.All` | Déléguée |

**Microsoft Graph → Autorisations d'application :**

| Permission | Type |
|---|---|
| `SecurityAlert.Read.All` | Application |
| `SecurityAlert.ReadWrite.All` | Application |

> ℹ️ `User.Read` est ajouté automatiquement à la création — le laisser en place.

> ℹ️ `ServiceHealth.Read` n'est **pas** requis par UTMStack — ne pas l'ajouter.

Après chaque ajout de permissions, cliquer sur **Accorder un consentement d'administrateur pour [nom du tenant]** et confirmer. Toutes les permissions doivent afficher le statut ✅ **Accordé**.

#### Étape 4 — Vérifier l'audit Microsoft Purview

L'audit M365 doit être actif pour que les logs remontent. Vérification depuis un poste local :

```powershell
# Installer le module si nécessaire (PowerShell local, en tant qu'Administrateur)
Install-Module -Name ExchangeOnlineManagement -Force -AllowClobber

# Vérifier si l'audit est actif
Connect-ExchangeOnline
Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled
# Résultat attendu : UnifiedAuditLogIngestionEnabled : True

# Si False — activer l'audit
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true

Disconnect-ExchangeOnline -Confirm:$false
```

> ⚠️ **Compatibilité PowerShell** : Windows PowerShell 5.1 est la méthode la plus fiable. Le module est également supporté sous PowerShell 7 (v7.4+ pour les versions 3.5.0 à 3.9.2 du module, v7.6+ pour les versions 3.10.0+). Azure Cloud Shell est techniquement supporté mais des conflits de versions avec le module Az préchargé peuvent provoquer des erreurs — si c'est le cas, ajouter `-DisableWAM` à la commande `Connect-ExchangeOnline`.

> ℹ️ Sur un tenant actif avec des utilisateurs licenciés, l'audit est généralement déjà actif. Le portail Microsoft Purview ([purview.microsoft.com](https://purview.microsoft.com)) le confirme : si l'interface de recherche Audit s'affiche directement sans bannière d'activation, l'audit est actif. L'ancien portail `compliance.microsoft.com` est retraité depuis novembre 2024 et redirige automatiquement vers Purview.

### 6.2 Configuration dans UTMStack

Dans UTMStack → **Integrations** → carte **Microsoft 365** → **Enabled**.

Cliquer sur **+ Add tenant** — un formulaire en deux étapes s'ouvre :

**Étape 1 — Créer le groupe :**

| Champ | Valeur |
|---|---|
| Name | Nom libre identifiant le tenant (ex: `M365 Lab`) |
| Group description | Description libre |

**Étape 2 — Saisir les credentials :**

| Champ UTMStack | Valeur à saisir |
|---|---|
| **Client ID** | ID d'application (client) de l'App Registration |
| **Client Secret** | Valeur du secret créé à l'étape 2 |
| **Tenant ID** | ID de l'annuaire (locataire) |
| **Cloud Environment** | `Commercial - Azure commercial global (Default)` |

Cliquer sur **Save configuration**. UTMStack teste la connexion et affiche une confirmation **"Check module configuration — Microsoft 365 ✅"** si les credentials sont valides.

Cliquer ensuite sur le bouton **Enable integration** pour activer les règles de corrélation M365 dans UTMStack.

> ℹ️ Il est possible d'ajouter **plusieurs tenants** en cliquant à nouveau sur **+ Add tenant** — utile pour superviser plusieurs organisations M365 depuis un même UTMStack.

**Index créé :** `v11-log-o365-*`

> ⚠️ L'index est `v11-log-o365-*` et **non** `v11-log-office365-*` — important pour les requêtes OpenSearch et les règles de corrélation.

**Latence observée :** ~5 minutes entre l'événement réel et son apparition dans UTMStack (polling de l'API O365 Management). Les horodatages affichés dans UTMStack sont en **UTC** — les événements n'ont pas de retard réel, c'est uniquement le fuseau horaire affiché vs le fuseau local.

**Volume de données observé :** avec un tenant Business Premium, un seul poste enrollé MDE et un utilisateur actif, le volume O365 est d'environ **400-500 KB/jour** — négligeable par rapport aux logs Windows (~150 MB/jour).

### 6.3 Dashboards O365 prédéfinis

L'activation de l'intégration crée automatiquement 5 dashboards O365 natifs accessibles depuis **Dashboards** :

| Dashboard | Contenu principal |
|---|---|
| **O365 Overview** | Vue globale : Failed Logins, Top Exchange Operations, SharePoint File Access, carte des connexions réussies, Top 5 events by Source (Endpoint/AzureActiveDirectory/Exchange), Alerts by Category |
| **O365 Exchange** | Activités email, règles inbox, opérations Exchange |
| **O365 Active Directory** | Connexions Entra ID, échecs par utilisateur, carte géographique, Failed Operations Count, Logon Error Count |
| **O365 SharePoint** | Accès fichiers, partages, activités SharePoint/OneDrive |
| **O365 Threat Intelligence** | Event Count par source (Endpoint, AzureActiveDirectory), Phishing Targets, Recent Attacks, Top 5 events by Source |

> ℹ️ Les dashboards s'alimentent progressivement — avec peu d'historique, certains widgets affichent "No data found". Après 24-48h d'activité normale sur le tenant, tous les widgets se remplissent. Le widget **O365 Alerts by Category** est cliquable et drille directement vers la liste des alertes filtrées par catégorie.

### 6.4 Règles de corrélation O365 natives

UTMStack CE inclut **15 règles de corrélation natives** pour les logs O365, toutes actives par défaut. Inventaire extrait depuis PostgreSQL :

| ID | Règle | Catégorie |
|---|---|---|
| 792 | Office 365 Anti-Phishing Policy Bypass Detected | Defense Evasion |
| 793 | Office 365 App Consent Grants Detected | Persistence |
| 801 | O365 Excessive Single Sign-On Logon Errors | Credential Access |
| 806 | Data Loss Prevention Policy Violation ✅ | Data Loss Prevention |
| 812 | Office 365 Forms and Sway Phishing Detection | Initial Access |
| 823 | Office 365 Mail Flow Rule Modified | Defense Evasion |
| 825 | Office 365 Mailbox Delegation Abuse | Persistence |
| 826 | Office 365 Mailbox Export to PST | Data Exfiltration |
| 832 | Office 365 OAuth Application Anomalous Activity | Credential Access |
| 838 | Office 365 Safe Attachment Policy Violation | Initial Access |
| 1437 | O365 Audit Log Purge | Defense Evasion |
| 1438 | O365 Admin Role/Permission Granted | Privilege Escalation |
| 1439 | O365 Inbox Forward Rule with Email Exfiltration | Data Exfiltration |
| 1440 | O365 Admin Role Assignment | Privilege Escalation |
| 802 | Microsoft 365 Exchange Malware Filter Policy Deletion | Defense Evasion |

> ⚠️ **Point d'attention — Règle 801** : cette règle cible uniquement les erreurs `SsoArtifactInvalidOrExpired` (tokens SSO invalides), **pas** les tentatives `InvalidUserNameOrPassword` (brute force classique). Pour détecter le brute force sur mot de passe, une règle custom est nécessaire — voir section 6.5.

> ℹ️ **Limitation CE** : avec Entra ID P1 et MDE Plan 1, les alertes MDE formelles (RecordType 41 avec `ThreatName`) ne sont pas disponibles. Seuls les events d'audit endpoint (RecordType 63, `Workload: Endpoint`) remontent dans UTMStack. La détection malware avec `ThreatName` complet passe par l'agent Windows (Event 1116) — voir section 2.3.

### 6.5 Règles custom O365 développées dans ce lab

Quatre règles custom ont été développées, testées et validées pour combler les gaps de détection avec une licence P1. Elles sont disponibles dans le [dépôt GitHub](https://github.com/doit4everyone/utmstack-lab/tree/main/rules/o365).

| Fichier | Règle | Scénario testé |
|---|---|---|
| `o365-entra-brute-force.yml` | Entra ID - Brute Force Password Attack | 6 tentatives `InvalidUserNameOrPassword` consécutives |
| `o365-entra-password-spray.yml` | Entra ID - Password Spray Attack | 1 mot de passe testé sur 5 comptes distincts |
| `o365-mde-malware-deleted.yml` | MDE Endpoint - Malware File Deleted by Defender | Fichier EICAR supprimé par MDE |
| `o365-impossible-travel.yml` | Entra ID - Impossible Travel Detection | Connexion CH puis NL via ProtonVPN dans la même fenêtre 2h |

> ℹ️ **Règles Brute Force vs Password Spray** : les deux règles partagent intentionnellement la même condition `where` (`UserLoginFailed` + `InvalidUserNameOrPassword`). La distinction entre les deux types d'attaque se fait lors de l'investigation : si `origin.user` est identique sur toutes les alertes → brute force ; si `origin.user` est différent sur chaque alerte depuis la même IP → password spray.

> ℹ️ **Règle MDE Malware Deleted** : avec MDE Plan 1, les events O365 de type `FileDeleted` (Workload: Endpoint, RecordType 63) ne contiennent pas le `ThreatName`. Pour une détection avec le nom complet de la menace, utiliser la règle Windows native sur l'Event 1116 (section 2.3). Les deux règles sont complémentaires : O365 pour la visibilité cloud, agent Windows pour les détails de la menace.

> ℹ️ **Règle Impossible Travel** : détecte deux `UserLoggedIn` du même utilisateur depuis deux pays différents dans une fenêtre de 2 heures, via le mécanisme `afterEvents`. Avec Entra ID P1, cette corrélation est assurée par UTMStack — Entra ID P2 (Identity Protection) offre une détection native avec scoring de risque automatisé.

### 6.6 Gaps de détection vs licence

| Fonctionnalité | P1 / MDE Plan 1 | P2 / E5 | Compensé par règle custom |
|---|---|---|---|
| Logs audit O365 (Exchange, SharePoint, Teams) | ✅ | ✅ | — |
| Events audit endpoint MDE (RecordType 63) | ✅ | ✅ | — |
| Alertes MDE avec ThreatName | ❌ | ✅ | ✅ Event 1116 via agent Windows |
| Brute force / Password Spray Entra ID | ❌ natif | ✅ | ✅ Règles custom |
| Impossible Travel | ❌ natif | ✅ | ✅ Règle custom afterEvents |
| Identity Protection (risk scoring) | ❌ | ✅ | ❌ |
| Privileged Identity Management (PIM) | ❌ | ✅ | ❌ |
| DLP Purview — détection | ✅ | ✅ | — |
| DLP Purview — blocage effectif | ⚠️ Partiel | ✅ | — |

> ℹ️ **DLP Purview avec Business Premium** : les règles DLP détectent et notifient, mais le blocage effectif des partages externes peut ne pas s'appliquer sans licence Purview add-on. Les événements `DLPRuleMatch` remontent correctement dans UTMStack et déclenchent la règle native 806 (**Data Loss Prevention Policy Violation**) — testée avec un fichier RH contenant un numéro AVS suisse.

---

## 7. Intégration Azure (Event Hub)

### 7.1 Pourquoi Event Hub et pas Log Analytics

Azure propose deux mécanismes d'export de logs : Log Analytics Workspace et Event Hub. UTMStack dispose d'un connecteur natif Event Hub — c'est donc le choix naturel pour cette intégration. Log Analytics est conçu pour rester dans l'écosystème Microsoft (Sentinel, Azure Monitor) et son export vers des SIEM tiers nécessite des workarounds (Logic Apps, Azure Functions).

### 7.2 Procédure de configuration

**Architecture :**

```
Azure Activity Log ──────────────────────────────┐
                                                  ▼
Azure Event Grid ──────────────────────► Event Hub (utmstack-azure/utmstack)
                                                  │
                                                  ▼
                                    UTMStack consomme (utmstack-listen)
                                                  │
                                                  ▼
                                         v11-log-azure-*
```

**Étape 1 — Créer le namespace Event Hub**

portal.azure.com → **Event Hubs** → **+ Créer** :

| Paramètre | Valeur |
|---|---|
| Groupe de ressources | `utmstack-azure` (nouveau) |
| Nom du namespace | `utmstack-azure` |
| Région | Switzerland North |
| Niveau tarifaire | Essentiel (Basic) |
| Unités de débit | 1 |

> ⚠️ **Limitation tier Essentiel** : un seul Consumer Group (`$Default`) — suffisant pour un lab avec UTMStack comme unique consommateur.

**Étape 2 — Créer l'Event Hub**

Dans le namespace → **+ Event Hub** :

| Paramètre | Valeur |
|---|---|
| Nom | `utmstack` |
| Partitions | 1 |
| Rétention | 1 heure (minimum) |

**Étape 3 — Créer les stratégies d'accès partagé (SAS)**

Deux règles séparées par principe de moindre privilège :

| Règle | Droits | Usage |
|---|---|---|
| `utmstack-listen` | Écouter uniquement | UTMStack lit les events |
| `azure-monitor-send` | Envoyer uniquement | Azure Monitor pousse les logs |

Récupérer la **connection string** de `utmstack-listen`.

**Étape 4 — Storage Account**

Nécessaire pour les checkpoints de position de lecture :

| Paramètre | Valeur |
|---|---|
| Nom | `utmstackazure` |
| Groupe de ressources | `utmstack-azure` |
| Région | Switzerland North |
| Type | Stockage Blob Azure |
| Performance | Standard |
| Redondance | LRS |

Créer un **container** nommé `utmstack` (accès Privé). Récupérer la **connection string** depuis Clés d'accès → key1.

**Étape 5 — Configurer les Diagnostic Settings**

Abonnements → votre abonnement → **Journal d'activité** → **Paramètres de diagnostic** → **+ Ajouter** :

- Cocher toutes les catégories : Administrative, Security, ServiceHealth, Alert, Recommendation, Policy, Autoscale, ResourceHealth
- Destination : **Diffuser vers Event Hub**
- Namespace : `utmstack-azure`, Hub : `utmstack`, Stratégie : `azure-monitor-send`

**Étape 6 — Configurer UTMStack**

Integrations → **Azure** → **Enabled** → onglet **Custom** → renseigner :

- Event Hub Connection string :

```
Endpoint=sb://utmstack-azure.servicebus.windows.net/;SharedAccessKeyName=utmstack-listen;SharedAccessKey=***;EntityPath=utmstack
```

> ⚠️ **Important** : ajouter `;EntityPath=utmstack` à la fin — UTMStack l'exige mais Azure ne le génère pas automatiquement dans la connection string.

- Consumer Group Name : `$Default`
- Storage Container Name : `utmstack`
- Storage Account Connection string : `DefaultEndpointsProtocol=https;AccountName=utmstackazure;AccountKey=***;EndpointSuffix=core.windows.net`

→ **Save configuration** → **Enable integration**

**Étape 7 — Event Grid (optionnel)**

Vérifier que `Microsoft.EventGrid` est enregistré : Abonnements → Fournisseurs de ressources → statut **Registered** (automatique si Event Hub créé).

Créer un abonnement aux événements : **Événements** → **+ Abonnement à un événement** → point de terminaison : **Hub d'événements** → `utmstack`.

> ℹ️ Event Grid est optionnel pour un lab — les Diagnostic Settings seuls suffisent pour capturer l'Activity Log complet. Event Grid ajoute les événements de ressources en temps réel (créations, modifications, suppressions).

### 7.3 Types d'événements observés

Deux canaux distincts avec des structures de champs différentes dans UTMStack :

| Canal | Structure des champs | Catégories |
|---|---|---|
| Activity Log (Diagnostic Settings) | `log.operationName`, `log.resultType`, `log.level` | Administrative, Security, Policy, ServiceHealth... |
| Event Grid | `log.data.operationName`, `log.data.status`, `log.eventType` | ResourceWriteSuccess, ResourceDeleteSuccess... |

**Catégories les plus utiles pour la détection SOC :**

- **Administrative** : créations/suppressions de ressources, modifications IAM
- **Policy** : violations des politiques Azure (VM sans JIT, ressources non conformes)
- **Security** : alertes Microsoft Defender for Cloud
- **ResourceActionSuccess/Failure** : actions sur les ressources via Event Grid

**Exemple — tentative de suppression d'un Resource Group verrouillé :**

```json
{
  "log.operationName": "MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/DELETE",
  "log.resultType": "Failure",
  "log.resultSignature": "Failed.Conflict",
  "log.properties.statusCode": "Conflict",
  "log.level": "Error"
}
```

Ce pattern est un bon candidat pour une règle de corrélation — détection d'une tentative de destruction d'infrastructure bloquée par un verrou (accidentelle ou malveillante).

### 7.4 Coûts et nettoyage

Coût estimé pour 2-3 semaines de test : ~5 CHF (Event Hub Basic ~2-3 CHF/mois, Storage LRS < 1 CHF/mois).

**Pour supprimer après les tests :**
1. Supprimer le **groupe de ressources `utmstack-azure`** — supprime tout d'un coup (Event Hub, Storage Account)
2. Désactiver le paramètre de diagnostic `utmstack` dans l'abonnement Azure
3. Dans UTMStack → Integrations → Azure → **Disable integration**

---

## 8. SOC AI natif UTMStack

UTMStack CE inclut un module SOC AI intégré accessible depuis l'onglet **SOC AI** de chaque alerte.

### 8.1 Architecture et providers supportés

**Providers supportés :** OpenAI, Anthropic, Azure OpenAI, Google Gemini, Ollama, Mistral AI, DeepSeek, Groq, Custom (compatible OpenAI API).

**Configuration :** Integrations → SOC AI → sélectionner le provider et renseigner les credentials.

**Trois options de comportement :**

| Option | Effet |
|---|---|
| Auto-analyze alerts | Enfile chaque nouvelle alerte dans la file d'attente → appel LLM automatique |
| Auto-create incidents | Groupe automatiquement les alertes par datasource sur 24h → crée un incident |
| Change alert status after analysis | Passe l'alerte de `Open (status=2)` à `Completed (status=5)` après l'analyse LLM |

### 8.2 Connexion à Ollama local

Le tab **Ollama** natif contient un bug en v11.2.12 — il envoie `POST /` au lieu de `POST /v1/chat/completions`, ce qui génère une erreur HTTP 405.

**Workaround** : utiliser le tab **Custom** avec l'URL complète :

```
API URL : http://192.168.1.198:11434/v1/chat/completions
Model   : utmstack-analyst-test:latest
Auth    : None
```

> ⚠️ **Limitation CPU** : sans GPU, l'inférence LLM dépasse le timeout UTMStack même avec Llama 3.1 8B (~4 minutes en CPU-only). Un GPU est nécessaire pour utiliser Ollama local avec le SOC AI natif.

### 8.3 Mécanisme de création d'incidents

Le mécanisme "Auto-create incidents" est purement mécanique — aucune intelligence n'intervient dans le groupement. UTMStack regroupe **toutes les alertes d'une même datasource sur les 24 dernières heures** en un incident unique.

La description générée est un template fixe :

> *"AI GENERATED ANALYSIS: Multiple related alerts were detected and grouped in the [datasource] datasource during the last 24 hours. Artificial intelligence classified this grouping as a possible incident"*

Les alertes groupées apparaissent avec le statut **pending** dans l'incident — comportement normal en CE.

### 8.4 Mécanisme des Echoes

Les **Echoes** (compteur visible dans la liste des alertes) représentent le mécanisme anti-flood d'UTMStack. Quand la même règle de corrélation se déclenche plusieurs fois pour la même source dans une fenêtre temporelle, UTMStack :

1. Crée une **alerte principale** (première détection)
2. Groupe les occurrences suivantes comme **Echoes** de la première
3. Affiche le **compteur** sur l'alerte principale

Les Echoes sont visibles dans l'onglet dédié de chaque alerte avec leur timestamp et statut individuel.

### 8.5 Exemple d'analyse — Mistral Small

Résultat d'une analyse SOC AI sur une alerte Suricata avec Mistral Small (provider cloud) :

```
Classification: Possible false positive

Reasoning:
The Suricata alert signature 'HTTP Response excessive header repetition'
is typically triggered by non-malicious HTTP responses with unusual
header structures, often seen in legitimate traffic from CDNs or
software update services. The HTTP user agent 'Microsoft BITS/7.8' and
hostname 'msedge.b.tlu.dl.delivery.mp.microsoft.com' strongly indicate
this is a legitimate Windows Update or Microsoft Edge update request.

Next steps:
• Verify Legitimate Traffic
• Review Suricata Rule
• Monitor for Recurrence
```

> ℹ️ **Résumé pré-rempli** : la section "Summary" visible dans l'onglet Detail de chaque alerte n'est pas générée par le LLM — c'est le champ `rule_description` de la règle de corrélation, défini en base PostgreSQL. Ce texte est identique pour toutes les alertes déclenchées par la même règle.

> ⚠️ **Clé free Mistral** : le plan "Experiment" de Mistral AI entraîne sur les données par défaut. Ne jamais utiliser une clé free avec des données réelles de production. Utiliser le plan Scale (pay-as-you-go) pour la conformité nLPD/RGPD.

### 8.6 Comparaison SOC AI natif vs Pipeline n8n custom

| Critère | SOC AI natif UTMStack | Pipeline n8n (ch. 09) |
|---|---|---|
| Configuration | 5 minutes | Plusieurs heures |
| Contexte lab/topologie | Aucun | Enrichissement contextuel |
| Threat intel intégrée | Non | AbuseIPDB, GreyNoise, OTX, ThreatFox |
| Corrélation temporelle | Non | 30 jours |
| Qualité d'analyse | Générique | Contextualisée |
| GPU requis (Ollama) | Oui (timeout sinon) | Non (tri déterministe) |

Le SOC AI natif est un complément rapide pour les équipes sans ressources pour déployer un pipeline custom. Pour un lab avec Ollama local sans GPU, le pipeline n8n reste la solution recommandée.

---

## 9. Index OpenSearch — Structure des données

| Index | Source | DataType | Champs clés |
|---|---|---|---|
| `v11-log-wineventlog-*` | Agents Windows | `wineventlog` | `log.eventCode`, `log.providerName`, `log.computer` |
| `v11-log-suricata-*` | OPNsense/Suricata | `suricata` | `log.alert.signature`, `log.src_ip`, `log.dest_ip` |
| `v11-log-linux-*` | Agents Linux | `linux` | `log.message`, `dataSource` |
| `v11-log-utmstack-*` | Collecteur UTMStack | `utmstack` | `log.containerName`, `log.args.*` |
| `v11-log-o365-*` | Microsoft 365 | `o365` | `action`, `log.Workload`, `log.RecordType`, `origin.user` |
| `v11-log-azure-*` | Azure Event Hub | `azure` | `log.operationName`, `log.resultType`, `log.category` |
| `v11-log-generic-*` | Syslog générique | `generic` | `log.message`, `dataSource` |

**Champs communs à tous les index :**

| Champ | Description |
|---|---|
| `@timestamp` | Horodatage de l'event (UTC) |
| `deviceTime` | Horodatage de l'appareil source |
| `dataType` | Type de source (wineventlog, o365, azure...) |
| `dataSource` | Nom de la machine/source |
| `tenantId` | ID du tenant UTMStack |
| `origin.ip` | IP source de l'événement |
| `origin.user` | Utilisateur associé |
| `origin.geolocation` | Géolocalisation de l'IP source |
| `_hasOverflow` | `true` si l'event dépasse la limite d'affichage UI — artefact visuel, non stocké dans OpenSearch |

---

## Ressources

- [Bibliothèque de règles de corrélation (GitHub)](https://github.com/doit4everyone/utmstack-lab/tree/main/rules)
- [Chapitre 11 — Règles de corrélation custom](https://doit4everyone.github.io/utmstack-lab/docs/11-correlation-rules.html) *(à venir)*
- [Réduction du bruit — Tuning des règles natives](https://doit4everyone.github.io/utmstack-lab/docs/correlation-rules-tuning.html)
- [Chapitre 09 — Pipeline SOC augmenté par IA locale](https://doit4everyone.github.io/utmstack-lab/docs/09-pipeline-llm.html)

---

> [← Retour à l'index](../) | [→ Chapitre 11 — Règles de corrélation custom](11-correlation-rules.md)

*Procédures testées et validées sur UTMStack v11.2.12 CE — Infrastructure lab PME Suisse*

*Références et aide à la rédaction assistées par IA, avec validation humaine finale.*
