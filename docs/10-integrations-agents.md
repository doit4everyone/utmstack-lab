---
title: "Intégrations agents et sources de logs — UTMStack v11 | DoIt4Everyone"
description: "Guide complet des intégrations UTMStack v11 : agent Windows, agent Linux, collecteur UTMStack, Microsoft 365, Azure Event Hub, SOC AI natif. Sources de logs et architecture de collecte — les règles de corrélation custom sont documentées dans le chapitre 11."
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
   - [6.5 Gaps de détection vs licence](#65-gaps-de-détection-vs-licence)
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

Quatre règles custom ont été développées pour compléter la couverture native. Elles sont documentées en détail dans le **[Chapitre 11 — Règles de corrélation YAML personnalisées](11-correlations-yaml.md)** (série WD) et disponibles dans le [dépôt GitHub](https://github.com/doit4everyone/utmstack-lab/tree/main/rules/windows-defender).

**Philosophie de tuning appliquée :** approche défensive — la règle capture large, les faux positifs connus sont exclus chirurgicalement. Cette approche minimise le risque de rater une vraie menace, au prix d'un tuning itératif en production.

| Règle | Event | Série ch.11 | FP exclus documentés |
|---|---|---|---|
| windows-defender-tamper-protection.yml | 5013 | WD2 | Changed Type = Ignoré |
| windows-defender-realtime-disabled.yml | 5001 | WD3 | — |
| windows-defender-remediation-failed.yml | 1118 | WD4 | — |
| windows-defender-exclusion-added.yml | 5007 | WD5 | Sous-répertoire Diagnostics (WdConfigHash, UX Configuration, DLP Configs, EcsConfigs) |

**Procédure d'import :**

1. Dans UTMStack → **Threat Management** → **Correlation Rules** → **Import**
2. Sélectionner le fichier `.yml`
3. Redémarrer les event-processors — **obligatoire**, sans ce redémarrage la règle apparaît dans la liste mais ne déclenche pas :

```bash
docker service update --force utmstack_event-processor-worker
sleep 30
docker service update --force utmstack_event-processor-manager
```

> ℹ️ **Stabilité** : les règles importées via l'UI (`system_owner = false`) ne sont **pas** réinitialisées au redémarrage des conteneurs UTMStack — contrairement aux règles natives. Le redémarrage ci-dessus n'est nécessaire qu'une seule fois, au moment de l'import.

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

**Prérequis licence :** Entra ID P1 minimum (inclus dans Microsoft 365 Business Premium). Entra ID P2 ou Microsoft 365 E5 débloque les alertes MDE formelles avec `ThreatName`.

**App Registration Entra ID :**

1. portal.azure.com → **Entra ID** → **Inscriptions d'applications** → **Nouvelle inscription**
2. Permissions API requises :
   - `Office 365 Management APIs` → `ActivityFeed.Read`, `ActivityFeed.ReadDlp`, `ServiceHealth.Read`
   - `Microsoft Graph` → `SecurityEvents.Read.All`
3. Créer un secret client et noter : Tenant ID, Client ID, Client Secret

**Activation de l'audit Microsoft Purview :** Microsoft Purview → **Audit** → activer si non actif (délai de propagation ~24h).

### 6.2 Configuration dans UTMStack

**Integrations** → **Microsoft 365** → **Enabled** → renseigner Tenant ID, Client ID, Client Secret.

**Index créé :** `v11-log-o365-*`

> ⚠️ L'index est `v11-log-o365-*` et non `v11-log-office365-*` — important pour les requêtes OpenSearch et les règles de corrélation.

**Latence observée :** ~5 minutes entre l'événement réel et son apparition dans UTMStack. Ce délai est lié au polling de l'API O365 Management, pas à un problème de configuration.

### 6.3 Dashboards O365 prédéfinis

UTMStack inclut 5 dashboards O365 natifs accessibles depuis **Dashboards** → **Office 365** :

| Dashboard | Contenu |
|---|---|
| Office 365 Overview | Vue globale des activités O365 |
| Exchange Online | Activités email, règles inbox |
| SharePoint & OneDrive | Accès fichiers, partages |
| Entra ID Sign-ins | Connexions, échecs, géolocalisation |
| DLP Events | Correspondances politiques DLP |

### 6.4 Règles de corrélation O365 natives

UTMStack inclut 15 règles de corrélation natives pour les logs O365, couvrant les scénarios courants : activités suspectes Exchange, partages anonymes SharePoint, modifications de rôles Entra ID, etc.

> ℹ️ **Limitation CE** : avec Entra ID P1 et MDE Plan 1, les alertes MDE formelles (RecordType 41 avec `ThreatName`) ne sont pas disponibles. Seuls les events d'audit endpoint (RecordType 63, `Workload: Endpoint`) remontent dans UTMStack.

### 6.5 Gaps de détection vs licence

| Fonctionnalité | P1 / MDE Plan 1 | P2 / E5 |
|---|---|---|
| Logs audit O365 | ✅ | ✅ |
| Alertes MDE avec ThreatName | ❌ | ✅ |
| Identity Protection (risk scoring) | ❌ | ✅ |
| Impossible Travel natif Entra | ❌ | ✅ |
| Privileged Identity Management | ❌ | ✅ |

Les règles custom O365 développées dans ce lab comblent partiellement ces gaps pour les environnements P1 — documentées en détail dans le **[Chapitre 11 — Série M](11-correlations-yaml.md#série-m--microsoft-365-et-entra-id)** et disponibles sur [GitHub](https://github.com/doit4everyone/utmstack-lab/tree/main/rules/microsoft-365).

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
| `v11-log-sysmon-*` | Sysmon via WEF | `sysmon` | `log.data.Image`, `log.data.CommandLine`, `log.data.ParentImage` |
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
- [Chapitre 11 — Règles de corrélation YAML personnalisées](https://doit4everyone.github.io/utmstack-lab/docs/11-correlations-yaml.html)
- [Réduction du bruit — Tuning des règles natives](https://doit4everyone.github.io/utmstack-lab/docs/correlation-rules-tuning.html)
- [Chapitre 09 — Pipeline SOC augmenté par IA locale](https://doit4everyone.github.io/utmstack-lab/docs/09-pipeline-llm.html)

---

> [← Retour à l'index](../) | [→ Chapitre 11 — Règles de corrélation YAML personnalisées](11-correlations-yaml.md)

*Procédures testées et validées sur UTMStack v11.2.12 CE — Infrastructure lab PME Suisse*

*Références et aide à la rédaction assistées par IA, avec validation humaine finale.*
