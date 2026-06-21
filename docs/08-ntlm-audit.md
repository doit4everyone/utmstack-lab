---
title: "Audit NTLM & Migration Kerberos | DoIt4Everyone"
description: "Audit complet de l'authentification NTLM via UTMStack SIEM — WEF, GPO/Intune, dashboard, roadmap de migration NTLM → Kerberos selon la roadmap Microsoft."
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

# Audit NTLM & Migration Kerberos

> [← Retour à l'index](../)

> **Contexte Microsoft :** Microsoft désactivera NTLM par défaut dans la prochaine version majeure de Windows Server. La Phase 1 consiste à cartographier toutes les dépendances NTLM avant de les éliminer. Ce guide documente comment UTMStack couvre cette Phase 1, puis prépare les Phases 2 et 3.

---

## Pourquoi auditer NTLM maintenant ?

NTLM est un protocole d'authentification legacy datant de plus de 30 ans. Il est vulnérable aux attaques de type pass-the-hash, relay, et replay. Microsoft a annoncé une roadmap en 3 phases :

| Phase | Disponibilité | Contenu |
|---|---|---|
| **1 — Audit** | Disponible maintenant | Journalisation améliorée pour cartographier l'usage NTLM |
| **2 — Remédiation** | 2ème semestre 2026 | IAKerb + Local KDC pour éliminer les fallbacks NTLM |
| **3 — Désactivation** | Prochain Windows Server majeur | NTLM désactivé par défaut sur le réseau |

Références Microsoft :
- [Advancing Windows security: Disabling NTLM by default](https://techcommunity.microsoft.com/blog/windows-itpro-blog/advancing-windows-security-disabling-ntlm-by-default/4489526)
- [Vue d'ensemble des améliorations d'audit NTLM — Windows 11 24H2 / Server 2025](https://support.microsoft.com/fr-fr/topic/vue-d-ensemble-des-am%C3%A9liorations-apport%C3%A9es-%C3%A0-l-audit-ntlm-dans-windows-11-version-24h2-et-windows-server-2025-b7ead732-6fc5-46a3-a943-27a4571d9e7b)
- [Active Directory Hardening Series - Part 8 – Disabling NTLM](https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-8-%E2%80%93-disabling-ntlm/4485782)

---

## Phase 1 — Audit NTLM

### Event IDs couverts

#### Journaux Security (collectés nativement par l'agent UTMStack)

| Event ID | Source | Ce que ça couvre |
|---|---|---|
| **4624** | DC + machines membres | Ouverture de session NTLM réussie (`AuthenticationPackageName = NTLM`) |
| **4625** | DC + machines membres | Échec d'authentification NTLM |
| **4776** | DC uniquement | Validation credentials NTLM par le DC (passthrough) |
| **4648** | Toutes machines | Connexion avec credentials explicites (net use, runas) |
| **6038** | Serveurs | Détection NTLM par LsaSRV (1 par boot, 1ère utilisation) |

#### Journaux NTLM/Operational (Windows 11 24H2 / Server 2025 — nécessite WEF)

À activer via GPO : « Journalisation NTLM améliorée » (Modèles d'administration → Système → NTLM) et « Journaliser les journaux NTLM étendus à l'échelle du domaine » (Modèles d'administration → Système → Net Logon).

Chaque type d'événement existe en deux variantes : **Information** (NTLMv2 normal) et **Warning** (NTLMv1 ou dégradation de sécurité).

| Information | Warning | Rôle | Ce que ça couvre |
|---|---|---|---|
| **4020** | **4021** | Client | Auth NTLM sortante + Reason ID (0-11) expliquant le non-usage de Kerberos |
| **4022** | **4023** | Serveur | Réception d'une auth NTLM entrante |
| **4024** | **4025** | DC | Passthrough NTLM validé par le DC |

> Les anciens Event IDs 8001-8004 (Server 2022 et antérieurs) sont remplacés par 4020-4025 sur 24H2 / Server 2025, avec en plus le niveau Warning et le Reason ID côté client.

> ⚠️ L'agent UTMStack v11.2.8 CE ne collecte pas `Microsoft-Windows-NTLM/Operational` nativement. Il faut router ces événements vers `ForwardedEvents` via Windows Event Forwarding.

### Prérequis GPO — Activer l'audit NTLM

Deux familles de stratégies GPO permettent d'auditer NTLM, avec des objectifs distincts. Les deux doivent être activées pour une couverture complète.

#### Stratégies historiques — Génèrent les événements Security log (4624, 4625, 4776)

Disponibles depuis Windows Server 2008 R2. Elles se trouvent dans :
`Configuration ordinateur` → `Paramètres Windows` → `Paramètres de sécurité` → `Stratégies locales` → `Options de sécurité`

| Stratégie | Cible | Valeur recommandée |
|---|---|---|
| Sécurité réseau : Restreindre NTLM : Auditer l'authentification NTLM dans ce domaine | **DC uniquement** | Activer tout |
| Sécurité réseau : Restreindre NTLM : Auditer le trafic NTLM entrant | Tous ordinateurs (DC compris) | Activer l'audit pour tous les comptes |
| Sécurité réseau : Restreindre NTLM : Trafic NTLM sortant vers des serveurs distants | Tous ordinateurs (DC compris) | Auditer tout |

> **Important :** « Auditer l'authentification NTLM dans ce domaine » se configure **uniquement sur les DC** via une GPO liée à l'OU Domain Controllers (elle n'a aucun effet sur les autres machines). Les deux autres stratégies (trafic entrant et sortant) se configurent sur **tous les ordinateurs, DC compris** — via une GPO liée au domaine entier. Exclure les DC de ces deux stratégies ferait perdre la visibilité sur le trafic NTLM le plus critique (loopback RPC, passthrough).

#### Nouvelles stratégies 24H2 / Server 2025 — Génèrent les événements NTLM/Operational (4020-4025)

Introduites en juillet 2025 spécifiquement pour Windows 11 24H2 et Windows Server 2025. Elles répondent aux questions **Qui / Pourquoi / Où** que les anciennes stratégies ne permettaient pas d'auditer :

- **Qui** utilise NTLM (compte, processus, machine)
- **Pourquoi** NTLM a été choisi plutôt que Kerberos (Reason ID 0-11)
- **Où** l'authentification a lieu (nom et IP de la machine)

Elles incluent aussi un niveau d'avertissement spécifique pour détecter NTLMv1 et autres dégradations de sécurité.

| Stratégie | Localisation GPO | Cible | Couvre |
|---|---|---|---|
| **Journalisation NTLM améliorée** | `Modèles d'administration → Système → NTLM` | Clients + Serveurs | Events 4020-4023 |
| **Journaliser les journaux NTLM étendus à l'échelle du domaine** | `Modèles d'administration → Système → Net Logon` | DC uniquement | Events 4024-4025 |

> ⚠️ Ces deux stratégies ne sont **pas activées par défaut** — elles doivent être activées manuellement via GPO. Sans elles, le canal `Microsoft-Windows-NTLM/Operational` reste vide même sur Windows 11 24H2 / Server 2025.

#### Niveaux d'événements (nouvelles stratégies)

Chaque type d'événement NTLM est dédoublé en deux IDs selon le niveau de sécurité détecté :

| Niveau | ID Information | ID Warning | Signification |
|---|---|---|---|
| Client (sortant) | 4020 | 4021 | 4021 = NTLMv1 ou downgrade détecté |
| Serveur (entrant) | 4022 | 4023 | 4023 = NTLMv1 ou downgrade détecté |
| DC (domaine) | 4024 | 4025 | 4025 = NTLMv1 ou downgrade détecté |

Cibler `EventID >= 4021` permet de filtrer rapidement les cas critiques dans le SIEM.

#### Application des stratégies

Après configuration des deux familles de stratégies, forcer la mise à jour :

```cmd
gpupdate /force
```

### Déploiement WEF — Self-subscription locale

#### Architecture choisie

Un collecteur WEF **local par machine** — aucun trafic réseau inter-machines, aucun port WinRM ouvert entre DCs.

```
Microsoft-Windows-NTLM/Operational  (local)
              ↓  wecutil cs
         ForwardedEvents            (local)
              ↓  agent UTMStack
         UTMStack SIEM              (10.100.1.150)
```

#### Deux variantes de script selon le contexte de déploiement

| Variante | Cible | Source XML | Mode de déploiement |
|---|---|---|---|
| [`Deploy-WEF-NTLM-GPO.ps1`](https://github.com/doit4everyone/utmstack-lab/tree/main/scripts/Deploy-WEF-NTLM-GPO.ps1) | Machines jointes au domaine (DC, serveurs membres, postes) | SYSVOL (`\\lab.local\SYSVOL\...`) | GPO Script de démarrage |
| [`Deploy-WEF-NTLM-Intune.ps1`](https://github.com/doit4everyone/utmstack-lab/tree/main/scripts/Deploy-WEF-NTLM-Intune.ps1) | Endpoints Intune (AAD-joined, Hybrid) | XML embarqué Base64 | Intune Remediations |

Les deux variantes partagent le même comportement (idempotence, gestion ACL, configuration WinRM, agrandissement ForwardedEvents). Seule la source du XML diffère, ce qui permet à chaque variante de fonctionner dans son contexte sans dépendance externe.

#### Méthode 1 — Déploiement GPO (environnements AD on-prem)

**1. Placer les fichiers en SYSVOL**

> ⚠️ **Windows Server 2025 :** le chemin local `C:\Windows\SYSVOL\sysvol\<domaine>\` utilise un lien symbolique DFS qui peut apparaître vide dans l'explorateur ou via `dir`. Toujours utiliser le **chemin UNC** pour accéder au SYSVOL : `\\<domaine>\SYSVOL\<domaine>\scripts\`

```
\\lab.local\SYSVOL\lab.local\scripts\
├── Deploy-WEF-NTLM-GPO.ps1
└── ntlm-subscription.xml
```

**2. Créer une GPO ciblant l'ensemble du domaine**

Le script doit s'exécuter sur **toutes les machines** — DC, serveurs membres, et postes clients. Les Event IDs 4020-4023 (client/serveur) se génèrent sur n'importe quelle machine 24H2/Server 2025, y compris les postes de travail ; seuls 4024-4025 sont spécifiques au rôle DC.

Limiter le déploiement aux seuls serveurs ferait perdre la visibilité côté postes clients — c'est souvent là que se trouvent les cas les plus utiles pour la Phase 2 : applications métier qui forcent NTLM, accès par IP, vieux logiciels qui ne négocient pas Kerberos.

```
GPO Name : SEC - WEF NTLM Operational Logging (GPO)
Lien     : DC=lab,DC=local
           (racine du domaine, ou toute OU englobant DC + serveurs + postes clients ciblés)
```

> Si l'OU `Domain Controllers` est utilisée pour activer « Auditer l'authentification NTLM dans ce domaine » (stratégie spécifique aux DC, voir Phase 1), la GPO de **déploiement WEF** elle-même doit rester liée au niveau du domaine — sous peine de n'auditer qu'une partie du parc.

> **Sur un grand parc :** pousser WEF sur plusieurs centaines de postes d'un coup peut générer un volume d'événements significatif — chaque navigation SMB, chaque connexion imprimante réseau, chaque service legacy compte. Pour un déploiement en production, mieux vaut cibler une GPO par vagues successives (un groupe pilote, puis OU par OU) plutôt que lier directement au domaine entier, afin de valider le volume et l'impact sur `ForwardedEvents` avant généralisation. Pour un lab de quelques machines, cette précaution n'est pas nécessaire.

**3. Activer les services via GPO**

```
Configuration ordinateur → Stratégies → Paramètres Windows
→ Paramètres de sécurité → Services système
  → Collecteur d'événements de Windows : Automatique
  → Gestion à distance de Windows (Gestion WSM) : Automatique
```

**4. Configurer le Gestionnaire d'abonnements cible**

Cette étape est indispensable — sans elle, la souscription WEF existe mais aucune machine ne sait qu'elle doit y envoyer des événements. Dans une self-subscription locale, chaque machine s'envoie les événements à elle-même.

> ⚠️ `localhost` ne fonctionne pas comme cible — le forwarder WinRM exige un vrai nom résolvable. Utiliser le FQDN de la machine.

```
Configuration ordinateur → Stratégies → Modèles d'administration
→ Composants Windows → Transfert d'événements
→ Configurer le Gestionnaire d'abonnements cible : Activé
  Valeur : Server=http://<FQDN_MACHINE>:5985/wsman/SubscriptionManager/WEC
```

Le script de déploiement gère cette étape automatiquement via WMI (`$env:COMPUTERNAME` + `(Get-WmiObject Win32_ComputerSystem).Domain`), ce qui permet à une seule GPO de couvrir tout le parc sans FQDN fixe. La variable `$env:USERDNSDOMAIN` ne fonctionne pas au boot (vide sans session utilisateur).

**5. Déployer le script via Script de démarrage GPO**

Les scripts de démarrage sont plus fiables que les tâches planifiées GPO Preferences — ils tournent en tant que SYSTEM à chaque boot, sans configuration de compte ni problème de création.

```
Configuration ordinateur → Paramètres Windows
→ Scripts (démarrage/arrêt) → Démarrage
→ Onglet "Scripts PowerShell" → Ajouter
  Script : \\lab.local\SYSVOL\lab.local\scripts\Deploy-WEF-NTLM-GPO.ps1
  Ordre : Exécuter les scripts Windows PowerShell en dernier
```

> Le script intègre une boucle d'attente SYSVOL (jusqu'à 5 minutes) et construit le FQDN dynamiquement via WMI — il fonctionne au boot sans session utilisateur connectée.

#### Méthode 2 — Déploiement Intune (environnements cloud / hybrides)

Pour les endpoints gérés via Intune (AAD-joined ou Hybrid AAD-joined), GPO n'est pas applicable. Le déploiement passe par **Intune Remediations** (anciennement Proactive Remediations) qui supporte l'exécution récurrente sur planification, contrairement aux Platform Scripts qui ne s'exécutent qu'une fois.

> La variante Intune n'utilise pas SYSVOL — le XML est embarqué en Base64 directement dans le script. Cela permet le déploiement sur des machines AAD-joined sans aucune connexion AD on-prem.

**1. Créer une Remediation Intune**

```
Intune Admin Center
→ Devices → Windows → Scripts and Remediations
→ Remediations → Create
  Name             : WEF NTLM Operational Logging
  Detection script : Detect-WEF-NTLM.ps1
  Remediation      : Deploy-WEF-NTLM-Intune.ps1
  Run as           : System
  Run as 32-bit    : No
  Schedule         : Daily
```

**2. Stratégies NTLM via Settings Catalog**

```
Devices → Configuration → Create
→ Platform: Windows 10 and later
→ Profile type: Settings catalog
→ Category: Local Policies Security Options
  → Network Security Restrict NTLM Audit Incoming NTLM Traffic
  → Network Security Restrict NTLM Outgoing NTLM Traffic To Remote Servers
```

**3. Ciblage**

Utiliser un **Filter** Intune (plus rapide qu'un groupe dynamique) ciblant par exemple :
```
(device.deviceType -eq "Windows") and (device.osVersion -startsWith "10.0.26")
```
pour cibler uniquement Windows 11 24H2+ où le canal NTLM/Operational existe.

**4. Mise à jour du XML embarqué**

Si la souscription doit évoluer, encoder le nouveau XML en Base64 et remplacer la valeur de `$XmlBase64` dans le script :

```powershell
# Sur une machine Linux ou WSL
base64 -w 0 ntlm-subscription.xml

# Sur PowerShell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("ntlm-subscription.xml"))
```

### Vérification dans UTMStack

**Événements Security (disponibles immédiatement) :**

```
log.eventCode = 4624
log.eventDataAuthenticationPackageName = NTLM
```

**Événements NTLM/Operational (après déploiement WEF) :**

```
log.channel = ForwardedEvents
log.eventCode = 4021
```

### Dashboard NTLM — Widgets recommandés

| Widget | Type | Filtre | Objectif |
|---|---|---|---|
| Total NTLM | Metric | eventCode=4624 + AuthPkg=NTLM | Volume global |
| NTLMv1 détecté | Metric | LmPackageName=NTLM V1 | Criticité — à éliminer en priorité |
| Échecs NTLM | Metric | eventCode=4625 + AuthPkg=NTLM | Brute force / mauvaises configs |
| Top machines sources | Bar horizontal | Terms origin.host | Qui utilise NTLM |
| Top comptes | Bar horizontal | Terms target.user | Quels comptes |
| NTLMv1 vs NTLMv2 | Donut | Terms LmPackageName | Répartition versions |
| Timeline | Line | eventCode=4624 + AuthPkg=NTLM | Évolution dans le temps |
| Top IPs sources | Bar horizontal | Terms origin.ip | D'où vient le trafic NTLM |

### Observations en lab

Événements capturés sur DC01-MAIN-SITE (Windows Server 2025) après activation des GPO :

| Observation | Event ID | Reason ID | Niveau |
|---|---|---|---|
| `lsass` initie NTLM anonyme vers LDAP (target name manquant) | 4021 | 5 | ⚠️ NTLMv1 — à corriger |
| `backgroundTaskHost` appelle NTLM directement | 4021 | 1 | Dépendance applicative |
| `DC01-MAIN-SITE$` s'authentifie en NTLM via RPC vers DC01-RM | 4023 | 10 | Loopback RPC EPM — voir Phase 3 |
| PC admin (MDM-BLAISE-871) → SYSVOL via IP → NTLM v2 | 4022/4624 | 7 | Normal — accès par IP |

#### Référence — Reason ID côté client (événements 4020/4021)

Le Reason ID indique pourquoi NTLM a été utilisé plutôt que Kerberos. C'est l'information clé pour la remédiation Phase 2 :

| ID | Description | Action de remédiation |
|---|---|---|
| 0 | Raison inconnue | Investiguer le processus appelant |
| 1 | NTLM appelé directement par l'application | Contacter l'éditeur — fallback applicatif forcé |
| 2 | Authentification d'un compte local | Migrer vers un compte de domaine si possible |
| 3 | RÉSERVÉ — non utilisé | — |
| 4 | Authentification d'un compte cloud | Vérifier la configuration AAD/Entra |
| 5 | Nom de la cible manquant ou vide | Corriger la configuration — SPN ou cible mal définie |
| 6 | Nom cible non résolu par Kerberos | DNS ou SPN manquant |
| 7 | Nom cible contient une adresse IP | Remplacer IP par FQDN |
| 8 | Nom cible dupliqué dans Active Directory | `setspn -X` pour identifier le doublon |
| 9 | Aucune ligne de vue avec un DC | Problème réseau / firewall vers le DC |
| 10 | NTLM appelé via interface loopback | Loopback RPC — voir Phase 3 |
| 11 | NTLM appelé avec session null | Authentification anonyme — auditer le service |

---

## Cas d'étude terrain : le paradoxe de la réplication RPC inter-DC (Event 4021)

Lors de l'analyse des journaux `Microsoft-Windows-NTLM/Operational` sur un contrôleur de domaine Windows Server 2025, il est fréquent de voir apparaître des alertes de niveau **Warning** (Event ID 4021) générées par le processus `lsass` à destination d'un autre DC du parc.

### Payload SIEM observé (UTMStack)

| Champ | Valeur |
|---|---|
| Event ID | **4021** (Warning — client NTLM sortant) |
| Process | `lsass` (LSA Subsystem) |
| Username | `DC01$` (compte machine du contrôleur de domaine) |
| Target | `RPC/10.100.2.1` (DC distant, adressé par IP) |
| NtlmUsageId | **10** |
| NtlmUsageReason | `The target name contains an IP address.` |
| NtlmVersion | NTLMv2 |
| DNS | Forward et reverse DNS fonctionnels — le FQDN est résolvable |

### Explication architecturale

Ce comportement, bien que surprenant, est **normal et par design** dans toutes les versions de Windows, y compris Server 2025. Certaines fonctions internes de réplication Active Directory (KCC, topologie RPC) initient des appels inter-serveurs en passant une adresse IP brute comme argument au lieu d'un FQDN.

Kerberos étant structurellement incapable de générer un ticket de service (TGS) basé sur une adresse IP — le format `RPC/10.100.2.1` ne correspond à aucun SPN valide dans l'annuaire — la couche de sécurité SSPI Windows applique un comportement hérité : elle dégrade silencieusement le protocole et effectue un **fallback automatique vers NTLMv2**.

Ce comportement est confirmé par Microsoft :

> « By default Windows will not attempt Kerberos authentication for a host if the hostname is an IP address. It will fall back to other enabled authentication protocols like NTLM. » — [Microsoft Learn, Configuring Kerberos for IP Address](https://learn.microsoft.com/en-us/windows-server/security/kerberos/configuring-kerberos-over-ip)

### Pourquoi ce cas est critique pour la migration

- **Toute entreprise multi-sites** avec des DC dans des sites AD distincts est concernée
- Le DNS fonctionne parfaitement — ce n'est pas un problème de résolution
- Ce trafic NTLM était **totalement invisible** avant les Event IDs 4020-4025 introduits avec Server 2025 / Windows 11 24H2
- La désactivation brute de NTLM sans préparation **casserait la réplication AD**

### Impact pour la Phase 3 (Désactivation)

Ce cas démontre pourquoi la désactivation de NTLM est impossible sans l'introduction par Microsoft de **IAKerb** (Phase 2, prévu second semestre 2026). IAKerb permettra à Kerberos de fonctionner avec des cibles identifiées par IP. En attendant, ces flux RPC d'infrastructure intra-domaine doivent être explicitement identifiés et ajoutés à la liste des exceptions.

> ⚠️ À ce jour (juin 2026), aucune documentation officielle francophone ne documente ce cas précis. Les administrateurs qui activent les GPO d'audit NTLM et découvrent ces événements peuvent les confondre avec une attaque par relais NTLM, alors qu'il s'agit du bruit de fond normal de l'infrastructure AD.

---

## Phase 2 — Remédiation (préparation Kerberos)

> **Objectif :** réduire l'usage NTLM jusqu'à un minimum résiduel sans casser la production. Cette phase peut durer plusieurs mois selon la complexité de l'environnement.

### Étape 1 — Classification des usages détectés

Avant toute remédiation, chaque flux NTLM identifié dans le dashboard doit être classé :

| Catégorie | Exemple typique | Action |
|---|---|---|
| ✅ **Normal** | Accès SYSVOL via FQDN avec NTLMv2 sur compte machine | Documenter, surveiller |
| ⚠️ **Mauvaise configuration** | Service appelant LDAP sans SPN enregistré | Corriger via SPN |
| 🔴 **Legacy** | NTLMv1 détecté | Éliminer en priorité |
| 🚨 **Inconnu** | Application non identifiée déclenchant du NTLM | Investiguer en priorité |

### Étape 2 — Éliminer NTLM lié à l'accès par IP

**Cas observé en lab :** PC admin → `\\10.100.1.1\SYSVOL` → NTLM forcé car Kerberos nécessite un nom DNS.

Actions :
- Remplacer toutes les références par IP par des FQDN (`\\dc01-main-site.lab.local\SYSVOL`)
- Vérifier la résolution DNS forward et reverse sur l'ensemble du parc
- Auditer les scripts, GPO, tâches planifiées contenant des accès UNC par IP

### Étape 3 — Corriger Kerberos via SPN

**Cas observé en lab :** `lsass` → LDAP/DC01-MAIN-SITE → NTLMv1 avec « target name was missing or empty ».

Méthode de diagnostic :

```powershell
# Lister les SPN d'un compte (compte machine ou compte de service)
setspn -L <ServerName>
setspn -L <ServiceAccountName>

# Rechercher un SPN spécifique dans le domaine
setspn -Q LDAP/dc01-main-site.lab.local

# Détecter les SPN dupliqués (cause fréquente de fallback NTLM)
setspn -X
```

Ajout d'un SPN manquant :

```powershell
setspn -A LDAP/server.domain.local DOMAIN\service-account
```

> **Cas particulier confirmé en prod :** un environnement SQL Server avec NTLM verrouillé et SPN absents pour le compte de service SQL produit l'erreur « Login failed for untrusted domain ». Vérifier systématiquement les SPN avant tout verrouillage NTLM.

### Étape 4 — Éliminer NTLMv1 (priorité absolue)

NTLMv1 est obsolète depuis plus de 15 ans et déjà retiré de Windows 11 24H2 / Server 2025. Stratégie progressive :

```
Configuration ordinateur → Stratégies → Paramètres Windows
→ Paramètres de sécurité → Stratégies locales → Options de sécurité
  → Network security: LAN Manager authentication level
```

| Étape | Valeur | Effet |
|---|---|---|
| 1. Audit | Send LM & NTLM responses | Mesure de baseline |
| 2. Warning | Send NTLM response only | Refuse LM, accepte NTLMv1+v2 |
| 3. Enforcement | Send NTLMv2 response only. Refuse LM & NTLM | Refuse LM et NTLMv1 |

### Étape 5 — Identifier et corriger les comptes de service

Les comptes de service mal configurés sont l'une des causes majeures de fallback NTLM :

- Utiliser des **gMSA** (Group Managed Service Accounts) quand l'application le supporte
- Enregistrer les SPN appropriés
- Éviter le « Run as Local System » pour les services réseau
- Documenter les applications incompatibles gMSA pour traitement spécifique

### Étape 6 — Services et appliances legacy

Inventaire typique des sources NTLM résiduelles :
- ERP et applications métier anciennes
- Appliances réseau (imprimantes, NAS, scanners)
- Scripts PowerShell / batch utilisant des credentials explicites
- Outils de monitoring tiers
- Vieux clients RDP / SMB

Pour chaque source identifiée : mise à jour si possible, isolation réseau sinon, et documentation des exceptions à maintenir.

### Étape 7 — Liste d'exceptions NTLM

Avant tout blocage en Phase 3, configurer la **liste blanche** des serveurs auxquels les clients peuvent encore s'authentifier en NTLM. Sans cette liste, activer le blocage sortant fait échouer **toutes** les authentifications NTLM en cours.

```
Network security: Restrict NTLM: Add remote server exceptions for NTLM authentication
```

Format de la liste — noms NetBIOS, un par ligne, wildcard `*` autorisé :

```
legacyapp01
SQLSRV-*
NAS-MAIN
```

---

## Phase 3 — Désactivation NTLM

> **Règle absolue :** NE JAMAIS désactiver NTLM sans avoir complété la Phase 2. Le risque d'incident majeur (perte d'accès fichiers, authentification utilisateur, applications métier) est garanti sinon.

### Ordre Microsoft recommandé

Microsoft documente trois stratégies de blocage avec une granularité croissante. L'ordre de déploiement recommandé est :

| # | Stratégie | Cible | Effet |
|---|---|---|---|
| 1 | Trafic NTLM sortant vers des serveurs distants | Client | Bloque le NTLM sortant initié par cette machine |
| 2 | Trafic NTLM entrant | Serveur membre | Bloque le NTLM entrant reçu par cette machine |
| 3 | Authentification NTLM dans ce domaine | DC uniquement | Bloque le NTLM passthrough validé par le DC |

À chaque étape : passer d'abord par **Audit** complet, attendre une période d'observation suffisante (au minimum 2 semaines), corriger toutes les remontées, puis passer à **Deny**.

### Piège critique — RPC EPM loopback

**Cas directement observé en lab :** `DC01-MAIN-SITE$` s'authentifie en NTLM via RPC vers `DC01-RM`. Ce trafic est en réalité du **loopback RPC EPM** — la machine s'authentifie à elle-même via un compte machine, ou un DC s'authentifie à un autre DC pour des appels RPC qui devraient être en Kerberos.

#### Origine du problème

Le piège vient de deux politiques GPO datant de l'époque de Windows 95/NT qui forcent RPC à utiliser NTLM. Ces politiques ont été créées à cause d'une crainte d'exploit RPC qui ne s'est jamais matérialisée. Près de 30 ans plus tard, les baselines de hardening (CIS, STIG) recommandent encore de les activer.

Les deux politiques en question :

| Politique | Effet |
|---|---|
| **Enable RPC Endpoint Mapper Client Authentication** | Force les clients RPC à s'authentifier au mapper via NTLM |
| **Restrict Unauthenticated RPC clients** | Refuse les clients RPC non authentifiés |

Localisation dans la GPO :

```
Configuration ordinateur
 → Modèles d'administration
   → Système
     → Appels de procédure distante (RPC)
       → Enable RPC Endpoint Mapper Client Authentication
       → Restrict Unauthenticated RPC clients
```

Si l'une de ces politiques est active **et** qu'on active le blocage NTLM (sortant ou entrant), RPC ne peut plus négocier d'authentification → cascade d'erreurs sur le DC (perte de console MMC, erreurs de réplication, échecs d'accès aux services).

#### Procédure de correction (ordre obligatoire)

**Étape 1 — Vérifier l'état actuel sur les DC**

```powershell
# Vérifier les clés de registre correspondantes
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" `
                 -ErrorAction SilentlyContinue | 
  Select-Object EnableAuthEpResolution, RestrictRemoteClients
```

Toute valeur non nulle ou non existante indique que les politiques sont actives.

**Étape 2 — Désactiver les deux politiques**

Dans la GPO liée à l'OU Domain Controllers :

```
Enable RPC Endpoint Mapper Client Authentication → Disabled
Restrict Unauthenticated RPC clients → Disabled
```

Forcer la mise à jour :

```cmd
gpupdate /force
```

**Étape 3 — Redémarrer**

Les changements de ces deux paramètres nécessitent un reboot pour prendre effet. Programmer une fenêtre de maintenance pour chaque DC, un à la fois pour préserver la disponibilité AD.

**Étape 4 — Vérifier la disparition du loopback NTLM dans UTMStack**

Après reboot, surveiller pendant 24-48h dans le dashboard NTLM. Les événements 4023 / 8003 avec `Username: <ComputerName>$` doivent disparaître ou diminuer fortement.

**Étape 5 — Activer ensuite le blocage NTLM progressif**

Une fois les politiques RPC désactivées et le reboot effectué, suivre la procédure Phase 3 sans casser le loopback :

1. Outgoing NTLM → Audit puis Deny (avec liste d'exceptions)
2. Incoming NTLM → Audit puis Deny  
3. NTLM in domain → Audit puis Deny

#### Argumentaire face à un auditeur

Si CIS ou STIG sont obligatoires dans le contexte, la désactivation de ces politiques sera flaggée par les outils d'audit. Microsoft documente explicitement la position à tenir :

- Désactiver ces paramètres n'autorise **pas** l'accès anonyme aux services RPC, car chaque service RPC dispose de son propre security descriptor pour restreindre l'accès
- L'exploit RPC EPM redouté dans les années 90 ne s'est jamais matérialisé en production
- Microsoft recommande explicitement : *« If faced with a choice between restricting NTLM and using EnableAuthEpResolution, the recommended approach is that you restrict NTLM in your environment. »* (source : [Restrict NTLM Outgoing traffic — Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-outgoing-ntlm-traffic-to-remote-servers))

Documenter ce choix dans le registre des exceptions de sécurité avec la référence à la position Microsoft suffit généralement à satisfaire les auditeurs sérieux.

#### Alternative pour environnements à conformité stricte — IPsec

Pour les environnements où CIS/STIG sont strictement obligatoires sans dérogation, une approche alternative consiste à protéger RPC via IPsec :
- Exiger l'authentification IPsec sur TCP 135 entrant
- Limiter les ports RPC dynamiques à une plage connue (150 ports)
- Bloquer NTLM sortant en parallèle

Cette approche conserve la protection des ports RPC contre les scans tout en permettant la migration NTLM → Kerberos. Plus complexe à mettre en place, mais c'est la voie « zéro compromis » entre les deux contraintes.

### Tests obligatoires avant chaque passage en Deny

| Test | Méthode | Critère |
|---|---|---|
| Logon utilisateur interactif | Console Windows | Succès |
| Accès fichiers SMB | `net use \\fqdn\share` | Succès via Kerberos |
| Requêtes LDAP | `dsquery` ou Outlook | Succès via Kerberos |
| Applications métier | Test fonctionnel ciblé | Succès complet |
| Loopback RPC sur DC | `dcdiag /test:NetLogons` | Succès |
| Réplication AD | `repadmin /showrepl` | Succès |

### Configuration de blocage finale (exemple)

Une fois Phase 2 complète et tests validés :

```
Sécurité réseau : Restreindre NTLM : Trafic NTLM sortant vers des serveurs distants
  → Refuser tout (avec liste d'exceptions configurée)

Sécurité réseau : Restreindre NTLM : Trafic NTLM entrant
  → Refuser tous les comptes de domaine (autorise local accounts pour DR)

Sécurité réseau : Restreindre NTLM : Authentification NTLM dans ce domaine
  → Refuser pour les comptes de domaine aux serveurs de domaine
```

---

## Intégration SIEM — Indicateurs de migration

Le dashboard NTLM construit en Phase 1 devient l'outil de mesure du projet de migration.

### Règles d'alerte à activer en Phase 3

| Règle | Condition | Sévérité |
|---|---|---|
| NTLM détecté après Phase 2 | eventCode=4624 + AuthPkg=NTLM hors liste d'exceptions | Medium |
| NTLMv1 détecté | LmPackageName=NTLM V1 | High |
| Blocage NTLM déclenché | eventCode=4002 (server blocked) | Info |
| Échec auth multiple NTLM | eventCode=4625 + même target.user > 5 en 5 min | Medium |
| Auth NTLM directe sur DC | eventCode=4024/4025 hors compte machine | Medium |

### KPI de migration

À afficher dans un dashboard dédié « NTLM Migration Progress » :

- % d'authentifications NTLM vs Kerberos par jour
- Top 10 machines générant du NTLM (cible de remédiation)
- Top 10 applications/processus initiant du NTLM
- Évolution NTLMv1 dans le temps (objectif : 0)
- Nombre de SPN dupliqués détectés (`setspn -X`)
- Compte de comptes utilisant NTLM (objectif : décroissance continue)

**Objectif final mesuré :** NTLM résiduel < 1% du trafic d'authentification total.

---

## Positionnement architecte

La désactivation de NTLM n'est pas une simple modification technique. C'est un **projet de transformation du système d'information** qui nécessite :

- Une **visibilité complète** sur l'usage NTLM (Phase 1 — assurée par le SIEM)
- Une **remédiation progressive et documentée** des dépendances (Phase 2 — plusieurs mois)
- Une **validation rigoureuse** par tests fonctionnels avant chaque étape de blocage (Phase 3)
- Un **plan de rollback** à chaque étape — les stratégies GPO permettent un retour rapide en Allow All
- Une **communication aux équipes applicatives** car certains correctifs nécessitent l'implication des éditeurs

Le SIEM UTMStack joue un rôle central dans les trois phases : cartographie en Phase 1, mesure de progression en Phase 2, détection des violations résiduelles en Phase 3.

---

## Limitations connues

| Limitation | Impact | Contournement |
|---|---|---|
| Agent UTMStack v11.2.8 ne collecte pas NTLM/Operational nativement | Events 4021–4025 / 8001–8004 absents | WEF → ForwardedEvents |
| Canal NTLM/Operational disponible uniquement sur Win 11 24H2 / Server 2025 | Machines plus anciennes non couvertes | Couverture partielle via Security log (4624/4625/4776) |
| Canal ForwardedEvents désactivé par défaut sur Server 2025 | Souscription WEF active mais aucun événement reçu (erreur 3ae9) | `wevtutil sl ForwardedEvents /e:true` (intégré dans le script) |
| `localhost` ne fonctionne pas comme Subscription Manager | Forwarder WinRM refuse la connexion (erreur 2150859027) | Utiliser le FQDN dynamique via WMI `(Get-WmiObject Win32_ComputerSystem).Domain` |
| SYSVOL inaccessible par chemin local sur Server 2025 | Lien symbolique DFS apparaît vide | Toujours utiliser le chemin UNC `\\domaine\SYSVOL\...` |
| WEF nécessite WinRM actif localement | Surface d'attaque légèrement élargie | Self-subscription locale uniquement — pas d'exposition réseau inter-machines |
| Intune Remediations nécessite licence appropriée | Coût supplémentaire | Platform Scripts (exécution unique) si licence absente |
| Loopback RPC EPM casse avec blocage NTLM entrant sans préparation | Risque incident sur DC | Désactiver politiques RPC concernées avant blocage |

---

## Annexes — Fichiers de déploiement

Les scripts sont disponibles dans le repository du projet :
[github.com/doit4everyone/utmstack-lab/scripts](https://github.com/doit4everyone/utmstack-lab/tree/main/scripts)

| Fichier | Cible | Rôle |
|---|---|---|
| [`Deploy-WEF-NTLM-GPO.ps1`](https://github.com/doit4everyone/utmstack-lab/tree/main/scripts/Deploy-WEF-NTLM-GPO.ps1) | Machines domaine | Script idempotent, lit XML depuis SYSVOL |
| [`Deploy-WEF-NTLM-Intune.ps1`](https://github.com/doit4everyone/utmstack-lab/tree/main/scripts/Deploy-WEF-NTLM-Intune.ps1) | Endpoints Intune | Script idempotent, XML embarqué Base64 |
| [`Detect-WEF-NTLM.ps1`](https://github.com/doit4everyone/utmstack-lab/tree/main/scripts/Detect-WEF-NTLM.ps1) | Endpoints Intune | Script de détection pour Remediation |
| [`ntlm-subscription.xml`](https://github.com/doit4everyone/utmstack-lab/tree/main/scripts/ntlm-subscription.xml) | Source XML | Référence — embarqué dans le script Intune |

---

> ℹ️ *Testé sur Windows Server 2025, Windows 11 24H2, UTMStack v11.2.8, Intune (juin 2026)*

---

[← Custom Rules](07-custom-rules.md) | [Retour à l'index →](../)
