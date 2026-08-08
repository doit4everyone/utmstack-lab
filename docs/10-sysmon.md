---
title: "Sysmon — Déploiement et configuration | DoIt4Everyone"
description: "Déploiement de Sysmon v15.21 en environnement hybride AD + Intune — méthode registre ANSSI, deux configurations XML commentées (postes et DC), collecte via WEF vers ForwardedEvents."
---
<style>
  header, footer { display: none !important; }
  .wrapper { max-width: 900px !important; margin: 0 auto !important;
    float: none !important; position: relative !important;
    padding: 40px 20px !important;
    font-family: "Helvetica Neue", Helvetica, Arial, sans-serif !important;
    font-size: 1.1em !important; }
  section { width: 100% !important; float: none !important; margin: 0 !important; }
  h1, h2 { text-align: center; }
  table { width: 100%; display: table; margin: 20px 0; }
</style>

# Chapitre 10b — Sysmon : déploiement et configuration

Sysmon (System Monitor) est un driver Windows qui étend considérablement la télémétrie native des journaux d'événements. Là où Windows ne logue que l'ID de processus au démarrage, Sysmon capture la ligne de commande complète, le hash du binaire, le processus parent, les connexions réseau par processus, les accès LSASS, les modifications de clés de registre sensibles et les named pipes — autant de données indispensables pour une détection efficace des techniques d'attaque modernes.

Ce chapitre couvre le déploiement de Sysmon v15.21 dans un environnement hybride Active Directory et Intune, avec deux configurations distinctes selon la cible — postes membres et contrôleurs de domaine. La méthode de déploiement retenue protège le fichier de configuration contre la lecture par un attaquant en transit sur le réseau.

La collecte des événements Sysmon par UTMStack passe obligatoirement par le Windows Event Forwarding (WEF) — l'agent UTMStack ne collecte pas nativement le canal `Microsoft-Windows-Sysmon/Operational`. Ce chapitre couvre l'intégralité de la chaîne : déploiement Sysmon, configuration WEF, et vérification dans UTMStack.

**Téléchargement officiel :** [Sysmon — Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) — lien direct ZIP : `https://download.sysinternals.com/files/Sysmon.zip`

> Version utilisée dans ce lab : **v15.21** (juin 2026), schéma **4.91**. Vérifier la version avant de déployer — la valeur `schemaversion` dans les fichiers XML doit correspondre à la version installée. La commande `.\edgeIT.exe -? config` affiche le schéma supporté par le binaire.

---

## Table des matières

**Partie 1 — Déploiement Sysmon**

- [1. Architecture de la solution](#1-architecture-de-la-solution)
- [2. Event IDs retenus et justification](#2-event-ids-retenus-et-justification)
- [3. GPO d'audit avancé Windows](#3-gpo-daudit-avancé-windows)
- [4. Configurations XML Sysmon](#4-configurations-xml-sysmon)
- [5. Déploiement sur la machine de référence](#5-déploiement-sur-la-machine-de-référence)
- [6. Déploiement GPO — méthode registre ANSSI](#6-déploiement-gpo--méthode-registre-anssi)
- [7. Déploiement Intune — Win32 App](#7-déploiement-intune--win32-app)

**Partie 2 — WEF Sysmon → UTMStack**

- [8. Pourquoi le WEF est obligatoire](#8-pourquoi-le-wef-est-obligatoire)
- [9. Architecture WEF self-subscription locale](#9-architecture-wef-self-subscription-locale)
- [10. Déploiement WEF via GPO](#10-déploiement-wef-via-gpo)
- [11. Vérification dans UTMStack](#11-vérification-dans-utmstack)
- [12. Mise à jour de la configuration](#12-mise-à-jour-de-la-configuration)

---

## 1. Architecture de la solution

### Vue d'ensemble — trois couches

La collecte Sysmon dans UTMStack repose sur trois couches distinctes :

```
┌─────────────────────────────────────────────────────────────┐
│  Couche 1 — Sysmon driver                                   │
│  Surveille l'activité système et écrit dans                 │
│  Microsoft-Windows-Sysmon/Operational                       │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│  Couche 2 — WEF self-subscription locale                    │
│  Forwarde les events Sysmon vers ForwardedEvents            │
│  (même machine — self-subscription)                         │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│  Couche 3 — Agent UTMStack                                  │
│  Collecte ForwardedEvents et envoie vers UTMStack           │
│  (ForwardedEvents est dans la liste native de l'agent)      │
└─────────────────────────────────────────────────────────────┘
```

Le WEF est indispensable parce que l'agent UTMStack ne collecte pas `Microsoft-Windows-Sysmon/Operational` directement — voir section 8 pour l'explication complète.

### Pourquoi deux configurations distinctes

Les contrôleurs de domaine sont les cibles prioritaires de toute attaque sur un environnement Active Directory. DCSync, Golden Ticket, Pass-the-Hash, Kerberoasting — toutes ces techniques passent par ou visent le DC. Ne pas surveiller les DC avec Sysmon serait un angle mort majeur.

Cependant, la configuration Sysmon sur un DC doit être différente de celle d'un poste de travail. Les DC génèrent des milliers de connexions réseau légitimes par heure — réplication AD, Kerberos, LDAP, DNS — qui rendraient la surveillance réseau (EID 3) inexploitable. Les exclusions de processus sont également plus étendues pour couvrir ADWS, DFSR, DNS Server et Netlogon.

| Paramètre | sysmon-workstation.xml | sysmon-dc.xml |
|---|---|---|
| Cible | gest-srv, WIN11-AD-TESTS | DC01-MAIN-SITE, DC01-RM |
| EID 1 ProcessCreate | ✅ — exclusions standard | ✅ — exclusions AD DS étendues |
| EID 3 NetworkConnect | ✅ — processus suspects | ❌ — désactivé (volume AD) |
| EID 10 ProcessAccess | ✅ — accès LSASS | ✅ — **critique** (DCSync) |
| EID 11 FileCreate | ✅ — startup + temp | ✅ — NTDS + SYSVOL uniquement |
| EID 12/13 RegistryEvent | ✅ — Run keys | ✅ — Run keys + LSA packages |
| EID 16 SysmonConfig | ❌ — supprimé schéma 4.91 | ❌ — supprimé schéma 4.91 |
| EID 17/18 PipeEvent | ✅ — named pipes C2 | ✅ — + exclusions pipes AD |

### Obfuscation du binaire

Le binaire `Sysmon64.exe` est renommé en `edgeIT.exe` dans ce lab. Un attaquant qui liste les processus en cours (`tasklist`, `Get-Process`) ne voit pas immédiatement "Sysmon" — ce qui laisse du temps avant qu'il adapte ses techniques d'évasion.

Le driver conserve son nom `SysmonDrv` par défaut sur les deux méthodes de déploiement (GPO et Intune). Cette cohérence simplifie la gestion et la vérification.

---

## 2. Event IDs retenus et justification

| EID | Événement | Valeur | Activé |
|---|---|---|---|
| 1 | ProcessCreate | Ligne de commande, hash, parent — cœur de la détection LOLBIN | ✅ |
| 3 | NetworkConnect | Connexion réseau par processus — détection C2 | ✅ (poste) / ❌ (DC) |
| 10 | ProcessAccess | Accès LSASS — credential dumping, DCSync | ✅ |
| 11 | FileCreate | Dépôt dans startup folders, NTDS, SYSVOL | ✅ |
| 12/13 | RegistryEvent | Modification Run keys, LSA packages | ✅ |
| 16 | SysmonConfigState | Modification de la config Sysmon | ❌ — supprimé dans schéma 4.91 |
| 17/18 | PipeEvent | Named pipes — PsExec, Cobalt Strike | ✅ |
| 7 | ImageLoad | Chargement de DLL | ❌ — volume excessif |
| 8 | RemoteThread | Injection de thread | ❌ — FP navigateurs/runtimes |
| 22 | DNSEvent | Requêtes DNS | ❌ — volume AD excessif |

**EID 8 (RemoteThread) — pourquoi désactivé.** Les navigateurs modernes (Chrome, Edge) et les runtimes .NET créent légitimement des threads distants dans d'autres processus — ce qui génère un bruit considérable. La détection d'injection mémoire passe mieux par EID 10 (accès LSASS) pour les cas critiques.

**EID 22 (DNS) — pourquoi désactivé.** En environnement Active Directory, chaque opération génère des résolutions DNS — authentification Kerberos, réplication, LDAP, GPO. Activer EID 22 produit plusieurs milliers d'événements par heure sur un DC, sans valeur ajoutée significative face à EID 1 et EID 3 qui capturent déjà le contexte d'exécution.

---

## 3. GPO d'audit avancé Windows

Avant de déployer Sysmon et d'écrire des règles de corrélation, il faut s'assurer que Windows génère effectivement les événements attendus. Sans la politique d'audit avancé correctement configurée, les Event IDs 4624, 4740, 4769, 4698 ou 7045 n'apparaissent tout simplement pas dans le journal Security — et les règles YAML du chapitre 11 ne déclencheront jamais d'alerte.

<cite index="18-1">Un point critique souvent négligé : si la politique d'audit avancé est configurée dans une GPO mais que le paramètre "Audit: Force audit policy subcategory settings to override audit policy category settings" n'est pas activé, la politique de base (legacy) peut continuer à prendre le dessus sur les paramètres avancés.</cite> Ce paramètre doit être activé en priorité.

### Point de vigilance — politique de base vs politique avancée

Windows dispose de deux niveaux de configuration d'audit :

- **Politique de base** — Configuration ordinateur > Paramètres Windows > Paramètres de sécurité > Stratégies locales > Stratégie d'audit — 9 catégories grossières, paramètres conflictuels possibles
- **Politique avancée** — Configuration ordinateur > Paramètres Windows > Paramètres de sécurité > Configuration avancée de la stratégie d'audit — 53 sous-catégories précises, recommandée par l'ANSSI, CIS et Microsoft

<cite index="19-1">Pour vérifier ce qui est réellement appliqué sur un DC, la commande `auditpol /get /category:*` affiche la politique effective — pas ce que la GPO prétend appliquer. Il est fréquent que la catégorie "Audit logon events" soit configurée en Success et Failure dans la GPO, mais que `auditpol` n'affiche que Success à cause d'une politique locale qui prend le dessus sur un ancien DC.</cite>

### Paramètre préalable obligatoire

Dans la GPO d'audit, avant toute sous-catégorie :

```
Configuration ordinateur
└── Stratégies
    └── Paramètres Windows
        └── Paramètres de sécurité
            └── Stratégies locales
                └── Options de sécurité
                    └── Audit : forcer les paramètres de sous-catégorie de stratégie d'audit
                        (Windows Vista ou version ultérieure) à se substituer aux paramètres
                        de catégorie de stratégie d'audit → Activé
```

### Sous-catégories à activer — tableau complet

Le tableau ci-dessous liste les sous-catégories de la politique d'audit avancé, les Event IDs générés, et le niveau requis (Succès / Échec / Les deux) pour couvrir toutes les règles YAML du chapitre 11.

Chemin GPO pour chaque sous-catégorie :
`Configuration ordinateur > Stratégies > Paramètres Windows > Paramètres de sécurité > Configuration avancée de la stratégie d'audit > Stratégies d'audit`

| Catégorie | Sous-catégorie | S | E | Event IDs générés | Règles ch.11 |
|---|---|:---:|:---:|---|---|
| **Account Logon** | Credential Validation | ✅ | ✅ | 4776 | Pass-the-Hash |
| **Account Logon** | Kerberos Authentication Service | ✅ | ✅ | 4768 | Kerberoasting |
| **Account Logon** | Kerberos Service Ticket Operations | ✅ | ✅ | 4769, 4770 | W7 Kerberoasting RC4 |
| **Account Management** | Computer Account Management | ✅ | ✅ | 4741, 4742 | — |
| **Account Management** | Security Group Management | ✅ | ✅ | 4728, 4732, 4756 | W3 Privileged Group |
| **Account Management** | User Account Management | ✅ | ✅ | 4720, 4722, 4723, 4725, 4726, 4738, 4740 | W1 Lockout, W2 Admin créé |
| **Detailed Tracking** | Process Creation | ✅ | — | 4688 | LOLBIN (complémentaire Sysmon) |
| **DS Access** | Directory Service Changes | ✅ | — | 5136, 5137, 5139, 5141 | DCSync (via 4662) |
| **DS Access** | Directory Service Access | ✅ | ✅ | 4662 | DCSync detection |
| **Logon/Logoff** | Logon | ✅ | ✅ | 4624, 4625 | W6 Pass-the-Hash LogonType3 |
| **Logon/Logoff** | Account Lockout | ✅ | — | 4625 | W1 Lockout |
| **Logon/Logoff** | Special Logon | ✅ | — | 4672 | Comptes privilégiés |
| **Logon/Logoff** | Other Logon/Logoff Events | ✅ | ✅ | 4648 | Pass-the-Hash explicit creds |
| **Object Access** | Kernel Object | ✅ | ✅ | 4656, 4663 | Accès LSASS (complémentaire Sysmon EID10) |
| **Policy Change** | Audit Policy Change | ✅ | ✅ | 4719 | Modification politique d'audit |
| **Policy Change** | Authentication Policy Change | ✅ | — | 4706, 4713, 4716 | Changement politique Kerberos |
| **Privilege Use** | Sensitive Privilege Use | ✅ | ✅ | 4673, 4674 | — |
| **System** | Security System Extension | ✅ | ✅ | 7045 | W5 Service Installed |
| **System** | Security State Change | ✅ | ✅ | 4608, 4621 | — |
| **Task Scheduler** | Other Object Access Events | ✅ | ✅ | 4698, 4699, 4700, 4701, 4702 | W4 Scheduled Task |

**S** = Succès, **E** = Échec

### Paramètre complémentaire — ligne de commande dans 4688

Par défaut, l'Event 4688 (Process Creation) ne contient pas la ligne de commande du processus. Pour inclure la ligne de commande, il faut activer séparément : Modèles d'administration > Système > Audit de création de processus > Inclure la ligne de commande dans les événements de création de processus.

Avec Sysmon déployé, ce paramètre devient secondaire — Sysmon capture la ligne de commande bien plus complètement dans l'EID 1. Mais l'activer reste utile pour les machines sans Sysmon.

```
Configuration ordinateur
└── Stratégies
    └── Modèles d'administration
        └── Système
            └── Audit de création de processus
                └── Inclure la ligne de commande dans les événements de création de processus → Activé
```

### Taille des journaux de sécurité

<cite index="22-1">La taille maximale recommandée par Microsoft pour les journaux de sécurité sur les systèmes modernes est de 4 Go, avec un maximum total de 16 Go pour l'ensemble des journaux.</cite> Dans un environnement lab où UTMStack ingère les événements en continu, une taille plus modeste suffit — l'important est que les événements soient collectés avant que le tampon ne soit écrasé.

```
Configuration ordinateur
└── Stratégies
    └── Paramètres Windows
        └── Paramètres de sécurité
            └── Journal des événements
                ├── Taille maximale du journal Sécurité → 1 024 000 KB (1 GB) sur DC
                ├── Taille maximale du journal Sécurité → 256 000 KB (256 MB) sur postes
                └── Retention method for Security log → Overwrite events as needed
```

### Deux GPO distinctes — DC et postes membres

Exactement comme pour Sysmon, les politiques d'audit doivent être séparées :

- **GPO "Audit Avancé - Domain Controllers"** liée à l'OU Domain Controllers — inclut les sous-catégories DS Access et Directory Service Changes, critiques uniquement sur DC
- **GPO "Audit Avancé - Workstations"** liée à l'OU des postes et serveurs membres — sous-catégories standard sans DS Access

### Vérification de l'application effective

Après refresh GPO, vérifier que les paramètres sont bien appliqués :

```powershell
# Sur le DC ou le poste cible
gpupdate /force

# Vérifier la politique effective réellement appliquée
auditpol /get /category:*

# Exemple de sortie attendue pour Logon
#   Logon and Logoff
#     Logon                           Success and Failure
#     Logoff                          Success
#     Account Lockout                 Success
```

Si `auditpol` affiche "No Auditing" alors que la GPO est configurée, vérifier en priorité :
1. Le paramètre "Force subcategory settings" est-il activé ?
2. La GPO est-elle liée à la bonne OU ?
3. Y a-t-il un filtre WMI ou une liste de filtrage de sécurité qui exclut la machine ?

---

## 4. Configurations XML Sysmon

Les deux fichiers XML sont commentés section par section. Chaque règle précise la technique MITRE ATT&CK correspondante.

### Pourquoi le XML ne doit pas rester sur les postes

Un fichier de configuration Sysmon expose exactement ce qui est surveillé et ce qui ne l'est pas. Un attaquant disposant d'un accès en lecture à `C:\Windows\sysmon-config.xml` peut adapter ses techniques d'évasion en temps réel. La méthode registre ANSSI (section 4) élimine ce risque — Sysmon charge la configuration en registre en format binaire au moment de l'application, puis n'a plus besoin du fichier XML.

### Téléchargement

Les fichiers XML sont disponibles dans le dépôt GitHub du lab :

| Fichier | Cible | Lien |
|---|---|---|
| `sysmon-workstation.xml` | Postes membres, serveurs membres | [Télécharger](https://raw.githubusercontent.com/doit4everyone/utmstack-lab/main/configs/sysmon/sysmon-workstation.xml) |
| `sysmon-dc.xml` | Contrôleurs de domaine | [Télécharger](https://raw.githubusercontent.com/doit4everyone/utmstack-lab/main/configs/sysmon/sysmon-dc.xml) |

⚠️ Ces fichiers sont fournis à titre de référence pour comprendre les règles déployées. La procédure de déploiement (section 6) utilise la méthode registre ANSSI — le XML ne doit jamais rester sur les machines cibles en production.

### sysmon-workstation.xml — vue d'ensemble des règles clés

**EID 1 — ProcessCreate : LOLBIN**

Les "Living Off the Land Binaries" sont des exécutables Windows légitimes détournés pour exécuter du code malveillant. La liste couvre les suspects classiques : `certutil.exe`, `mshta.exe`, `wscript.exe`, `cscript.exe`, `regsvr32.exe`, `rundll32.exe` et une vingtaine d'autres. La règle capture également les patterns PowerShell suspects — commandes encodées (`-EncodedCommand`, `-enc`), download cradles (`DownloadString`, `WebClient`), contournements AMSI (`AmsiInitFailed`).

**EID 3 — NetworkConnect : processus qui ne devraient pas se connecter**

Cette règle capture les connexions réseau initiées par des processus qui n'ont normalement aucune raison de contacter Internet — `mshta.exe`, `wscript.exe`, `certutil.exe`, `regsvr32.exe`. Toute connexion réseau depuis ces binaires est un signal d'alerte fort. Les navigateurs et agents UTMStack sont exclus pour éviter le bruit.

**EID 10 — ProcessAccess : accès LSASS**

Le processus LSASS stocke les credentials des sessions Windows en mémoire. Tout accès à LSASS depuis un processus non système est suspect — c'est ainsi que fonctionnent Mimikatz, ProcDump ciblant LSASS, et la majorité des outils de credential dumping. Les exclusions couvrent les accès légitimes système (wininit, csrss, services, svchost) et Windows Defender.

**EID 12/13 — RegistryEvent : Run keys et persistance**

Les clés `HKLM\...\Run` et `HKCU\...\Run` sont le mécanisme de persistance le plus utilisé par les malwares. La règle surveille également `AppInit_DLLs` (injection de DLL), `Image File Execution Options` (détournement de processus) et les clés Winlogon. Les modifications par le système lui-même (services.exe, svchost.exe) sont exclues.

### sysmon-dc.xml — différences critiques

**EID 10 encore plus critique sur DC.** Un accès à LSASS sur un DC peut indiquer une tentative de DCSync — technique qui imite le protocole de réplication AD pour extraire les hash de tous les comptes, y compris krbtgt. Les exclusions sont étendues pour couvrir ADWS, DFSR et les autres composants AD DS qui accèdent légitimement à LSASS.

**Clés LSA supplémentaires en EID 12/13.** La modification de `LSA\Security Packages`, `LSA\Authentication Packages` ou `LSA\Notification Packages` permet à un attaquant d'installer un SSP (Security Support Provider) malveillant qui capture les credentials de tous les utilisateurs qui se connectent au DC. Ce vecteur — connu sous le nom de "LSA SSP injection" — est rarement surveillé.

**WDigest surveille sur DC.** La clé `WDigest\UseLogonCredential = 1` force Windows à conserver les mots de passe en clair en mémoire LSASS. Cette modification sur un DC est un signal d'alerte critique — elle permet à l'attaquant de récupérer les credentials en clair de tous les comptes qui se connectent.

---

## 5. Déploiement sur la machine de référence

Avant de créer les GPOs, Sysmon doit être appliqué sur une machine de référence pour générer les valeurs registre qui seront ensuite distribuées via GPP. Ce déploiement initial utilise le fichier XML directement — c'est la seule exception à la règle "pas de XML en production".

### Choix des machines de référence

| Config | Machine de référence | Justification |
|---|---|---|
| sysmon-workstation.xml | WIN11-AD-TESTS | Machine AD-only, représentative des postes membres |
| sysmon-dc.xml | DC01-MAIN-SITE | DC de production — appliquer en maintenance |

### Préparation sur WIN11-AD-TESTS

Télécharger Sysmon depuis le lien officiel et préparer les fichiers :

```powershell
# Créer un dossier de travail temporaire
New-Item -Path "C:\Temp\SysmonDeploy" -ItemType Directory -Force

# Placer dans ce dossier :
#   - Sysmon64.exe renommé en edgeIT.exe
#   - sysmon-workstation.xml
```

Les fichiers peuvent être copiés depuis le SYSVOL ou déposés manuellement pour ce déploiement de référence.

### Installation avec la configuration workstation

```powershell
# Depuis un terminal administrateur sur WIN11-AD-TESTS
cd C:\Temp\SysmonDeploy

# Installation avec la config XML
.\edgeIT.exe -accepteula -i sysmon-workstation.xml
```

La sortie attendue :

```
System Monitor v15.21 - System activity monitor
By Mark Russinovich and Thomas Garnier
Copyright (C) 2014-2026 Microsoft Corporation
Sysinternals - www.sysinternals.com

Loading configuration file with schema version 4.91
Sysmon schema version: 4.91
Configuration file validated.
Sysmon installed.
SysmonDrv installed.
Starting SysmonDrv.
SysmonDrv started.
Starting Sysmon.
Sysmon started.
```

⚠️ Si la sortie s'arrête après "Configuration file validated." sans afficher "Sysmon installed.", l'installation n'a pas eu lieu. Cause la plus fréquente : le terminal n'est pas exécuté en tant qu'administrateur. Relancer depuis un terminal **Administrateur** (clic droit → Exécuter en tant qu'administrateur).

### Vérification post-installation

```powershell
# Vérifier que le service driver est actif
Get-Service SysmonDrv | Select-Object Name, Status, StartType

# Vérifier que les 4 valeurs registre sont présentes
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters" |
    Select-Object DnsLookup, HashingAlgorithm, Options, Rules

# Vérifier que des événements sont générés dans le canal Sysmon
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 |
    Select-Object Id, TimeCreated, Message
```

La valeur `Rules` doit être présente et non vide — elle contient la configuration complète compilée en binaire. Si elle est absente, la configuration n'a pas été chargée correctement.

### Export des valeurs registre — étape critique

```powershell
# Export en fichier .reg pour alimenter la GPO
$regPath = "HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters"
reg export $regPath "C:\Temp\sysmon-workstation-params.reg" /y

# Vérifier le contenu — les 4 valeurs doivent être présentes
Get-Content "C:\Temp\sysmon-workstation-params.reg"
```

Le fichier `.reg` ressemble à ceci :

```
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters]
"DnsLookup"=dword:00000000
"HashingAlgorithm"=dword:00008003
"Options"=dword:00000010
"Rules"=hex:...données binaires de la configuration compilée...
```

**Conserver ce fichier** — il sera utilisé pour créer les éléments GPP Registre dans la section suivante.

### Suppression du XML

```powershell
# Le XML a été chargé en registre — il peut maintenant être supprimé
Remove-Item "C:\Temp\SysmonDeploy\sysmon-workstation.xml" -Force

# Archiver le XML dans le repo privé (jamais sur GitHub public)
# Sysmon continue de fonctionner exclusivement depuis le registre
```

### Répéter pour la config DC

Même procédure sur DC01-MAIN-SITE avec `sysmon-dc.xml`, de préférence pendant une fenêtre de maintenance :

```powershell
.\edgeIT.exe -accepteula -i sysmon-dc.xml
reg export "HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters" `
    "C:\Temp\sysmon-dc-params.reg" /y

# Supprimer le XML — adapter le chemin selon l'emplacement utilisé
Remove-Item "C:\Temp\SysmonDeploy\sysmon-dc.xml" -Force

# Vérifier qu'aucun XML ne reste accessible sur le DC
Get-ChildItem "C:\Temp\SysmonDeploy\" | Where-Object { $_.Extension -eq ".xml" }
```

---

## 6. Déploiement GPO — méthode registre ANSSI

Cette méthode, recommandée par l'ANSSI dans son guide de journalisation Windows, garantit qu'aucun fichier XML de configuration n'est présent sur les postes en production.

### Principe de fonctionnement

Sysmon lit le fichier XML **une seule fois** pour convertir la configuration en format binaire et la stocker dans le registre sous `HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters`. Une fois cette conversion effectuée, le XML peut être supprimé — Sysmon n'a plus besoin de lui et travaille exclusivement depuis le registre.

Les quatre valeurs créées sont : `DnsLookup`, `HashingAlgorithm`, `Options` et `Rules`.

### Étape 1 — Générer la configuration sur une machine de référence

Appliquer chaque XML sur une machine dédiée (pas une machine de production) :

```powershell
# Pour la config workstation — appliquer sur gest-srv ou WIN11-AD-TESTS
edgeIT.exe -accepteula -i sysmon-workstation.xml

# Pour la config DC — appliquer sur DC01-MAIN-SITE
edgeIT.exe -accepteula -i sysmon-dc.xml
```

Après application, le XML peut être archivé hors ligne. Il n'a plus aucun rôle sur la machine.

### Étape 2 — Exporter les valeurs registre

```powershell
# Export des 4 valeurs SysmonDrv\Parameters en fichier .reg
$regPath = "HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters"
reg export $regPath "C:\Temp\sysmon-workstation-params.reg" /y

# Vérification — les 4 valeurs attendues
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters"
```

Les valeurs `DnsLookup`, `HashingAlgorithm`, `Options` et `Rules` doivent toutes être présentes. La valeur `Rules` contient la configuration complète en format binaire.

### Étape 3 — Créer le filtre WMI d'exclusion des DC

Les machines du domaine sont réparties dans des OUs différentes. Plutôt que de gérer des liens GPO par OU, les deux GPOs Sysmon sont liées au **domaine racine** et un filtre WMI exclut automatiquement les contrôleurs de domaine. Cette approche couvre tous les postes membres, serveurs membres et hôtes Hyper-V sans configuration supplémentaire.

La propriété `DomainRole` de WMI identifie le rôle de la machine :

| DomainRole | Rôle |
|---|---|
| 0 | Standalone Workstation |
| 1 | Member Workstation |
| 2 | Standalone Server |
| 3 | Member Server (Hyper-V, serveurs fichiers…) |
| 4 | Backup Domain Controller |
| 5 | Primary Domain Controller |

La requête `DomainRole < 4` cible tout sauf les DC — postes, serveurs membres, hôtes Hyper-V en cluster inclus.

Dans la GPMC :

1. Clic droit sur **Filtres WMI** → **Nouveau**
2. Nom : `Exclure Domain Controllers`
3. Description : `Applique la GPO a tous les membres du domaine sauf les DC (DomainRole < 4)`
4. Cliquer **Ajouter** :
   - Espace de noms : `root\CIMv2`
   - Requête : `SELECT * FROM Win32_ComputerSystem WHERE DomainRole < 4`
5. **Enregistrer**

### Étape 4 — Créer la GPO d'installation

Placer les fichiers dans le SYSVOL — accessible par toutes les machines du domaine :

```
\\lab.local\SYSVOL\lab.local\Sysmon\
├── edgeIT.exe
└── Deploy-Sysmon.ps1
```

Dans la GPMC :

1. Clic droit sur le **domaine racine** → **Créer un objet GPO dans ce domaine, et le lier ici**
2. Nom : `Sysmon - Install`
3. Clic droit sur la GPO → **Modifier**
4. `Configuration ordinateur > Stratégies > Paramètres Windows > Scripts (démarrage/arrêt) > Démarrage`
5. Onglet **Scripts PowerShell** → **Ajouter**
   - Nom du script : `\\lab.local\SYSVOL\lab.local\Sysmon\Deploy-Sysmon.ps1`
   - Paramètres du script : (vide)
6. OK → OK
7. Fermer l'éditeur → retour dans GPMC
8. Onglet **Étendue** de la GPO → **Filtrage WMI** → sélectionner `Exclure Domain Controllers`

### Étape 5 — Créer la GPO de configuration (GPP Registre)

Cette GPO pousse les quatre valeurs registre sur toutes les machines cibles, sans fichier XML en transit.

Dans la GPMC :

1. Clic droit sur le **domaine racine** → **Créer un objet GPO dans ce domaine, et le lier ici**
2. Nom : `Sysmon - Config Workstations`
3. Clic droit → **Modifier**
4. `Configuration ordinateur > Préférences > Paramètres Windows > Registre`
5. Clic droit → **Nouveau** → **Assistant Registre**
6. Sélectionner **Un autre ordinateur** → entrer `WIN11-AD-TESTS` (la machine de référence)
7. Naviguer vers : `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters`
8. Cocher les 4 valeurs : `DnsLookup`, `HashingAlgorithm`, `Options`, `Rules`
9. **Suivant** → **Terminer**

Les 4 éléments apparaissent dans la liste. Vérifier que `Rules` est bien de type `REG_BINARY` — c'est la valeur qui contient toute la configuration compilée. Changer l'action de chaque valeur de **Mettre à jour** → **Remplacer** pour garantir l'application même si les valeurs sont absentes.

10. Fermer l'éditeur → onglet **Étendue** → **Filtrage WMI** → sélectionner `Exclure Domain Controllers`

> **Alternative si l'Assistant Registre ne peut pas atteindre WIN11-AD-TESTS** : utiliser le fichier `sysmon-workstation-params.reg` exporté précédemment. Copier ce fichier sur le DC, puis dans l'Assistant Registre sélectionner **Ordinateur local** après avoir importé le `.reg` localement via `reg import` — ou saisir les valeurs manuellement depuis le contenu du `.reg`.

### Vérification du déploiement

```powershell
# Forcer le refresh GPO sur un poste cible
gpupdate /force

# Vérifier que le driver est actif
Get-Service SysmonDrv | Select-Object Name, Status, StartType

# Vérifier la présence des 4 valeurs Parameters
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters"

# Vérifier que des événements sont générés
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 |
    Select-Object Id, TimeCreated
```

### GPO DC — déploiement séparé

Les DC utilisent une configuration distincte (`sysmon-dc.xml`) exportée depuis DC01-MAIN-SITE. La procédure est identique mais sans filtre WMI — les GPOs sont liées directement à l'**OU Domain Controllers**.

**GPO `Sysmon - Install DC`**

1. Clic droit sur l'**OU Domain Controllers** → **Créer un objet GPO dans ce domaine, et le lier ici**
2. Nom : `Sysmon - Install DC`
3. Clic droit → **Modifier**
4. `Configuration ordinateur > Stratégies > Paramètres Windows > Scripts (démarrage/arrêt) > Démarrage`
5. Onglet **Scripts PowerShell** → **Ajouter** → même script `Deploy-Sysmon.ps1`
6. Pas de filtre WMI — la liaison à l'OU Domain Controllers suffit

**GPO `Sysmon - Config DC`**

1. Clic droit sur l'**OU Domain Controllers** → **Créer un objet GPO dans ce domaine, et le lier ici**
2. Nom : `Sysmon - Config DC`
3. Clic droit → **Modifier**
4. `Configuration ordinateur > Préférences > Paramètres Windows > Registre`
5. Clic droit → **Nouveau** → **Assistant Registre** → **Ordinateur local** (DC01-MAIN-SITE)
6. Naviguer vers `HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters`
7. Cocher les valeurs présentes : `DnsLookup`, `HashingAlgorithm`, `Rules`
8. **Suivant** → **Terminer**
9. Changer l'action de chaque valeur → **Remplacer**

---

## 7. Déploiement Intune — Win32 App

Le déploiement Intune cible uniquement MDM-BLAISE-871 dans ce lab. La méthode diffère de GPO car Intune dépose les fichiers du package dans `C:\Windows\IMECache` avant l'installation, ce qui expose temporairement le XML. La commande d'installation supprime ce dossier immédiatement après.

### Structure du package

```
SYSMON_edgeIT\
├── edgeIT.exe          ← Sysmon64.exe renommé
└── sysmonconfig.xml    ← Config XML — supprimée après installation
```

Le package est converti en `.intunewin` avec l'outil Microsoft Win32 Content Prep Tool.

### Configuration dans Intune

| Paramètre | Valeur |
|---|---|
| Nom | SYSMON_edgeIT.exe |
| Comportement à l'installation | Système |
| Comportement de redémarrage | Aucune action spécifique |

**Commande d'installation :**

```cmd
cmd.exe /c "edgeIT.exe -accepteula -i sysmonconfig.xml && powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"Remove-Item -Path 'C:\Windows\IMECache' -Recurse -Force -ErrorAction SilentlyContinue\""
```

Le `&&` garantit que la suppression du XML ne s'effectue qu'après une installation réussie. `ErrorAction SilentlyContinue` évite un code retour non-zéro si le dossier est déjà vide ou absent.

**Commande de désinstallation :**

```cmd
edgeIT.exe -u force
```

**Règle de détection :** Registre — `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters` — existence de la clé.

Cette clé n'est créée que si l'installation a réussi et que la configuration a été chargée correctement — c'est une détection fiable qui ne peut pas être satisfaite par la simple présence du binaire.

---

---

## 8. Pourquoi le WEF est obligatoire

### Limite de l'agent UTMStack

L'agent UTMStack v11.2.12 CE ne collecte pas nativement le canal `Microsoft-Windows-Sysmon/Operational`. La liste des canaux collectés est codée en dur dans le binaire de l'agent — elle inclut `Security`, `System`, `Application`, `Windows PowerShell`, `Microsoft-Windows-PowerShell/Operational`, `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall`, `Microsoft-Windows-Windows Defender/Operational`, et `ForwardedEvents`, mais pas Sysmon.

Cette limitation a été confirmée par analyse du binaire `utmstack_agent_service_windows_amd64.exe` :

```bash
# Depuis l'hôte UTMStack
docker cp $(docker ps -q -f name=utmstack_agentmanager):/dependencies/agent/utmstack_agent_service_windows_amd64.exe /tmp/
cat /tmp/utmstack_agent_service_windows_amd64.exe | \
  grep -oa 'ForwardedEvents\|Microsoft-Windows-Sysmon[^[:space:]]*' | sort -u
# Résultat : ForwardedEvents présent — Microsoft-Windows-Sysmon/Operational absent
```

Un ticket a été ouvert auprès d'UTMStack pour demander l'ajout natif de ce canal ou un mécanisme de configuration des canaux collectés : [GitHub issue #2446](https://github.com/utmstack/UTMStack/issues/2446).

### La solution : WEF self-subscription locale

`ForwardedEvents` **est** collecté nativement par l'agent. Le WEF permet à chaque machine de forwarder ses propres events Sysmon vers son propre canal `ForwardedEvents` — sans collecteur central, sans exposition réseau entre machines. L'agent UTMStack collecte ensuite `ForwardedEvents` normalement.

Les events arrivent dans UTMStack en conservant leurs métadonnées d'origine :
- `log.providerName` : `Microsoft-Windows-Sysmon`
- `log.channel` : `Microsoft-Windows-Sysmon/Operational`
- `dataSource` : nom de la machine source

### Périmètre de fonctionnement

Le WEF self-subscription locale a été validé sur :

| Machine | OS | Statut |
|---|---|---|
| gest-srv | Windows Server 2022 | ✅ Fonctionnel |
| DC01-MAIN-SITE | Windows Server 2025 | ✅ Fonctionnel |
| DC01-RM | Windows Server 2025 | ✅ Fonctionnel |
| WIN11-AD-TESTS | Windows 11 24H2 | ❌ Non fonctionnel |
| MDM-BLAISE-871 | Windows 11 24H2 (Intune) | ❌ Non fonctionnel |

Sur Windows 11, le service `Wecsvc` ne parvient pas à s'enregistrer comme source auprès de son propre Subscription Manager local — erreur `2150859027` (`/SubscriptionManager/WEC` non exposé sur les SKUs client). Ce comportement a été reproduit sur deux postes Win11 distincts après diagnostic exhaustif (DNS, pare-feu, URL ACL WinRM, `SvcHostSplitDisable`, dépréciation VBScript). Il s'agit d'une limitation de conception de Windows 11, pas d'un problème de configuration.

Pour les postes Windows 11, Sysmon reste déployé et actif — les events sont présents dans le canal local `Microsoft-Windows-Sysmon/Operational` mais ne remontent pas dans UTMStack faute de WEF fonctionnel.

---

## 9. Architecture WEF self-subscription locale

### Principe

Chaque machine gère sa propre subscription WEF en mode `SourceInitiated`. Elle se déclare elle-même comme source et comme collecteur — d'où le terme "self-subscription". Les events Sysmon sont forwarded vers le canal `ForwardedEvents` local, que l'agent UTMStack collecte ensuite.

Ce mode ne nécessite aucun collecteur WEF central dédié, aucune ouverture réseau entre machines, et aucune modification de l'architecture existante.

### Prérequis sur chaque machine cible

Pour que la self-subscription fonctionne, plusieurs conditions doivent être réunies :

**WinRM et Wecsvc actifs** — WinRM écoute sur le port 5985, `Wecsvc` démarre automatiquement.

**ACL sur le canal Sysmon** — Le canal `Microsoft-Windows-Sysmon/Operational` utilise l'isolation `Custom`, ce qui signifie que seuls les processus explicitement autorisés peuvent le lire. `Network Service` (le compte sous lequel tourne `Wecsvc`) doit avoir le droit de lecture sur ce canal.

**Network Service dans Event Log Readers** — En complément de l'ACL canal, `Network Service` doit appartenir au groupe local `Lecteurs du journal d'événements`. Ce groupe est requis pour accéder aux canaux en isolation Custom.

**URL ACL WinRM correctes** — Les URL ACL HTTP.sys doivent autoriser explicitement les SID des services `WinRM` et `Wecsvc`. Sur certaines machines, ces ACL peuvent être corrompues ou incomplètes, ce qui bloque silencieusement l'enregistrement de la source. C'est la cause racine la plus fréquente du problème "0 ordinateur" dans la subscription.

**Canal ForwardedEvents activé** — Désactivé par défaut sur les serveurs membres et les DC, il doit être activé et dimensionné (500 MB recommandé dans ce lab).

**Canal Microsoft-Windows-Forwarding/Operational activé** — Indispensable pour que le service de forwarding puisse journaliser ses propres opérations.

**Reboot obligatoire** — Après la première configuration complète, un redémarrage est nécessaire pour que `Network Service` hérite effectivement des droits du groupe `Event Log Readers`. Sans ce reboot, la source ne s'enregistre pas même si toutes les autres conditions sont réunies.

### Fichier de subscription

Le fichier `sysmon-wef-subscription.xml` définit la subscription déployée sur chaque machine. Il est disponible dans le dépôt GitHub du lab : [Télécharger sysmon-wef-subscription.xml](https://raw.githubusercontent.com/doit4everyone/utmstack-lab/main/configs/sysmon/sysmon-wef-subscription.xml)

```xml
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
  <SubscriptionId>Sysmon-Operational</SubscriptionId>
  <SubscriptionType>SourceInitiated</SubscriptionType>
  <Description>Forward Sysmon Operational events to ForwardedEvents (self-subscription locale)</Description>
  <Enabled>true</Enabled>
  <Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri>
  <ConfigurationMode>MinLatency</ConfigurationMode>
  <Delivery Mode="Push">
    <Batching>
      <MaxLatencyTime>30000</MaxLatencyTime>
    </Batching>
    <PushSettings>
      <Heartbeat Interval="3600000"/>
    </PushSettings>
  </Delivery>
  <Query>
    <![CDATA[
      <QueryList>
        <Query Id="0">
          <Select Path="Microsoft-Windows-Sysmon/Operational">*</Select>
        </Query>
      </QueryList>
    ]]>
  </Query>
  <ReadExistingEvents>false</ReadExistingEvents>
  <TransportName>HTTP</TransportName>
  <ContentFormat>Events</ContentFormat>
  <Locale Language="fr-FR"/>
  <LogFile>ForwardedEvents</LogFile>
  <AllowedSourceDomainComputers>O:NSG:NSD:(A;;GA;;;DC)(A;;GA;;;NS)(A;;GA;;;DD)</AllowedSourceDomainComputers>
</Subscription>
```

Points critiques de ce fichier :

`ContentFormat: Events` est obligatoire. Le mode `RenderedText` échoue silencieusement sur les canaux en isolation Custom comme Sysmon — les events sont forwarded mais arrivent vides ou malformés.

`ConfigurationMode: MinLatency` garantit une latence de forwarding de 30 secondes maximum, adapté à un usage SOC.

`AllowedSourceDomainComputers` contient le SDDL qui autorise les Domain Computers (`DC`), Network Service (`NS`) et Domain Admins (`DD`) — les trois identités nécessaires pour la self-subscription sur des machines membres du domaine.

---

## 10. Déploiement WEF via GPO

### Script de déploiement

Le script `Deploy-WEF-Sysmon-GPO.ps1` est déposé dans le SYSVOL et exécuté via GPO au démarrage de chaque machine. Il est idempotent — il vérifie si la subscription existe déjà et si la source est enregistrée avant d'agir.

```
\\lab.local\SYSVOL\lab.local\scripts\
├── Deploy-WEF-Sysmon-GPO.ps1
└── sysmon-wef-subscription.xml
```

Le script effectue dans l'ordre :

1. Vérification que `SysmonDrv` est installé — si absent, abandon propre (inutile de configurer WEF sans Sysmon)
2. Attente SYSVOL accessible (jusqu'à 300 secondes)
3. Idempotence — si la subscription existe et a une source active, sortie immédiate
4. `Set-WSManQuickConfig` et `Enable-PSRemoting` — configuration WinRM sans passer par VBScript (sur Windows 11 24H2, `winrm quickconfig` passe par `winrm.vbs` via `cscript.exe`, dont le comportement est modifié par la dépréciation de VBScript)
5. Activation de `Wecsvc` en démarrage automatique
6. ACL sur le canal `Microsoft-Windows-Sysmon/Operational` — droit de lecture pour `Network Service`
7. Ajout de `Network Service` au groupe `Lecteurs du journal d'événements` (détection bilingue FR/EN)
8. Activation du canal `Microsoft-Windows-Forwarding/Operational`
9. Activation et dimensionnement de `ForwardedEvents` (500 MB)
10. Correction des URL ACL WinRM — étape critique :

```powershell
$sddl = "D:(A;;GX;;;S-1-5-80-569256582-2953403351-2909559716-1301513147-412116970)(A;;GX;;;S-1-5-80-4059739203-877974739-1245631912-527174227-2996563517)"
cmd.exe /c "netsh http delete urlacl url=http://+:5985/wsman/"
cmd.exe /c "netsh http add urlacl url=http://+:5985/wsman/ sddl=$sddl"
```

Cette étape corrige les URL ACL HTTP.sys qui peuvent être incomplètes ou corrompues. Sans elle, `Wecsvc` ne peut pas s'enregistrer comme source même si toutes les autres conditions sont réunies — c'est la cause racine du problème "0 ordinateur" observé en lab.

11. Configuration du Subscription Manager en registre — FQDN construit dynamiquement :

```powershell
$domain    = (Get-WmiObject Win32_ComputerSystem).Domain
$MachineFQDN = "$env:COMPUTERNAME.$domain"
$smKey   = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager"
$smValue = "Server=http://${MachineFQDN}:5985/wsman/SubscriptionManager/WEC"
Set-ItemProperty -Path $smKey -Name "1" -Value $smValue -Type String
```

Le FQDN est construit via WMI et non via `$env:USERDNSDOMAIN` — cette variable d'environnement est vide au démarrage en l'absence de session utilisateur.

12. Redémarrage de WinRM et Wecsvc
13. Création de la subscription via `wecutil cs`
14. Vérification finale du statut

### GPO de déploiement

La GPO `Sysmon - WEF Operational` est liée au domaine racine sans filtre WMI. Le script se charge lui-même de vérifier la présence de `SysmonDrv` — si Sysmon n'est pas installé, il sort proprement sans erreur.

Dans la GPMC :

1. Clic droit sur le **domaine racine** → **Créer un objet GPO dans ce domaine, et le lier ici**
2. Nom : `Sysmon - WEF Operational`
3. Clic droit → **Modifier**
4. `Configuration ordinateur > Stratégies > Paramètres Windows > Scripts (démarrage/arrêt) > Démarrage`
5. Onglet **Scripts PowerShell** → **Ajouter**
   - Nom du script : `\\lab.local\SYSVOL\lab.local\scripts\Deploy-WEF-Sysmon-GPO.ps1`
   - Paramètres : (vide)
6. Pas de filtre WMI

### Vérification après déploiement

Après le reboot de la machine cible, vérifier depuis la machine elle-même :

```powershell
# La source est-elle enregistrée ?
wecutil gr Sysmon-Operational
# Attendu : RunTimeStatus: Active + EventSources avec la machine listée

# Des events Sysmon arrivent-ils dans ForwardedEvents ?
Get-WinEvent -LogName ForwardedEvents -MaxEvents 10 |
    Where-Object { $_.ProviderName -eq "Microsoft-Windows-Sysmon" } |
    Select-Object Id, TimeCreated, MachineName
```

Le log du script est disponible sur chaque machine :

```powershell
Get-Content "C:\Windows\Logs\Deploy-WEF-Sysmon.log"
```

### Points importants

**Le reboot est obligatoire au premier déploiement.** `Network Service` n'hérite des droits du groupe `Event Log Readers` qu'après un redémarrage complet. Sans ce reboot, `wecutil gr` affiche `Active` et `LastError: 0` mais aucune source n'est enregistrée.

**Une machine avec deux interfaces réseau peut poser problème.** Si les deux interfaces sont enregistrées dans le DNS, `Wecsvc` peut résoudre le FQDN de la machine sur l'interface non-domaine et échouer silencieusement à s'authentifier. Solution : désactiver l'enregistrement DNS sur les interfaces non-domaine via `Set-DnsClient -RegisterThisConnectionsAddress $false`.

**La subscription réapparaît après chaque reboot via la GPO.** Si elle est supprimée manuellement, elle est recréée au prochain démarrage.

---

## 11. Vérification dans UTMStack

### Champs Sysmon validés en lab

Les events Sysmon forwarded via WEF arrivent dans UTMStack avec leurs métadonnées complètes. Les champs suivants ont été validés en production depuis gest-srv et DC01-MAIN-SITE :

| Champ OpenSearch | Valeur exemple | EID |
|---|---|---|
| `log.providerName` | `Microsoft-Windows-Sysmon` | tous |
| `log.channel` | `Microsoft-Windows-Sysmon/Operational` | tous |
| `log.eventCode` | `12` | RegistryEvent |
| `log.data.Image` | `C:\Windows\System32\lsass.exe` | 1, 10, 12/13 |
| `log.data.ProcessGuid` | `{6e2a3eee-c8d7-...}` | 1, 10 |
| `log.data.RuleName` | `RegistryEvent - Run keys et persistance` | tous |
| `log.data.TargetObject` | `HKLM\System\CurrentControlSet\...` | 12/13 |
| `log.data.User` | `AUTORITE NT\Système` | tous |
| `log.data.UtcTime` | `2026-08-07 13:39:02.077` | tous |
| `dataSource` | `DC01-MAIN-SITE` | tous |

> Les champs `log.data.CommandLine`, `log.data.ParentImage` (EID 1), `log.data.TargetImage`, `log.data.GrantedAccess` (EID 10) et `log.data.PipeName` (EID 17/18) doivent être confirmés en live avant d'écrire les règles YAML du chapitre 11.

### Requête de vérification depuis UTMStack

```bash
OSPWD='votre-mot-de-passe-opensearch'
docker exec $(docker ps -q -f name=utmstack_node1) \
  curl -sk -u "admin:$OSPWD" \
  'https://localhost:9200/v11-log-wineventlog-*/_search?pretty' \
  -H 'Content-Type: application/json' \
  -d '{
    "query": {
      "term": { "log.providerName": "Microsoft-Windows-Sysmon" }
    },
    "size": 5,
    "sort": [{ "@timestamp": { "order": "desc" }}]
  }'
```

---

## 12. Mise à jour de la configuration

### Via GPO (postes et DC joints au domaine)

Toute modification de la configuration suit le même cycle :

1. Modifier le XML sur la machine de référence (WIN11-AD-TESTS pour la config workstation, DC01-MAIN-SITE pour la config DC)
2. Appliquer la nouvelle config : `edgeIT.exe -c sysmon-workstation-v2.xml`
3. Exporter les nouvelles valeurs registre :
```powershell
reg export "HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters" `
    "C:\Temp\sysmon-workstation-params-v2.reg" /y
```
4. Mettre à jour les éléments GPP Registre dans la GPO `Sysmon - Config Workstations` (ou `Sysmon - Config DC`)
5. Les machines reçoivent les nouvelles valeurs au prochain refresh GPO

La prise en compte est immédiate — Sysmon surveille les modifications de ses clés registre et recharge la configuration sans redémarrage de service.

### Via Intune (MDM-BLAISE-871)

La mise à jour de configuration passe par une révision du package. La commande d'installation utilise le nom générique `sysmonconfig.xml` — renommer le nouveau XML en `sysmonconfig.xml` avant de packager pour ne pas avoir à modifier la commande dans Intune.

**Préparation du package :**

```
C:\tmp\sysmon\
├── edgeIT.exe          ← inchangé
└── sysmonconfig.xml    ← nouveau XML renommé
```

**Packaging :**

```powershell
.\IntuneWinAppUtil.exe -c "C:\tmp\sysmon" -s edgeIT.exe -o "C:\tmp\sysmon-out"
```

**Mise à jour dans Intune :**

1. **Apps → Windows → SYSMON_edgeIT.exe → Propriétés → Modifier**
2. Uploader le nouveau `edgeIT.intunewin`
3. Incrémenter la version de l'application : `2` → `3`
4. **Réviser + enregistrer**

Intune détecte le changement de version et redéploie sur MDM-BLAISE-871, même si la règle de détection est déjà satisfaite par l'installation précédente. Aucune désinstallation préalable n'est nécessaire.

---

> [← Retour à l'index](../) | [→ Chapitre 11 — Règles de corrélation custom](11-correlation-rules)

*Procédures testées et validées sur UTMStack v11.2.12 CE — Infrastructure lab PME Suisse*  
*Références et aide à la rédaction assistées par IA, avec validation humaine finale.*
