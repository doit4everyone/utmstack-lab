# Règles de corrélation UTMStack — Bibliothèque

Règles de corrélation custom pour UTMStack v11, développées et testées en conditions réelles dans le cadre du projet [UTMStack Lab](https://doit4everyone.github.io/utmstack-lab/).

## Structure

```
rules/
├── windows/             ← Règles basées sur les journaux Windows natifs (wineventlog)
├── sysmon/              ← Règles basées sur les événements Sysmon via WEF
├── linux/               ← Règles basées sur les événements auditd Linux
├── windows-defender/    ← Règles basées sur les événements Windows Defender
├── microsoft-365/       ← Règles basées sur les logs O365/Entra ID
└── azure/               ← Règles basées sur les logs Azure Activity Log
```

## Procédure d'import

1. Dans UTMStack → **Threat Management** → **Correlation Rules** → **Import**
2. Sélectionner le fichier `.yml`
3. La règle est immédiatement active — aucune étape supplémentaire requise

> ℹ️ **Stabilité** : les règles importées via l'UI (`system_owner = false`) ne sont **pas** réinitialisées au redémarrage des conteneurs UTMStack — contrairement aux règles natives. Elles persistent sans aucune automatisation supplémentaire.

## Tableau des règles

### Windows natif (wineventlog)

| Fichier | Event ID | Technique MITRE | Testé | Notes |
|---|---|---|---|---|
| [w1-account-lockout.yml](windows/w1-account-lockout.yml) | 4740 | T1110 | ✅ DC01-MAIN-SITE | Exclusion comptes machine (suffixe `$`) |
| [w2-local-admin-group.yml](windows/w2-local-admin-group.yml) | 4732 | T1098 | ✅ gest-srv | Filtre SID S-1-5-32-544 (langue-agnostique) |
| [w3-privileged-domain-group.yml](windows/w3-privileged-domain-group.yml) | 4728/4756 | T1098 | ✅ DC01-MAIN-SITE | Groupes Domain/Schema/Enterprise Admins via RID |
| [w4-scheduled-task.yml](windows/w4-scheduled-task.yml) | 4698 | T1053.005 | ✅ WIN11-AD-TESTS | Exclusion namespaces Microsoft/Windows/SoftLanding |
| [w5a-service-installed-user-dir.yml](windows/w5a-service-installed-user-dir.yml) | 7045 | T1543.003 | ✅ gest-srv | Services installés depuis répertoires utilisateur/temp |
| [w5b-service-installed-suspicious-name.yml](windows/w5b-service-installed-suspicious-name.yml) | 7045 | T1543.003 | ✅ logique validée | Noms de service générés aléatoirement |
| [w6-ntlm-lateral-movement.yml](windows/w6-ntlm-lateral-movement.yml) | 4624 | T1550.002 | ✅ DC01-MAIN-SITE | Logon type 3 NTLM, exclusion MSOL_ (Entra Connect) |
| [w7-kerberoasting.yml](windows/w7-kerberoasting.yml) | 4769 | T1558.003 | ✅ DC01-MAIN-SITE | RC4 (0x17), exclusion comptes machine |

### Sysmon (via WEF)

| Fichier | Event ID | Technique MITRE | Testé | Notes |
|---|---|---|---|---|
| [s1-lolbas-execution.yml](sysmon/s1-lolbas-execution.yml) | 4688 | T1218 | ✅ WIN11-AD-TESTS | EID 4688 + GPO ligne de commande (EID 1 filtré par UTMStack) |
| [s2-suspicious-parent-child.yml](sysmon/s2-suspicious-parent-child.yml) | 4688 | T1059 | ✅ WIN11-AD-TESTS | Exclusion VMware Tools (faux positif confirmé) |
| [s3-process-injection.yml](sysmon/s3-process-injection.yml) | 8 | T1055 | ✅ WIN11-AD-TESTS | Sysmon EID 8 CreateRemoteThread |
| [s4-ntds-sam-access.yml](sysmon/s4-ntds-sam-access.yml) | 11 | T1003.003 | ✅ DC01-MAIN-SITE | Sysmon EID 11 FileCreate sur NTDS/SAM |
| [s5-registry-run-key.yml](sysmon/s5-registry-run-key.yml) | 12/13 | T1547.001 | ✅ WIN11-AD-TESTS | Sysmon EID 12/13 Run/RunOnce |

> ⚠️ **Prérequis Sysmon** : la règle S1 requiert l'activation de la GPO "Inclure la ligne de commande dans les événements de création de processus" (Configuration ordinateur → Stratégies → Modèles d'administration → Système → Création de processus d'audit). Sans cette GPO, `log.data.CommandLine` est absent.

### Linux (auditd)

| Fichier | Action auditd | Technique MITRE | Testé | Notes |
|---|---|---|---|---|
| [l1-ssh-brute-force.yml](linux/l1-ssh-brute-force.yml) | USER_AUTH fail + sshd | T1110.001 | ✅ docker-services | Seuls les champs auditd structurés sont évalués par UTMStack |
| [l2-sudo-abuse.yml](linux/l2-sudo-abuse.yml) | USER_AUTH success + sudo | T1548.003 | ✅ docker-services | `log.message` non évalué par le moteur — utiliser `log.userauth.*` |

> ⚠️ **Limitation moteur** : le moteur de corrélation UTMStack v11 n'évalue pas `log.message` ni `raw` pour les événements Linux. Seuls les champs auditd structurés (`action`, `log.userauth.*`) sont traités.

### Windows Defender

| Fichier | Event ID | Technique MITRE | Testé | Notes |
|---|---|---|---|---|
| [windows-defender-exclusion-added.yml](windows-defender/windows-defender-exclusion-added.yml) | 5007 | T1562.001 | ✅ WIN11-AD-TESTS | Exclusions FP : WdConfigHash, UX Configuration, DLP Configs, EcsConfigs |
| [windows-defender-realtime-disabled.yml](windows-defender/windows-defender-realtime-disabled.yml) | 5001 | T1562.001 | ⚠️ Non testé | Bloqué par Tamper Protection dans le lab |
| [windows-defender-remediation-failed.yml](windows-defender/windows-defender-remediation-failed.yml) | 1118 | T1204 | ⚠️ Non testé | Nécessite un malware non remédiable |
| [windows-defender-tamper-protection.yml](windows-defender/windows-defender-tamper-protection.yml) | 5013 | T1562.001 | ✅ MDM-BLAISE-871 | Exclusion FP : Changed Type = Ignoré |

> **Note** : l'Event 1116 (Malware Detected) est couvert par la règle native UTMStack — aucune règle custom nécessaire.

### Microsoft 365 / Entra ID

| Fichier | Action O365 | Technique MITRE | Testé | Prérequis |
|---|---|---|---|---|
| [o365-entra-brute-force.yml](microsoft-365/o365-entra-brute-force.yml) | UserLoginFailed + LogonError InvalidUserNameOrPassword | T1110.001 | ✅ M365 Lab | Intégration O365 UTMStack active |
| [o365-entra-password-spray.yml](microsoft-365/o365-entra-password-spray.yml) | UserLoginFailed + LogonError InvalidUserNameOrPassword | T1110.003 | ✅ M365 Lab | Intégration O365 UTMStack active |
| [o365-impossible-travel.yml](microsoft-365/o365-impossible-travel.yml) | UserLoggedIn | T1078 | ✅ M365 Lab | Géolocalisation activée dans UTMStack |
| [o365-dlp-rule-match.yml](microsoft-365/o365-dlp-rule-match.yml) | DLPRuleMatch / DlpRuleMatch | T1567 | ✅ M365 Lab | Microsoft Purview DLP activé |
| [o365-mde-malware-deleted.yml](microsoft-365/o365-mde-malware-deleted.yml) | FileDeleted + Endpoint | T1070 | ✅ M365 Lab (EICAR) | MDE Plan 1 minimum |
| [m2-oauth-app-consent.yml](microsoft-365/m2-oauth-app-consent.yml) | Consent to application. | T1550.001 | ✅ M365 Lab | Intégration O365 active |
| [m5-mfa-required-interrupt.yml](microsoft-365/m5-mfa-required-interrupt.yml) | UserLoginFailed + LogonError StrongAuth | T1078.004 | ✅ M365 Lab | Intégration O365 active |
| [m6-entra-group-member-added.yml](microsoft-365/m6-entra-group-member-added.yml) | Add member to group. | T1098.003 | ✅ M365 Lab | Exclusion ServicePrincipals Microsoft |
| [m7-entra-user-created.yml](microsoft-365/m7-entra-user-created.yml) | Add user. | T1136.003 | ✅ M365 Lab | Exclusion Entra Connect (ConnectSyncProvisioning) |
| [m10-purview-autolabel-match.yml](microsoft-365/m10-purview-autolabel-match.yml) | AutoSensitivityLabelRuleMatch | T1567 | ✅ M365 Lab | Microsoft Purview auto-labeling activé |
| [m12-exchange-external-mailbox-access.yml](microsoft-365/m12-exchange-external-mailbox-access.yml) | MailItemsAccessed + ExternalAccess | T1114.002 | ✅ logique validée | Audit Exchange activé |

> ⚠️ **Boucle DLP** : dans les environnements où les notifications UTMStack sont envoyées vers une adresse externe, les règles M10 et M11 peuvent déclencher en boucle sur les emails de rapport DLP. Configurer les notifications UTMStack vers une adresse interne.

> ℹ️ **Limitation Purview Audit** : la détection des tentatives d'accès à un fichier chiffré AIP (avec IP de l'attaquant) nécessite Microsoft Purview Audit Premium (E5 ou add-on). Non disponible avec Business Premium.

### Azure Activity Log

| Fichier | Opération Azure | Technique MITRE | Testé | Notes |
|---|---|---|---|---|
| [a1-azure-storage-keys-listed.yml](azure/a1-azure-storage-keys-listed.yml) | STORAGEACCOUNTS/LISTKEYS | T1552.005 | ✅ Abonnement Tests Azure | Volume élevé — services automatiques Azure (NetworkWatcher, Event Grid) |
| [a2-azure-resource-group-deleted.yml](azure/a2-azure-resource-group-deleted.yml) | RESOURCEGROUPS/DELETE | T1485 | ✅ Abonnement Tests Azure | Filtre resultType=Success |
| [a3-azure-vm-deallocated.yml](azure/a3-azure-vm-deallocated.yml) | VIRTUALMACHINES/DEALLOCATE\|DELETE | T1529 | ✅ Abonnement Tests Azure | regexMatch pour couvrir les deux opérations |
| [a4a-azure-nsg-created-modified.yml](azure/a4a-azure-nsg-created-modified.yml) | NETWORKSECURITYGROUPS/WRITE | T1562.007 | ✅ Abonnement Tests Azure | NSG entier — exclusion SECURITYRULES |
| [a4b-azure-nsg-rule-modified.yml](azure/a4b-azure-nsg-rule-modified.yml) | NETWORKSECURITYGROUPS/SECURITYRULES/WRITE | T1562.007 | ✅ Abonnement Tests Azure | Règle individuelle — signal plus fort |
| [a5-azure-storage-keys-eventhub.yml](azure/a5-azure-storage-keys-eventhub.yml) | EVENTHUB/NAMESPACES/AUTHORIZATIONRULES/LISTKEYS | T1552.005 | ✅ Abonnement Tests Azure | Clés SAS Event Hub |
| [a6-azure-arm-deployment.yml](azure/a6-azure-arm-deployment.yml) | DEPLOYMENTS/WRITE | T1072 | ✅ Abonnement Tests Azure | Déclenche aussi sur déploiements implicites (portail Azure) |

> ⚠️ **Prérequis Azure** : Event Hub SKU **Standard** requis (pas Essentiel/Basic). Créer un Consumer Group dédié `utmstack` dans l'instance Event Hub — le SKU Essentiel limite à un seul Consumer Group (`$Default`), ce qui provoque des pertes de messages en cas d'accès concurrent.

## Philosophie de tuning

Ces règles suivent une **approche défensive** : la règle capture large, les faux positifs connus sont exclus chirurgicalement avec documentation de la raison. Cette approche est préférable à une approche offensive (liste blanche de patterns dangereux) car elle minimise le risque de rater une vraie menace.

Un ServicePrincipal compromis peut effectuer les mêmes opérations qu'un ServicePrincipal légitime — les exclusions sur `principalType` ne sont pas appliquées pour cette raison.

Chaque exclusion ajoutée est documentée dans le champ `where:` avec un commentaire implicite dans le nom du pattern exclu.

## Contraintes moteur UTMStack v11 (validées empiriquement)

| Contrainte | Impact |
|---|---|
| `groupBy: []` et `deduplicateBy: []` obligatoirement vides | Toute valeur non vide bloque silencieusement le déclenchement |
| Pas de blocs `()` avec `\|\|` multiples | Le moteur crashe → règle auto-désactivée après 5 échecs |
| `log.channel` Sysmon indexé en `text` | Utiliser `contains()` et non `equals()` |
| `log.ExternalAccess` O365 est un booléen natif | `equals("log.ExternalAccess", true)` sans guillemets sur la valeur |
| Events Linux : `log.message` et `raw` non évalués | Utiliser uniquement les champs auditd structurés |
| Sysmon EID 1 filtré par l'agent UTMStack | Utiliser EID 4688 + GPO ligne de commande |

## Références

- [Chapitre 10 — Intégrations des agents](https://doit4everyone.github.io/utmstack-lab/docs/10-integrations-agents.html)
- [Chapitre 11 — Règles de corrélation custom](https://doit4everyone.github.io/utmstack-lab/docs/11-correlations-yaml.html)
- [Documentation UTMStack](https://docs.utmstack.com)
