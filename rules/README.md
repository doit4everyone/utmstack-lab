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

> ⚠️ **Redémarrage obligatoire après import** : après chaque import, redémarrer les event-processors pour que la règle soit prise en compte par le moteur de corrélation :
> ```bash
> docker service update --force utmstack_event-processor-worker
> sleep 30
> docker service update --force utmstack_event-processor-manager
> ```

## Tableau des règles

### Windows natif (wineventlog)

| Fichier | Event ID | Technique MITRE | Testé | Notes |
|---|---|---|---|---|
| [w1-account-lockout.yml](windows/w1-account-lockout.yml) | 4740 | T1110 | ✅ DC01-MAIN-SITE | Exclusion comptes machine (suffixe `$`) |
| [w2-local-admin-group.yml](windows/w2-local-admin-group.yml) | 4732 | T1098 | ✅ gest-srv | Filtre SID S-1-5-32-544 (langue-agnostique) |
| [w3-privileged-group-member-added.yml](windows/w3-privileged-group-member-added.yml) | 4728/4756 | T1098 | ✅ DC01-MAIN-SITE | Groupes Domain/Schema/Enterprise Admins via RID |
| [w4-scheduled-task.yml](windows/w4-scheduled-task.yml) | 4698 | T1053.005 | ✅ WIN11-AD-TESTS | Exclusion namespaces Microsoft/Windows/SoftLanding |
| [w5a-service-installed-user-dir.yml](windows/w5a-service-installed-user-dir.yml) | 7045 | T1543.003 | ✅ gest-srv | Services installés depuis répertoires utilisateur/temp |
| [w5b-service-installed-suspicious-name.yml](windows/w5b-service-installed-suspicious-name.yml) | 7045 | T1014 | ✅ logique validée | Driver noyau hors system32\drivers — regexMatch multilingue (noyau\|kernel) |
| [w6-ntlm-lateral-movement.yml](windows/w6-ntlm-lateral-movement.yml) | 4624 | T1550.002 | ✅ DC01-MAIN-SITE | Logon type 3 NTLM, exclusion MSOL_ (Entra Connect) |
| [w7-kerberoasting.yml](windows/w7-kerberoasting.yml) | 4769 | T1558.003 | ✅ DC01-MAIN-SITE | RC4 (0x17), exclusion comptes machine |

> ⚠️ **W8 — Run Key EID 4657 (non implémentable v11.2.12)** : le champ `ObjectName` de l'EID 4657 n'est pas mappé dans les champs structurés par UTMStack v11 et le moteur de corrélation n'évalue pas le champ `raw`. La règle sera implémentable si UTMStack mappe ce champ ou lève la limitation Sysmon sur Windows 11 (issue #2446). Alternative actuelle : MDE Plan 1 détecte nativement T1547.001 via son moteur ASEP.

### Sysmon (via WEF)

| Fichier | Event ID | Technique MITRE | Testé | Notes |
|---|---|---|---|---|
| [s1-lolbas-execution.yml](sysmon/s1-lolbas-execution.yml) | 4688 | T1218 | ✅ WIN11-AD-TESTS | EID 4688 + GPO ligne de commande (EID 1 filtré par UTMStack) |
| [s2-lsass-access.yml](sysmon/s2-lsass-access.yml) / [s2-lsass-access-vmware.yml](sysmon/s2-lsass-access-vmware.yml) | 10 | T1003.001 | ✅ gest-srv | Exclusion masques query-only (5120/5200) + AAD Health Agent — variante VMware exclut vmtoolsd.exe |
| [s3-suspicious-named-pipe.yml](sysmon/s3-suspicious-named-pipe.yml) | 17 | T1559.001 | ✅ WIN11-AD-TESTS | Named pipes C2 (Cobalt Strike, Metasploit, Mimikatz) |
| [s4-ntds-sam-access.yml](sysmon/s4-ntds-sam-access.yml) | 11 | T1003.003 | ✅ DC01-MAIN-SITE | Sysmon EID 11 FileCreate sur NTDS/SAM |
| [s5-registry-run-persistence.yml](sysmon/s5-registry-run-persistence.yml) | 12/13 | T1547.001 | ✅ WIN11-AD-TESTS | Sysmon EID 12/13 Run/RunOnce |

> ⚠️ **Prérequis Sysmon** : la règle S1 requiert l'activation de la GPO "Inclure la ligne de commande dans les événements de création de processus" (Configuration ordinateur → Stratégies → Modèles d'administration → Système → Création de processus d'audit). Sans cette GPO, `log.data.CommandLine` est absent.

> ℹ️ **S2 — deux variantes** : utiliser `s2-lsass-access-vmware.yml` dans les environnements VMware, `s2-lsass-access.yml` dans les autres. Ne pas importer les deux simultanément. UTMStack stocke `log.data.GrantedAccess` en **décimal** — les valeurs hexadécimales des règles publiques Sysmon (0x1010, 0x1410) doivent être converties (4112, 5136).

### Linux (auditd)

| Fichier | Action auditd | Technique MITRE | Testé | Notes |
|---|---|---|---|---|
| [l1-ssh-brute-force.yml](linux/l1-ssh-brute-force.yml) | USER_AUTH fail + sshd | T1110.001 | ✅ docker-services | Seuls les champs auditd structurés sont évalués par UTMStack |
| [l2-sudo-abuse.yml](linux/l2-sudo-abuse.yml) | USER_AUTH success + sudo | T1548.003 | ✅ docker-services | `log.message` non évalué par le moteur — utiliser `log.userauth.*` |

> ⚠️ **Limitation moteur** : le moteur de corrélation UTMStack v11 n'évalue pas `log.message` ni `raw` pour les événements Linux. Seuls les champs auditd structurés (`action`, `log.userauth.*`) sont traités.

### Windows Defender

| Fichier | Event ID | Technique MITRE | Testé | Notes |
|---|---|---|---|---|
| [windows-defender-malware-detected.yml](windows-defender/windows-defender-malware-detected.yml) | 1116 | T1587.001 | ✅ WIN11-AD-TESTS | Malware détecté avec ThreatName complet — aucune règle native UTMStack ne couvre cet event |
| [windows-defender-tamper-protection.yml](windows-defender/windows-defender-tamper-protection.yml) | 5013 | T1562.001 | ✅ MDM-BLAISE-871 | Exclusion FP : Changed Type = Ignoré |
| [windows-defender-realtime-disabled.yml](windows-defender/windows-defender-realtime-disabled.yml) | 5001 | T1562.001 | ⚠️ Non testé | Bloqué par Tamper Protection dans le lab |
| [windows-defender-remediation-failed.yml](windows-defender/windows-defender-remediation-failed.yml) | 1118 | T1204 | ⚠️ Non testé | Nécessite un malware non remédiable |
| [windows-defender-exclusion-added.yml](windows-defender/windows-defender-exclusion-added.yml) | 5007 | T1562.001 | ✅ WIN11-AD-TESTS | Exclusions FP : WdConfigHash, UX Configuration, DLP Configs, EcsConfigs |

### Microsoft 365 / Entra ID

| Fichier | Action O365 | Technique MITRE | Testé | Notes |
|---|---|---|---|---|
| [o365-entra-brute-force.yml](microsoft-365/o365-entra-brute-force.yml) | UserLoginFailed + LogonError InvalidUserNameOrPassword | T1110.001 | ✅ M365 Lab | Intégration O365 active |
| [o365-entra-password-spray.yml](microsoft-365/o365-entra-password-spray.yml) | UserLoginFailed + LogonError InvalidUserNameOrPassword | T1110.003 | ✅ M365 Lab | Intégration O365 active |
| [o365-impossible-travel.yml](microsoft-365/o365-impossible-travel.yml) | UserLoggedIn | T1078 | ✅ M365 Lab | Géolocalisation activée dans UTMStack |
| [o365-dlp-rule-match.yml](microsoft-365/o365-dlp-rule-match.yml) | DLPRuleMatch / DlpRuleMatch | T1567 | ✅ M365 Lab | Microsoft Purview DLP activé — regexMatch insensible à la casse |
| [o365-mde-malware-deleted.yml](microsoft-365/o365-mde-malware-deleted.yml) | FileDeleted + Endpoint | T1070 | ✅ M365 Lab | MDE Plan 1 minimum — exclusions explorer.exe, OneDrive.exe, Teams.exe, taskhostw.exe |
| [m2-oauth-app-consent.yml](microsoft-365/m2-oauth-app-consent.yml) | Consent to application. | T1550.001 | ✅ M365 Lab | Intégration O365 active |
| [m5-mfa-required-interrupt.yml](microsoft-365/m5-mfa-required-interrupt.yml) | UserLoginFailed + LogonError StrongAuth | T1078.004 | ✅ M365 Lab | Intégration O365 active |
| [m6-entra-group-member-added.yml](microsoft-365/m6-entra-group-member-added.yml) | Add member to group. | T1098.003 | ✅ M365 Lab | Exclusion ServicePrincipals Microsoft |
| [m7-entra-user-created.yml](microsoft-365/m7-entra-user-created.yml) | Add user. | T1136.003 | ✅ M365 Lab | Exclusion Entra Connect (ConnectSyncProvisioning) |
| [m8-audit-log-disabled.yml](microsoft-365/m8-audit-log-disabled.yml) | Set-AdminAuditLogConfig | T1562.008 | ✅ M365 Lab | Alerte sur toute exécution — log.Parameters tableau imbriqué non filtrable |
| [m10-purview-autolabel-match.yml](microsoft-365/m10-purview-autolabel-match.yml) | AutoSensitivityLabelRuleMatch | T1567 | ✅ M365 Lab | Microsoft Purview auto-labeling activé |
| [m12-exchange-external-mailbox-access.yml](microsoft-365/m12-exchange-external-mailbox-access.yml) | MailItemsAccessed + ExternalAccess | T1114.002 | ✅ logique validée | Audit Exchange activé — aucun event ExternalAccess=true en base (tenant single-user) |
| [m14-signin-blocked-ca.yml](microsoft-365/m14-signin-blocked-ca.yml) | UserLoginFailed + BlockedByConditionalAccess | T1078.004 | ✅ M365 Lab | CA temporelle via Graph API — couvre tous les blocages CA (ErrorNumber 53003) |

> ⚠️ **Boucle DLP** : dans les environnements où les notifications UTMStack sont envoyées vers une adresse externe, les règles M10 et M11 peuvent déclencher en boucle. Configurer les notifications vers une adresse interne au tenant.

> ⚠️ **M13 — Téléchargement massif SharePoint (non implémentable v11.2.12)** : l'event `FileDownloaded` (RecordType 6) est perdu dans le pipeline ETL d'UTMStack malgré une souscription `Audit.SharePoint` active et une collecte confirmée des blobs. À tester après chaque mise à jour d'UTMStack.

> ℹ️ **M14 — CA temporelle** : la condition temporelle n'est pas disponible dans l'interface graphique Entra ID — configurer via `PATCH https://graph.microsoft.com/beta/identity/conditionalAccess/policies/{id}`. Exclure impérativement le compte break-glass. Note nLPD : documenter dans le registre des activités de traitement.

> ℹ️ **Limitation Purview Audit** : la détection des tentatives d'accès à un fichier chiffré AIP nécessite Microsoft Purview Audit Premium (E5 ou add-on). Non disponible avec Business Premium.

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
| [a7-azure-role-assignment.yml](azure/a7-azure-role-assignment.yml) | ROLEASSIGNMENTS/WRITE + DELETE | T1078.004 | ✅ Abonnement Tests Azure | origin.user non mappé — UPN dans log.identity.claims |
| [a8-azure-diagnostic-settings.yml](azure/a8-azure-diagnostic-settings.yml) | DIAGNOSTICSETTINGS/WRITE + DELETE | T1562.008 | ✅ Abonnement Tests Azure | Log Analytics Contributor suffit — pas besoin d'Owner |
| [a9-azure-keyvault.yml](azure/a9-azure-keyvault.yml) | KEYVAULT/VAULTS/WRITE + DELETE | T1485 | ✅ Abonnement Tests Azure | Accès aux secrets individuels non détectable via Activity Log |
| [a10-azure-resource-lock.yml](azure/a10-azure-resource-lock.yml) | AUTHORIZATION/LOCKS/WRITE + DELETE | T1562.007 | ✅ Abonnement Tests Azure | Corrélation A10+A11 = signal d'urgence (pattern Scattered Spider) |
| [a11-azure-deletion-blocked-lock.yml](azure/a11-azure-deletion-blocked-lock.yml) | DELETE + Failure + ScopeLocked | T1485 | ✅ Abonnement Tests Azure | Discriminant : log.properties.statusMessage contient ScopeLocked |

> ⚠️ **Prérequis Azure** : Event Hub SKU **Standard** requis (pas Essentiel/Basic). Créer un Consumer Group dédié `utmstack` dans l'instance Event Hub.

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
| `log.Workload` O365 indexé en `text` | Utiliser `contains()` et non `equals()` |
| `log.operationName` Azure indexé en `text`, valeurs en MAJUSCULES | Utiliser `contains()` — `log.operationName.keyword` pour les aggregations |
| `log.ExternalAccess` O365 est un booléen natif | `equals("log.ExternalAccess", true)` sans guillemets sur la valeur |
| `log.Parameters` O365 est un tableau imbriqué | Non filtrable par le moteur — alerter sur l'action, pas sur la valeur |
| Events Linux : `log.message` et `raw` non évalués | Utiliser uniquement les champs auditd structurés |
| Sysmon EID 1 filtré par l'agent UTMStack | Utiliser EID 4688 + GPO ligne de commande |
| Champ `raw` non évalué par le moteur de corrélation | Utiliser uniquement les champs structurés mappés dans `log.*` |
| `log.data.GrantedAccess` stocké en **décimal** (pas hexadécimal) | Convertir les valeurs hex des règles publiques Sysmon avant usage |
| Règles non rétroactives | Déclenchent uniquement sur les nouveaux events après import |

## Références

- [Chapitre 10 — Intégrations des agents](https://doit4everyone.github.io/utmstack-lab/docs/10-integrations-agents.html)
- [Chapitre 11 — Règles de corrélation custom](https://doit4everyone.github.io/utmstack-lab/docs/11-correlations-yaml.html)
- [Guide Microsoft Purview 2026 — nLPD](https://doit4everyone.github.io/microsoft-purview-configuration-2026-nLPD/)
- [Documentation UTMStack](https://docs.utmstack.com)
