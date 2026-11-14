# Règles de corrélation UTMStack : bibliothèque

Règles de corrélation personnalisées pour UTMStack v11, développées et testées en conditions réelles dans le cadre du projet [UTMStack Lab](https://doit4everyone.github.io/utmstack-lab/).

> ⚠️ **Version de référence : UTMStack v11.3.0.** Cette version remplace le sac de champs `log.*` par `event.*` (indexé en `flat_object` dans OpenSearch). Toutes les règles de ce dossier ont été migrées en `event.*` et revalidées en novembre 2026, sauf la série Azure (voir plus bas). Les règles écrites pour v11.2 (`log.*`) ne matchent plus rien en v11.3.0 : elles restent disponibles dans la release [`v11.2-final`](https://github.com/doit4everyone/utmstack-lab/releases/tag/v11.2-final).

## Structure

```
rules/
├── windows/             → journaux Windows natifs (wineventlog)
├── sysmon/              → événements Sysmon collectés par WEF
├── windows-defender/    → journal Microsoft-Windows-Windows Defender/Operational
├── linux/               → événements auditd
├── microsoft-365/       → journaux O365, Entra ID, Exchange, Purview
├── azure/               → Azure Activity Log et Event Grid (non revalidées)
├── suricata/            → clones de règles natives Suricata
├── pipeline/            → supervision du pipeline SOC (heartbeat)
└── retirees/            → règles retirées en v11.3.0, conservées pour référence
```

## Procédure d'import

1. Dans UTMStack → **Threat Management** → **Correlation Rules** → **Import**.
2. Sélectionner le fichier `.yml`.
3. Redémarrer les event-processors, qui chargent les règles en mémoire :
   ```bash
   docker service update --force utmstack_event-processor-worker
   sleep 30
   docker service update --force utmstack_event-processor-manager
   ```

> ℹ️ **Persistance** : les règles importées (`system_owner = false`) ne sont pas réécrites au redémarrage. Le backend v11.3.0 resynchronise seulement les règles natives depuis ses propres YAML, en conservant leur statut actif ou inactif.

> ℹ️ **Mise à jour d'une règle existante** : supprimer l'ancienne version avant d'importer la nouvelle. C'est indispensable pour la série Azure, dont deux règles ont changé de nom (A8, A9).

> ℹ️ **Règles non rétroactives** : une règle ne se déclenche que sur les événements reçus après son import et le redémarrage des event-processors.

## Prérequis de collecte

Plusieurs règles dépendent d'un réglage d'audit absent par défaut. Sans lui, la règle est importée sans erreur mais ne voit jamais l'événement.

| Règle | Prérequis |
|---|---|
| S1 | Audit « Création du processus » `{0CCE922B-69AE-11D9-BED3-505054503030}` et GPO « Inclure la ligne de commande dans les événements de création de processus » |
| W4 | Audit « Autres événements d'accès à l'objet » `{0CCE9227-69AE-11D9-BED3-505054503030}` |
| S5b | Audit du registre et SACL sur les clés `Run` et `RunOnce` |
| PowerShell (lab) | GPO « Activer la journalisation des blocs de scripts PowerShell ». Sans elle, PowerShell ne journalise en 4104 que les blocs qu'il juge suspicieux d'après sa propre liste |
| S2 à S5 | Sysmon et abonnement WEF vers le collecteur ; S5 exige une configuration Sysmon qui journalise les clés `Run` |
| M12, M10, Mailbox Activity | Audit des boîtes aux lettres Exchange ; M10 exige l'étiquetage automatique Purview |
| Impossible Travel, Mailbox Activity | Géolocalisation activée dans UTMStack |

## Tableau des règles

Légende : ✅ validée en v11.3.0 par un test réel ; 🔵 validée en passif (déclenchement spontané correct) ; ⚠️ non testée ou non testable dans le lab.

### Windows natif (wineventlog)

| Fichier | Event ID | Technique MITRE | Statut | Notes |
|---|---|---|---|---|
| [w1-account-lockout.yml](windows/w1-account-lockout.yml) | 4740 | T1110 | ✅ | `target.domain` contient la machine source du verrouillage (Caller Computer Name) |
| [w3-gpo-creator-owners-added.yml](windows/w3-gpo-creator-owners-added.yml) | 4728/4756 | T1098 | ✅ | Réduite au RID -520 : les RID -512, -518 et -519 sont couverts par la règle native 1512 |
| [w4-scheduled-task-created.yml](windows/w4-scheduled-task-created.yml) | 4698 | T1053.005 | ✅ | Exclusion des tâches Microsoft, Windows et SoftLanding |
| [w5a-service-from-user-path.yml](windows/w5a-service-from-user-path.yml) | 7045 | T1543.003 | ✅ | Exclut les pilotes noyau, qui relèvent de W5b |
| [w5b-kernel-driver-outside-system32.yml](windows/w5b-kernel-driver-outside-system32.yml) | 7045 | T1014 | ✅ | `ServiceType` est traduit : la regex couvre `noyau` et `kernel` |
| [w6-pass-the-hash.yml](windows/w6-pass-the-hash.yml) | 4624 | T1550.002 | 🔵 | Exclusion d'un couple poste d'administration et compte, à adapter (voir plus bas) |
| [w7-kerberoasting-rc4.yml](windows/w7-kerberoasting-rc4.yml) | 4769 | T1558.003 | ✅ | Ticket RC4 (`TicketEncryptionType = 23`) |
| [s5b-registry-run-persistence-4657.yml](windows/s5b-registry-run-persistence-4657.yml) | 4657 | T1547.001 | ✅ | Variante de S5 sans Sysmon ; suppressions de valeurs exclues (`%%1906`) |
| [windows-suspicious-powershell-lab.yml](windows/windows-suspicious-powershell-lab.yml) | 4104 | T1059.001 | ✅ | Clone de la règle native 1424 (voir « Clones de règles natives ») |

> ℹ️ **W6, exclusion à adapter** : la règle exclut le couple `origin.host = ADMIN-WORKSTATION` et `target.user = admin`, qui représente un poste d'administration hors domaine se connectant en RDP avec NLA (donc en NTLM). Remplacer ces deux valeurs par celles de l'environnement, ou supprimer la ligne. Ne jamais exclure le poste seul : tout compte utilisé depuis ce poste échapperait à la détection.

### Sysmon (via WEF)

| Fichier | Event ID | Technique MITRE | Statut | Notes |
|---|---|---|---|---|
| [s1-lolbas-execution.yml](sysmon/s1-lolbas-execution.yml) | 4688 | T1218 | ✅ | Repose sur le 4688 et non sur Sysmon 1, filtré par l'agent UTMStack |
| [s2-lsass-access-vmware.yml](sysmon/s2-lsass-access-vmware.yml) | 10 | T1003.001 | 🔵 | Variante VMware : exclut `vmtoolsd.exe` par son chemin exact |
| [s2-lsass-access.yml](sysmon/s2-lsass-access.yml) | 10 | T1003.001 | 🔵 | Variante universelle, désactivée dans le lab (VMware) |
| [s3-suspicious-named-pipe.yml](sysmon/s3-suspicious-named-pipe.yml) | 17 | T1559.001 | ✅ | Pipes nommés de C2 (Cobalt Strike, PsExec et variantes) |
| [s4-ntds-sam-access.yml](sysmon/s4-ntds-sam-access.yml) | 11 | T1003.003 | ✅ | Création de fichiers NTDS, SAM, SYSTEM, SECURITY |
| [s5-registry-run-persistence.yml](sysmon/s5-registry-run-persistence.yml) | 12/13 | T1547.001 | ⚠️ | Inopérante dans le lab : la configuration Sysmon ne journalise pas les clés `Run` de HKCU. Voir S5b |

> ℹ️ **S2, deux variantes** : importer `s2-lsass-access-vmware.yml` dans un environnement VMware, `s2-lsass-access.yml` ailleurs, jamais les deux. UTMStack stocke `GrantedAccess` en décimal : les valeurs hexadécimales des règles Sysmon publiques (0x1010, 0x1410) doivent être converties (4112, 5136).

### Windows Defender

| Fichier | Event ID | Technique MITRE | Statut | Notes |
|---|---|---|---|---|
| [windows-defender-malware-detected.yml](windows-defender/windows-defender-malware-detected.yml) | 1116 | T1587.001 | ✅ | Le champ s'appelle `Threat Name`, avec une espace |
| [windows-defender-tamper-protection.yml](windows-defender/windows-defender-tamper-protection.yml) | 5013 | T1562.001 | ✅ | Exclusion de `Changed Type` dans les deux langues (`Ignoré`, `Ignored`) |
| [windows-defender-exclusion-added.yml](windows-defender/windows-defender-exclusion-added.yml) | 5007 | T1562.001 | ✅ | Critère positif : seules les écritures sous `\Exclusions\` déclenchent |
| [windows-defender-realtime-disabled.yml](windows-defender/windows-defender-realtime-disabled.yml) | 5001 | T1562.001 | ⚠️ | Non testable : bloquée par la Tamper Protection |
| [windows-defender-remediation-failed.yml](windows-defender/windows-defender-remediation-failed.yml) | 1118 | T1204 | ⚠️ | Non testée : nécessite un malware non remédiable |

### Linux (auditd)

| Fichier | Action auditd | Technique MITRE | Statut | Notes |
|---|---|---|---|---|
| [l1-ssh-brute-force.yml](linux/l1-ssh-brute-force.yml) | USER_AUTH (échec) | T1110.001 | ✅ | Sur Ubuntu 26.04, le processus s'appelle `sshd-session` ; la regex `sshd` le couvre |
| [l2-sudo-abuse.yml](linux/l2-sudo-abuse.yml) | USER_AUTH (succès) | T1548.003 | ✅ | |

### Microsoft 365 et Entra ID

| Fichier | Action O365 | Technique MITRE | Statut | Notes |
|---|---|---|---|---|
| [o365-entra-brute-force.yml](microsoft-365/o365-entra-brute-force.yml) | UserLoginFailed | T1110.001 | ✅ | 5 échecs du même compte en 10 min (`afterEvents`) |
| [o365-entra-password-spray.yml](microsoft-365/o365-entra-password-spray.yml) | UserLoginFailed | T1110.003 | ✅ | 10 échecs depuis la même IP en 30 min (`afterEvents`) |
| [o365-impossible-travel.yml](microsoft-365/o365-impossible-travel.yml) | UserLoggedIn | T1078 | ✅ | Corrélation sur `event.UserKey` ; angle mort des lots O365 (voir plus bas) |
| [o365-mailbox-activity-other-country.yml](microsoft-365/o365-mailbox-activity-other-country.yml) | MailItemsAccessed | T1539 | ✅ | Complète Impossible Travel et couvre le rejeu d'un cookie de session |
| [m2-oauth-app-consent.yml](microsoft-365/m2-oauth-app-consent.yml) | Consent to application. | T1550.001 | ✅ | |
| [m6-entra-group-member-added.yml](microsoft-365/m6-entra-group-member-added.yml) | Add member to group. | T1098.003 | ✅ | Exclusion des ServicePrincipals Microsoft |
| [m7-entra-user-created.yml](microsoft-365/m7-entra-user-created.yml) | Add user. | T1136.003 | ✅ | Exclusion d'Entra Connect (`ConnectSyncProvisioning`) |
| [m8-audit-log-disabled.yml](microsoft-365/m8-audit-log-disabled.yml) | Set-AdminAuditLogConfig | T1562.008 | ✅ | Se déclenche sur toute exécution de la commande, pas seulement sur une désactivation : `Parameters` n'est pas filtrable |
| [m10-purview-autolabel-match.yml](microsoft-365/m10-purview-autolabel-match.yml) | AutoSensitivityLabelRuleMatch | T1567 | ✅ | Étiquetage automatique Purview (Business Premium avec le module Purview Suite dans le lab) |
| [m12-exchange-external-mailbox-access.yml](microsoft-365/m12-exchange-external-mailbox-access.yml) | MailItemsAccessed | T1114.002 | ⚠️ | `ExternalAccess = true` désigne un accès par un tiers extérieur à l'organisation, impossible à provoquer dans le lab |
| [m14-signin-blocked-ca.yml](microsoft-365/m14-signin-blocked-ca.yml) | UserLoginFailed | T1078.004 | ✅ | Tout blocage par l'accès conditionnel (`BlockedByConditionalAccess`) |
| [o365-mde-malware-deleted.yml](microsoft-365/o365-mde-malware-deleted.yml) | FileDeleted (Endpoint) | T1070 | ⚠️ | Sans source dans le lab : aucun poste intégré à MDE ; le workload Endpoint semble correspondre à Endpoint DLP, à vérifier |

> ⚠️ **Impossible Travel, angle mort des lots O365** : `afterEvents` cherche dans les événements déjà indexés. Quand O365 livre la connexion légitime et la connexion étrangère dans le même lot, aucune ne voit l'autre. L'angle mort est aléatoire. La règle « Mailbox Activity From Another Country » le compense : l'activité de messagerie arrive dans un lot postérieur à la connexion.

> ⚠️ **Boucle DLP** : si les notifications UTMStack partent vers une adresse externe, une règle Purview peut se déclencher sur la notification elle-même, en boucle. Envoyer les notifications vers une adresse interne au locataire.

> ⚠️ **M13, téléchargement massif SharePoint (non implémentable)** : l'événement `FileDownloaded` (RecordType 6) n'arrivait pas dans UTMStack en v11.2, malgré une souscription `Audit.SharePoint` active. Non revérifié en v11.3.0.

> ℹ️ **M14, accès conditionnel temporel** : la condition temporelle n'existe pas dans l'interface Entra ID ; la configurer par l'API Graph (`PATCH https://graph.microsoft.com/beta/identity/conditionalAccess/policies/{id}`). Exclure impérativement le compte break-glass.

### Suricata

| Fichier | Statut | Notes |
|---|---|---|
| [suricata-medium-lab.yml](suricata/suricata-medium-lab.yml) | ✅ | Clone de la règle native 876 (voir « Clones de règles natives ») |
| [suricata-high-lab.yml](suricata/suricata-high-lab.yml) | ✅ | Clone de la règle native 875 |
| [suricata-portscan-lab.yml](suricata/suricata-portscan-lab.yml) | ✅ | Clone de la règle native 525 |
| [suricata-tunneling-lab.yml](suricata/suricata-tunneling-lab.yml) | ✅ | Clone de la règle native 530 |
| [suricata-inbound-ban-lab.yml](suricata/suricata-inbound-ban-lab.yml) | ✅ | Déclencheur du flow SOAR 5002 : attaques entrantes laissées passer sur le WAN ([chapitre 05](https://doit4everyone.github.io/utmstack-lab/docs/05-soar.html)) |

### Supervision du pipeline

| Fichier | Statut | Notes |
|---|---|---|
| [soc-pipeline-heartbeat.yml](pipeline/soc-pipeline-heartbeat.yml) | ✅ | Message syslog émis par `soc-pipeline-heartbeat.sh` ([chapitre 09](https://doit4everyone.github.io/utmstack-lab/docs/09-pipeline-llm.html)) |

> ℹ️ Cette règle a été créée dans l'interface et non importée. Elle porte `groupBy` et `deduplicateBy` sur `@timestamp`, et se déclenche pourtant normalement. Elle cherche dans `raw`, qui est donc bien évalué par le moteur, au moins pour le dataType syslog.

### Azure (Activity Log et Event Grid)

> ⚠️ **Non revalidées en v11.3.0.** L'intégration Azure du lab est désactivée (coût). Les règles A1 à A10 ont été réécrites sur le modèle des règles natives v11.3.0 (`event.azureKind`, `event.azureOperation`, `actionResult`), qui couvre à la fois l'Activity Log et Event Grid, mais aucune n'a été testée sur un événement réel. **A11 n'est pas migrée** : elle repose encore sur `log.*`, faute de connaître les champs d'un échec en v11.3.0, et ne se déclenchera pas. Une session de validation est prévue.

| Fichier | Opération Azure | Technique MITRE | Notes |
|---|---|---|---|
| [a1-azure-storage-keys-listed.yml](azure/a1-azure-storage-keys-listed.yml) | Storage, listKeys | T1552.005 | Volume élevé : services automatiques Azure |
| [a2-azure-resource-group-deleted.yml](azure/a2-azure-resource-group-deleted.yml) | resourceGroups, delete | T1485 | |
| [a3-azure-vm-deallocated.yml](azure/a3-azure-vm-deallocated.yml) | virtualMachines, deallocate et delete | T1529 | |
| [a4a-azure-nsg-created-modified.yml](azure/a4a-azure-nsg-created-modified.yml) | networkSecurityGroups, write | T1562.007 | NSG entier |
| [a4b-azure-nsg-rule-modified.yml](azure/a4b-azure-nsg-rule-modified.yml) | securityRules, write | T1562.007 | Règle individuelle, signal plus fort |
| [a5-azure-storage-keys-eventhub.yml](azure/a5-azure-storage-keys-eventhub.yml) | Event Hub authorizationRules, listKeys | T1552.005 | Clés SAS Event Hub |
| [a6-azure-arm-deployment.yml](azure/a6-azure-arm-deployment.yml) | deployments, write | T1072 | Se déclenche aussi sur les déploiements implicites du portail |
| [a7-azure-role-assignment.yml](azure/a7-azure-role-assignment.yml) | roleAssignments, write et delete | T1078.004 | |
| [a8-azure-diagnostic-settings.yml](azure/a8-azure-diagnostic-settings.yml) | diagnosticSettings, write | T1562.008 | Renommée : la suppression est couverte par une règle native |
| [a9-azure-keyvault.yml](azure/a9-azure-keyvault.yml) | Key Vault, delete | T1485 | Renommée : réduite à la suppression pour ne plus doublonner une règle native |
| [a10-azure-resource-lock.yml](azure/a10-azure-resource-lock.yml) | locks, write et delete | T1562.007 | A10 suivie d'A11 : signal d'urgence |
| [a11-azure-deletion-blocked-lock.yml](azure/a11-azure-deletion-blocked-lock.yml) | delete en échec (ScopeLocked) | T1485 | **Non migrée** (`log.*`) |

> ⚠️ **Prérequis Azure** : Event Hub de niveau **Standard** (pas Essentiel/Basic) et un groupe de consommateurs dédié `utmstack`.

## Clones de règles natives

Le backend v11.3.0 réécrit les règles natives depuis ses propres YAML à chaque démarrage : une exclusion ajoutée directement en base est perdue. La méthode retenue consiste à copier la règle native dans une règle utilisateur, à y ajouter l'exclusion, puis à désactiver la règle native par son nom. Le backend conserve ce statut inactif.

```bash
PG=$(docker ps -qf name=postgres | head -1)
docker exec -i $PG psql -U postgres -d utmstack -c "UPDATE utm_correlation_rules SET rule_active=false WHERE rule_name='<nom exact de la règle native>' AND system_owner=true;"
```

Puis redémarrer les event-processors (voir « Procédure d'import »). Toujours cibler une règle native par son nom : les identifiants changent d'une version à l'autre.

| Clone | Règle native désactivée | Exclusion ajoutée |
|---|---|---|
| [suricata-medium-lab.yml](suricata/suricata-medium-lab.yml) | Medium level Suricata alert (876) | Trafic entrant vers le WAN déjà bloqué par Suricata, trafic Microsoft Delivery Optimization, réponses 403 du reverse proxy (sid 2101201), requêtes du pipeline SOC vers Ollama (port 11434), signatures bannies par le flow SOAR 5002 ; `adversary: origin` au lieu de `target` |
| [suricata-high-lab.yml](suricata/suricata-high-lab.yml) | High level Suricata alert (875) | Trafic entrant vers le WAN déjà bloqué par Suricata |
| [suricata-portscan-lab.yml](suricata/suricata-portscan-lab.yml) | Port Scan Detection (525) | Trafic entrant vers le WAN déjà bloqué par Suricata |
| [suricata-tunneling-lab.yml](suricata/suricata-tunneling-lab.yml) | Tunneling Detection (530) | Tout le trafic à destination du WAN : un tunnel concerne un hôte interne qui sort, pas une sonde entrante |
| [windows-suspicious-powershell-lab.yml](windows/windows-suspicious-powershell-lab.yml) | Windows: Suspicious PowerShell (Encoded / Download Cradle / AMSI Bypass) (1424) | Scripts du dossier `DataCollection` de Microsoft Defender for Endpoint (scanner Log4Shell signé Microsoft) |

> ℹ️ Dans les clones Suricata, l'adresse `192.168.1.203` est l'interface WAN d'OPNsense dans le lab. La remplacer par celle de l'environnement.

> ℹ️ Quand la règle native évolue (nouvelle version d'UTMStack), comparer sa définition avec celle du clone et reporter les changements.

## Règles retirées

Ces règles sont désactivées dans le lab depuis la v11.3.0. Elles restent dans [`retirees/`](retirees/), migrées en `event.*`, pour les environnements où la règle native qui les remplace n'existe pas.

| Fichier | Motif du retrait |
|---|---|
| [w2-local-admin-added.yml](retirees/w2-local-admin-added.yml) | Entièrement couverte par la règle native 1512 |
| [m-new-1-privileged-role-assigned.yml](retirees/m-new-1-privileged-role-assigned.yml) | Couverte par la règle native 1440 |
| [m-new-2-service-principal-credentials.yml](retirees/m-new-2-service-principal-credentials.yml) | Couverte par la règle native 840, qui détecte aussi les secrets ajoutés depuis le portail |
| [m5-mfa-required-interrupt.yml](retirees/m5-mfa-required-interrupt.yml) | `UserStrongAuthClientAuthNRequiredInterrupt` est l'étape normale de chaque connexion MFA. Une règle de fatigue MFA (refus répétés) la remplacera |
| [m11-purview-dlp-rule-match.yml](retirees/m11-purview-dlp-rule-match.yml) | Entièrement incluse dans la règle DLP suivante |
| [o365-dlp-rule-match.yml](retirees/o365-dlp-rule-match.yml) | Couverte par la règle native 806 « Data Loss Prevention Policy Violation » (Exchange, SharePoint, OneDrive, Teams, y compris les contournements avec justification) |

> ℹ️ Les numéros de règles natives sont ceux du lab en v11.3.0, donnés à titre indicatif : chercher la règle par son nom.

## Philosophie de réglage

Les règles suivent une **approche défensive** : la règle capture large, et les faux positifs connus sont exclus de façon chirurgicale, avec la raison documentée. Cette approche limite le risque de rater une vraie menace, contrairement à une liste de motifs dangereux.

Un ServicePrincipal compromis peut effectuer les mêmes opérations qu'un ServicePrincipal légitime : c'est pourquoi les exclusions sur `principalType` ne sont pas appliquées.

Avant d'écrire une règle native en double, vérifier ce que couvrent les règles natives : la v11.3.0 en a ajouté beaucoup, et plusieurs règles de ce dossier ont été retirées pour cette raison.

## Contraintes du moteur v11.3.0 (constatées dans le lab)

| Contrainte | Conséquence |
|---|---|
| `event.*` est un `flat_object` | Les conditions `equals`, `contains`, `regexMatch` fonctionnent ; les agrégations OpenSearch ne fonctionnent pas sur `event.*` (utiliser `utm.*` quand le filtre l'alimente) |
| Champs texte : `action`, `origin.user`, `origin.ip` (anciens index), `origin.geolocation.countryCode`, `dataSource` | Dans `afterEvents`, utiliser le sous-champ `.keyword`, sinon le filtre ne matche jamais |
| Point littéral dans une regex | Écrire `[.]` ou `\\.`, jamais `\.` (échappement invalide en CEL : la règle échoue sans alerte) |
| Champ facultatif | Le garder par `exists()` avant de le tester |
| Libellés traduits (`Changed Type`, `ServiceType`, `StartType`) | Prévoir les deux langues, ou filtrer sur un champ numérique |
| `ModifiedProperties` et `Parameters` (O365) | Listes d'objets, inutilisables dans une condition |
| `UserKey` O365 | Celle d'Exchange (PUID) diffère de celle d'Entra (ID d'objet) : entre workloads, relier par l'UPN |
| Parenthèses avec `\|\|` | Fonctionnent en v11.3.0 (constat de v11.2 requalifié) |
| Disjoncteur (« Circuit Breaker ») | Une règle qui échoue 5 fois est coupée temporairement et génère une alerte « Circuit Breaker: <nom> », sans le message d'erreur |
| Renommage Windows | `event.data.TargetSid` devient `event.eventDataTargetSid` (seul renommage touchant ces règles) |
| Sysmon 1 filtré par l'agent UTMStack | Utiliser le 4688 avec la ligne de commande |
| `GrantedAccess` en décimal | Convertir les valeurs hexadécimales des règles Sysmon publiques |
| Valeur YAML contenant `: ` | La mettre entre guillemets, sinon l'import échoue (`bad indentation of a mapping entry`) |

## Références

- [Chapitre 10 : intégrations des agents](https://doit4everyone.github.io/utmstack-lab/docs/10-integrations-agents.html)
- [Chapitre 11 : règles de corrélation personnalisées](https://doit4everyone.github.io/utmstack-lab/docs/11-correlations-yaml.html)
- [Guide Microsoft Purview 2026 et nLPD](https://doit4everyone.github.io/microsoft-purview-configuration-2026-nLPD/)
- [Documentation UTMStack](https://docs.utmstack.com)
