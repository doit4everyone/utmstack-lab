# Règles de corrélation UTMStack — Bibliothèque

Règles de corrélation custom pour UTMStack v11, développées et testées en conditions réelles dans le cadre du projet [UTMStack Lab](https://doit4everyone.github.io/utmstack-lab/).

## Structure

```
rules/
├── windows-defender/    ← Règles basées sur les événements Windows Defender (wineventlog)
├── microsoft-365/       ← Règles basées sur les logs O365/Entra ID
└── azure/               ← Règles basées sur les logs Azure Activity Log (à venir)
```

## Procédure d'import

1. Dans UTMStack → **Threat Management** → **Correlation Rules** → **Import**
2. Sélectionner le fichier `.yml`
3. La règle est immédiatement active — aucune étape supplémentaire requise

> ℹ️ **Stabilité** : les règles importées via l'UI (`system_owner = false`) ne sont **pas** réinitialisées au redémarrage des conteneurs UTMStack — contrairement aux règles natives. Elles persistent sans aucune automatisation supplémentaire.

## Tableau des règles

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
| [o365-dlp-rule-match.yml](microsoft-365/o365-dlp-rule-match.yml) | DLPRuleMatch | T1567 | ✅ M365 Lab | Microsoft Purview DLP activé |
| [o365-entra-brute-force.yml](microsoft-365/o365-entra-brute-force.yml) | UserLoginFailed | T1110.001 | ✅ M365 Lab | Intégration O365 UTMStack active |
| [o365-entra-password-spray.yml](microsoft-365/o365-entra-password-spray.yml) | UserLoginFailed | T1110.003 | ✅ M365 Lab | Intégration O365 UTMStack active |
| [o365-impossible-travel.yml](microsoft-365/o365-impossible-travel.yml) | UserLoggedIn | T1078 | ✅ M365 Lab | Géolocalisation activée dans UTMStack |
| [o365-mde-malware-deleted.yml](microsoft-365/o365-mde-malware-deleted.yml) | FileDeleted + Endpoint | T1070 | ✅ M365 Lab (EICAR) | MDE Plan 1 minimum |

### Azure (à venir — chapitre 11)

| Fichier | Technique MITRE | Statut |
|---|---|---|
| azure-resource-group-delete-blocked.yml | T1485 | 📋 Planifié |
| azure-vm-deallocate.yml | T1529 | 📋 Planifié |

## Philosophie de tuning

Ces règles suivent une **approche défensive** : la règle capture large, les faux positifs connus sont exclus chirurgicalement avec documentation de la raison. Cette approche est préférable à une approche offensive (liste blanche de patterns dangereux) car elle minimise le risque de rater une vraie menace.

Chaque exclusion ajoutée est documentée dans le champ `where:` avec un commentaire implicite dans le nom du pattern exclu.

## Références

- [Chapitre 10 — Intégrations des agents](https://doit4everyone.github.io/utmstack-lab/docs/10-integrations-agents.html)
- [Chapitre 11 — Règles de corrélation custom](https://doit4everyone.github.io/utmstack-lab/docs/11-correlation-rules.html) *(à venir)*
- [Réduction du bruit — Règles natives UTMStack](https://doit4everyone.github.io/utmstack-lab/docs/correlation-rules-tuning.html)
