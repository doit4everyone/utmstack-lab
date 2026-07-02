---
title: "Réduction du bruit — Règles de corrélation UTMStack | DoIt4Everyone"
description: "Alert fatigue sur UTMStack v11 : diagnostic OpenSearch/PostgreSQL, fixes des règles de corrélation 530/875/876, redémarrage des services de corrélation, checklist post-update."
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

# Réduction du bruit — Règles de corrélation UTMStack

> [← Retour à l'index](../)

---

## Contexte — l'alert fatigue, un phénomène universel sur les SIEM

Les règles de corrélation built-in d'un SIEM (`system_owner=true` côté UTMStack) sont calibrées pour un périmètre générique — elles doivent fonctionner sur n'importe quel déploiement, donc elles pèchent presque toujours par excès de largeur plutôt que par excès de précision. Le tuning post-déploiement n'est pas une anomalie, c'est une discipline à part entière du métier SOC (le *detection engineering*), et ce comportement se retrouve sur tous les produits du marché (Splunk ES, QRadar, Sentinel, Elastic Security, Wazuh…).

Ce lab amplifie particulièrement le phénomène : la plupart des déploiements SIEM en entreprise ne reçoivent les logs IDS/IPS qu'après un premier filtrage côté firewall managé. Ici, `HOME_NET` a été délibérément élargi pour inclure le réseau WAN (voir [07 — Règles Suricata avancées](07-custom-rules.md)), afin de capturer tout le trafic de scan Internet à des fins pédagogiques et documentaires. Conséquence directe : 100% du bruit de reconnaissance passive (scanners connus, listes de réputation IP) remonte jusqu'aux règles de corrélation UTMStack, alors qu'un déploiement pro filtrerait une bonne partie de ce volume en amont.

**Échelle observée** sur un mois de lab (`v11-alert-*`, 2026-05-31 → 2026-06-29) : **150 004 alertes "Open"**, dont trois règles built-in concentraient à elles seules 97% du volume.

---

## Méthode de diagnostic — où vivent réellement les alertes

Architecture confirmée par inspection directe (OpenSearch + PostgreSQL) :

| Composant | Contenu |
|---|---|
| **OpenSearch** — index `v11-alert-YYYY-MM-DD` | Instances d'alertes (un index par jour, géré par ISM) |
| **PostgreSQL** — table `utm_correlation_rules` | Définitions des règles de corrélation (`rule_definition_def`) |

Le port OpenSearch (9200) n'est pas exposé sur l'hôte — toute requête passe par `docker exec` dans le conteneur `utmstack_node1` :

```bash
docker exec -it <container_id> curl -s -u 'admin:<password>' -k -X POST "https://localhost:9200/v11-alert-*/_search?pretty" \
-H 'Content-Type: application/json' -d '{ ... }'
```

> ⚠️ Le mot de passe OpenSearch contenant un `!`, il déclenche l'expansion d'historique bash s'il n'est pas entre guillemets simples (`'admin:motdepasse!xxx'`). Toujours encadrer les credentials de guillemets simples.

### Identifier la règle responsable d'un volume de bruit

Agrégation `terms` sur `name.keyword` (le nom de la règle de corrélation associée à chaque alerte) :

```json
{
  "size": 0,
  "aggs": {
    "by_statusLabel": {"terms": {"field": "statusLabel.keyword"}},
    "by_name": {"terms": {"field": "name.keyword", "size": 20}}
  }
}
```

Résultat obtenu (extrait, 1 mois de lab) :

| Règle | Volume | % du total |
|---|---|---|
| Tunneling Detection | 118 932 | 77% |
| High level Suricata alert | 28 195 | 18% |
| Medium level Suricata alert | 3 184 | 2% |
| Known Malicious IP Detected *(SOAR flow 5000)* | 2 254 | 1,5% |
| Suricata Network Anomaly Detected *(SOAR flow 5001)* | 632 | 0,4% |
| *(13 autres règles)* | ~900 | 0,6% |

Une fois la règle identifiée, sa définition se récupère côté PostgreSQL :

```bash
docker exec $(docker ps -q -f name=utmstack_postgres) psql -U postgres -d utmstack -x -c \
"SELECT id, rule_name, rule_category, system_owner, rule_active, rule_definition_def FROM utm_correlation_rules WHERE rule_name = '<nom>';"
```

> ⚠️ **Ne jamais exclure les règles `Known Malicious IP Detected` et `Suricata Network Anomaly Detected`** — ce sont les déclencheurs des flows SOAR 5000/5001 (ban CrowdSec automatique, voir [05 — SOAR & Automatisation](05-soar.md)). Toute modification de filtre doit explicitement les laisser intactes.

---

## Fix 1 — Règle 530 « Tunneling Detection »

### Diagnostic

```
rule_definition_def:
(
  (equals("log.eventType", "alert") &&
   (contains("log.alert.signature", "SSH") &&
    !equals("target.port", 22))) ||
  (equals("log.appProto", "ssh") &&
   !equals("target.port", 22)) ||
  (equals("protocol", "TCP") &&
   equals("target.port", 443) &&
   !equals("log.appProto", "tls")) ||
  (equals("log.eventType", "alert") &&
   contains("log.alert.signature", "tunnel")) ||
  (equals("target.port", 53) &&
   equals("protocol", "TCP") &&
   greaterThan("log.flow.bytes_toserver", 5000))
)
```

La branche 3 (`target.port=443 && !appProto=tls`) est conçue pour détecter du C2 caché sur le port 443 — un signal légitime. Mais en environnement WAN-facing, ce critère matche aussi massivement les scans Internet qui touchent le port 443 sans jamais compléter de handshake TLS.

**Validation par agrégation** sur les hits "Tunneling Detection" :

| Critère | Résultat |
|---|---|
| `target.port` | 443 → 118 994 / 119 105 (99,9%) |
| `log.direction` | `to_server` → 118 191 (quasi 100%, donc trafic entrant uniquement) |
| `log.appProto` identifié | 1 775 / ~119 000 (1,5% seulement — le reste n'a simplement jamais atteint un protocole identifiable) |

Exemple représentatif : signature `SURICATA STREAM 3way handshake SYN resend different seq on SYN recv`, origine externe, cible `192.168.1.203` (WAN OPNsense) — une anomalie de stream TCP typique d'un scan superficiel, pas un vrai tunnel applicatif.

### Fix appliqué

Ajout d'une exclusion ciblée sur la seule branche 443, sans toucher aux 4 autres branches (SSH, port 53) ni à la capacité de détection d'un vrai C2 sortant depuis un hôte interne :

```sql
UPDATE utm_correlation_rules
SET rule_definition_def = $$(
  (equals("log.eventType", "alert") &&
   (contains("log.alert.signature", "SSH") &&
    !equals("target.port", 22))) ||
  (equals("log.appProto", "ssh") &&
   !equals("target.port", 22)) ||
  (equals("protocol", "TCP") &&
   equals("target.port", 443) &&
   !equals("log.appProto", "tls") &&
   !equals("target.ip", "192.168.1.203")) ||
  (equals("log.eventType", "alert") &&
   contains("log.alert.signature", "tunnel")) ||
  (equals("target.port", 53) &&
   equals("protocol", "TCP") &&
   greaterThan("log.flow.bytes_toserver", 5000))
)$$
WHERE id = 530;
```

**Résultat observé** : volume quotidien de "Tunneling Detection" passé de plusieurs milliers à ~200 sur les jours suivant le fix.

---

## Fix 2 — Règle 876 « Medium level Suricata alert »

### Diagnostic

```
rule_definition_def:
equals("log.eventType", "alert") && equals("severity", "medium")
```

Règle volontairement générique — capte tout event Suricata de sévérité moyenne, sans distinction de direction ni de cible. Validation par agrégation :

| Critère | Résultat |
|---|---|
| `action: blocked` total | 1 712 |
| dont `target.ip = 192.168.1.203` (WAN) | 1 708 (99,8% du volume bloqué) |
| `action: allowed` (à préserver) | 1 472 |

Le trafic `blocked` + cible WAN est composé de signatures déjà neutralisées par Suricata (Dshield, NF Known Scanner) — risque réel nul. Le trafic `allowed`, lui, doit rester visible quelle que soit sa cible.

### Fix appliqué

```sql
UPDATE utm_correlation_rules
SET rule_definition_def = $$(
  equals("log.eventType", "alert") &&
  equals("severity", "medium") &&
  !(equals("target.ip", "192.168.1.203") &&
    equals("log.alert.action", "blocked"))
)$$
WHERE id = 876;
```

**Résultat attendu** : ~54% de réduction sur cette règle, sans toucher au trafic `allowed`.

> ⚠️ **Cette version du fix a été complétée par la suite** — voir [Fix 6](#fix-6--règle-876-v2--medium-level-suricata-alert--deuxième-itération) plus bas pour un second profil de bruit découvert sur cette même règle. Si tu construis ton fichier `update-rule876.sql` pour la première fois, utilise directement la version complète du Fix 6, pas celle-ci.

---

## Fix 3 — Règle 875 « High level Suricata alert »

### Diagnostic — l'hypothèse initiale (action=blocked) ne s'est pas vérifiée ici

```
rule_definition_def:
equals("log.eventType", "alert") && equals("severity", "high")
```

Contrairement à la règle 876, l'agrégation sur `by_action` a montré l'inverse de ce qui était attendu :

| `log.alert.action` | Volume |
|---|---|
| `allowed` | 28 413 |
| `blocked` | 10 |

Le critère "WAN + blocked" ne pouvait donc réduire que 10 documents sur 28 195 — inutile tel quel. L'agrégation sur `by_signature` a révélé le vrai dénominateur commun :

| Signature | Volume | % du bucket |
|---|---|---|
| SCAN Very slow stealth port scan | 15 758 | 56% |
| SCAN Ultra-slow paranoid stealth scan | 12 162 | 43% |
| *(8 autres signatures + reste)* | ~275 | 1% |

Ces deux signatures sont des détections **comportementales** de scan furtif (paquets espacés dans le temps) — Suricata les classe en `alert`/`allowed` par nature, car ce ne sont jamais des règles de blocage par correspondance de paquet. D'où l'inefficacité du critère `action`.

### Fix appliqué

Critère corrigé sur la sous-chaîne `"stealth"` (commune aux deux signatures) combinée à la cible WAN :

```sql
UPDATE utm_correlation_rules
SET rule_definition_def = $$(
  equals("log.eventType", "alert") &&
  equals("severity", "high") &&
  !(equals("target.ip", "192.168.1.203") &&
    contains("log.alert.signature", "stealth"))
)$$
WHERE id = 875;
```

Tout vrai scan furtif visant le réseau LAN (reconnaissance interne réelle) reste détecté — seul le bruit de reconnaissance passive contre le WAN est filtré.

---

## Fix 4 — Règle 525 « Port Scan Detection »

### Diagnostic

```
rule_definition_def:
(
  (equals("log.eventType", "alert") &&
   contains("log.alert.signature", ["scan", "SCAN", "portscan"])) ||
  (equals("protocol", "TCP") &&
   equals("log.tcp.flags", "S") &&
   equals("log.flow.state", "new") &&
   lessThan("log.flow.duration", 1)) ||
  (equals("protocol", "TCP") &&
   oneOf("log.tcp.flags", ["", "F", "FPU"])) ||
  (equals("log.eventType", "anomaly") &&
   contains("log.anomaly.event", "scan"))
)
```

Règle large (4 branches OR). Volume : 241 docs sur 1 mois, **100% sur `target.ip = 192.168.1.203`** (WAN), répartition 151 `blocked` / 90 `allowed`. Même pattern que la règle 876 : le trafic déjà bloqué visant le WAN ne mérite pas de triage manuel.

> ℹ️ Pour ce type de règle comportementale (scan furtif basé sur le timing des paquets), **ne pas passer Suricata en `drop`** — des services légitimes (Google, Azure, CDN) déclenchent régulièrement ces patterns sans intention malveillante. Si une IP est réellement malveillante, elle apparaîtra aussi dans les listes Dshield/CINS/Spamhaus déjà en `drop`. La couche comportementale reste en `alert` comme observateur, pas comme bloqueur.

### Fix appliqué

```sql
UPDATE utm_correlation_rules
SET rule_definition_def = $$(
  (
    (equals("log.eventType", "alert") &&
     contains("log.alert.signature", ["scan", "SCAN", "portscan"])) ||
    (equals("protocol", "TCP") &&
     equals("log.tcp.flags", "S") &&
     equals("log.flow.state", "new") &&
     lessThan("log.flow.duration", 1)) ||
    (equals("protocol", "TCP") &&
     oneOf("log.tcp.flags", ["", "F", "FPU"])) ||
    (equals("log.eventType", "anomaly") &&
     contains("log.anomaly.event", "scan"))
  ) &&
  !(equals("target.ip", "192.168.1.203") &&
    equals("log.alert.action", "blocked"))
)$$
WHERE id = 525;
```

---

## Fix 5 — Règle 1424 « Windows: Suspicious PowerShell (Encoded / Download Cradle / AMSI Bypass) »

### Diagnostic

Règle endpoint (event Windows 4104 = PowerShell ScriptBlock Logging), 3 occurrences sur 1 mois. Toutes issues du même chemin :
```
C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\DataCollection\...\36dc1ba5-....ps1
```

**Fausse alerte** : c'est le **scanner Log4Shell/CVE-2021-44228** intégré à Microsoft Defender for Endpoint, exécuté en tâche de fond par MDE lui-même. Le script contient `Invoke-WebRequestWithRootCaVerification` (contient le mot-clé `Invoke-WebRequest`) et `FromBase64String` (décodage légitime de certificats) — combinaison matchant la deuxième branche regex de détection sans qu'il s'agisse d'une vraie tentative de contournement AMSI.

Ce cas illustre une source de bruit d'une nature différente des précédents : **pas du bruit réseau périmétrique, mais un faux positif endpoint généré par l'outil de sécurité Microsoft lui-même**. Signal à retenir pour tout déploiement SIEM avec MDE : les agents de sécurité endpoint (MDE, CrowdStrike Falcon, etc.) génèrent régulièrement des scripts PowerShell qui peuvent déclencher des règles AMSI/obfuscation — une exclusion par chemin d'exécution est préférable à une désactivation de la règle.

### Fix appliqué

Exclusion ciblée sur le chemin MDE, sans toucher aux deux branches de détection (actives pour tout autre processus) :

```sql
UPDATE utm_correlation_rules
SET rule_definition_def = $$equals("log.eventCode", "4104") &&
(regexMatch("log.eventDataScriptBlockText", "(?i)(amsiutils|amsiinitfailed|amsiscanbuffer|virtualalloc|writeprocessmemory|getdelegateforfunctionpointer|invoke-mimikatz|invoke-shellcode|invoke-dllinjection|createremotethread)") ||
(regexMatch("log.eventDataScriptBlockText", "(?i)(downloadstring|downloadfile|downloaddata|invoke-webrequest|net.webclient|start-bitstransfer)") &&
regexMatch("log.eventDataScriptBlockText", "(?i)(iex|invoke-expression|-enc |-encodedcommand|-w hidden|-windowstyle hidden|frombase64string)"))) &&
!contains("log.data.Path", "Windows Defender Advanced Threat Protection")$$
WHERE id = 1424;
```

> ⚠️ **ID corrigé** — ce fix visait initialement l'ID 1436, qui après un revert de snapshot pointait vers une règle différente ("GCP Firewall Rule Created"). La vraie règle PowerShell vit sous l'ID **1424** en v11.2.11. Voir la section [Les ID de règles ne sont pas stables entre versions](#-les-id-de-règles-ne-sont-pas-stables-entre-versions-utmstack) pour la méthode de recherche utilisée pour la retrouver.

---

## Fix 6 — Règle 876 v2 « Medium level Suricata alert » — deuxième itération

### Diagnostic

Après la mise en place du fix 2 (WAN + `action=blocked`), un nouveau profil de bruit est apparu sur la même règle : le trafic **sortant** légitime d'OPNsense lui-même (mise à jour des définitions Microsoft Defender via *Delivery Optimization*) déclenchait toujours la règle, puisqu'il n'est pas bloqué (`action: allowed`) et ne correspond donc pas à l'exclusion existante.

```
lastEvent.log.alert.signature_id: 2021076
signature: "ET HUNTING SUSPICIOUS Dotted Quad Host MZ Response"
http.http_user_agent: "Microsoft-Delivery-Optimization/10.1" / "10.0"
target.ip: 192.168.1.203 (100% des 36 occurrences)
```

La signature détecte un exécutable Windows (en-tête "MZ") téléchargé depuis un hôte désigné par IP brute plutôt qu'un nom de domaine — un pattern généralement associé à du C2 évitant le DNS. Mais Microsoft Delivery Optimization (le CDN interne de Windows Update) utilise couramment des IP directes pour ses téléchargements, sans lien avec une activité malveillante. Confirmé : 100% des occurrences ont ce User-Agent précis, 100% ciblent le WAN local (donc c'est bien OPNsense qui télécharge, pas une machine tierce qui le contacte).

### Fix appliqué

Ajout d'une exclusion supplémentaire sur le User-Agent, en plus (pas en remplacement) de l'exclusion WAN+blocked du fix 2 :

```sql
UPDATE utm_correlation_rules
SET rule_definition_def = $$(
  equals("log.eventType", "alert") &&
  equals("severity", "medium") &&
  !(equals("target.ip", "192.168.1.203") &&
    equals("log.alert.action", "blocked")) &&
  !contains("log.http.http_user_agent", "Microsoft-Delivery-Optimization")
)$$
WHERE id = 876;
```

---

## Méthode d'application — pattern réutilisable

Pour éviter les problèmes d'échappement de guillemets imbriqués (`$$...$$`, guillemets doubles dans `equals("...")`) à travers `docker exec -c`, le SQL est écrit dans un fichier, copié dans le conteneur, puis exécuté via `-f` :

```bash
# 1. Backup avant modification
docker exec $(docker ps -q -f name=utmstack_postgres) psql -U postgres -d utmstack -c \
"SELECT rule_definition_def FROM utm_correlation_rules WHERE id = <id>;" > /root/backup-rule<id>-$(date +%Y%m%d).txt

# 2. Fichier SQL (via nano)
nano /root/update-rule<id>.sql

# 3. Copie + exécution dans le conteneur
docker cp /root/update-rule<id>.sql $(docker ps -q -f name=utmstack_postgres):/tmp/update-rule<id>.sql
docker exec -i $(docker ps -q -f name=utmstack_postgres) psql -U postgres -d utmstack -f /tmp/update-rule<id>.sql

# 4. Vérification
docker exec $(docker ps -q -f name=utmstack_postgres) psql -U postgres -d utmstack -c \
"SELECT rule_definition_def FROM utm_correlation_rules WHERE id = <id>;"
```

> ℹ️ `docker exec -it` avec une commande non-interactive (`-c "SELECT..."` redirigée vers un fichier) peut sembler « figer » le terminal — c'est en réalité le pager (`less`) du résultat psql qui attend une touche. `q` débloque immédiatement. Pour éviter le piège, ne pas utiliser `-it` quand la sortie est redirigée.

---

## ⚠️ Étape obligatoire — redémarrer les services de corrélation

**Une modification de `utm_correlation_rules` en base ne suffit pas.** Constat fait le 2026-06-30 : malgré un `UPDATE` confirmé en base (vérifié par `SELECT`), une alerte Dshield correspondant exactement au nouveau critère d'exclusion de la règle 876 a continué à être créée plus de 3 heures après l'application du fix.

**Cause identifiée** : `utm_correlation_rules` est lue en mémoire **au démarrage** des services `utmstack_event-processor-worker` et `utmstack_event-processor-manager`, et n'est pas relue à chaud. Tant que ces services tournent depuis avant la modification SQL, ils continuent d'évaluer les alertes avec l'ancienne définition de règle.

**Action requise après tout `UPDATE` sur `utm_correlation_rules`** — redémarrer les deux services, un par un pour limiter le risque (prudence justifiée par un historique d'instabilité Docker Swarm sur ce lab) :

```bash
docker service update --force utmstack_event-processor-worker
docker service ps utmstack_event-processor-worker --no-trunc
# Attendre "Running X secondes ago" sans "Failed", puis :
docker service update --force utmstack_event-processor-manager
docker service ps utmstack_event-processor-manager --no-trunc
```

Validation finale : observer dans le Log Explorer qu'un nouvel événement correspondant au critère d'exclusion n'apparaît plus dans la file Alerts/incidents.

---

## Le backlog historique — pas de nettoyage manuel nécessaire

Les ~118 932 alertes "Tunneling Detection" déjà générées avant le fix ne sont pas supprimées rétroactivement par la modification de règle — celle-ci n'agit que sur les futures alertes.

Vérification de la politique ISM (`_plugins/_ism/policies/utmstack_ism_policy`) :

```json
{
  "name": "open",
  "transitions": [
    {"state_name": "delete", "conditions": {"min_index_age": "30d"}}
  ]
}
```

Rétention fixe à **30 jours** sur les index `v11-alert-*` (template partagé avec `v11-log-*`). Le backlog s'autopurge donc progressivement sans action manuelle, au rythme où chaque index quotidien atteint son seuil d'âge.

> ⚠️ Un nettoyage manuel via `_update_by_query` est possible (changement de `status`/`statusLabel` en masse) mais déconseillé en routine : risque de timeout sur ~30 index, conflits de version avec les processus actifs (cron de purge, SOC-AI), et opération irréversible sur des documents existants. La rétention naturelle à 30 jours est suffisante dans la plupart des cas. Si un nettoyage immédiat est nécessaire, valider d'abord avec `/_count` (non destructif) sur un seul index avant d'élargir à `v11-alert-*`, et utiliser `wait_for_completion=false` + `requests_per_second` pour throttler l'opération.

**Architecture à considérer pour une solution durable** : découpler la politique ISM des alertes (cycle de vie court — objet de triage opérationnel) de celle des logs bruts (cycle de vie long — donnée forensique/historique), plutôt que de partager `utmstack_ism_policy` entre `v11-log-*` et `v11-alert-*`.

---

## ⚠️ Comportement confirmé — réinitialisation des règles au redémarrage

**Constaté empiriquement le 2026-07-01** après un reboot d'UTMStack : les règles `system_owner=true` sont **réinitialisées à leur définition d'origine** au démarrage. Les fixes 530, 525, 875 et 876 ont tous été écrasés. La règle 1436 (PowerShell MDE) a survécu à ce reboot — comportement non encore expliqué, à surveiller.

Ce n'est plus une hypothèse : **tout reboot ou update UTMStack nécessite une réapplication des fixes**.

---

## Automatisation — service systemd de réapplication au démarrage

Plutôt que de réappliquer manuellement après chaque reboot (procédure décrite dans la section précédente), un service systemd gère la réapplication automatiquement.

### Fichiers SQL à conserver dans `/root/utmstack-fixes/`

```bash
mkdir -p /root/utmstack-fixes
cp /root/update-rule530.sql /root/utmstack-fixes/
cp /root/update-rule875.sql /root/utmstack-fixes/
cp /root/update-rule876.sql /root/utmstack-fixes/
cp /root/update-rule525.sql /root/utmstack-fixes/
cp /root/update-rule1424.sql /root/utmstack-fixes/
```

> ℹ️ **Pour un lecteur qui reconstruit ces fichiers depuis zéro** : voici le contenu final et à jour de chacun des 5 fichiers, prêt à copier-coller directement (`nano /root/update-rule<id>.sql`, coller, sauvegarder). Ce sont les mêmes contenus que dans les sections Fix 1 à 6 plus haut — regroupés ici pour éviter d'avoir à les rechercher un par un.

<details>
<summary><strong>update-rule530.sql</strong> (Fix 1 — Tunneling Detection)</summary>

```sql
UPDATE utm_correlation_rules
SET rule_definition_def = $$(
  (equals("log.eventType", "alert") &&
   (contains("log.alert.signature", "SSH") &&
    !equals("target.port", 22))) ||
  (equals("log.appProto", "ssh") &&
   !equals("target.port", 22)) ||
  (equals("protocol", "TCP") &&
   equals("target.port", 443) &&
   !equals("log.appProto", "tls") &&
   !equals("target.ip", "192.168.1.203")) ||
  (equals("log.eventType", "alert") &&
   contains("log.alert.signature", "tunnel")) ||
  (equals("target.port", 53) &&
   equals("protocol", "TCP") &&
   greaterThan("log.flow.bytes_toserver", 5000))
)$$
WHERE id = 530;
```
</details>

<details>
<summary><strong>update-rule875.sql</strong> (Fix 3 — High level Suricata alert)</summary>

```sql
UPDATE utm_correlation_rules
SET rule_definition_def = $$(
  equals("log.eventType", "alert") &&
  equals("severity", "high") &&
  !(equals("target.ip", "192.168.1.203") &&
    contains("log.alert.signature", "stealth"))
)$$
WHERE id = 875;
```
</details>

<details>
<summary><strong>update-rule876.sql</strong> (Fix 6 — version finale, remplace le Fix 2)</summary>

```sql
UPDATE utm_correlation_rules
SET rule_definition_def = $$(
  equals("log.eventType", "alert") &&
  equals("severity", "medium") &&
  !(equals("target.ip", "192.168.1.203") &&
    equals("log.alert.action", "blocked")) &&
  !contains("log.http.http_user_agent", "Microsoft-Delivery-Optimization")
)$$
WHERE id = 876;
```
</details>

<details>
<summary><strong>update-rule525.sql</strong> (Fix 4 — Port Scan Detection)</summary>

```sql
UPDATE utm_correlation_rules
SET rule_definition_def = $$(
  (
    (equals("log.eventType", "alert") &&
     contains("log.alert.signature", ["scan", "SCAN", "portscan"])) ||
    (equals("protocol", "TCP") &&
     equals("log.tcp.flags", "S") &&
     equals("log.flow.state", "new") &&
     lessThan("log.flow.duration", 1)) ||
    (equals("protocol", "TCP") &&
     oneOf("log.tcp.flags", ["", "F", "FPU"])) ||
    (equals("log.eventType", "anomaly") &&
     contains("log.anomaly.event", "scan"))
  ) &&
  !(equals("target.ip", "192.168.1.203") &&
    equals("log.alert.action", "blocked"))
)$$
WHERE id = 525;
```
</details>

<details>
<summary><strong>update-rule1424.sql</strong> (Fix 5 — PowerShell / MDE, ID vérifié au 2026-07-02)</summary>

```sql
UPDATE utm_correlation_rules
SET rule_definition_def = $$equals("log.eventCode", "4104") &&
(regexMatch("log.eventDataScriptBlockText", "(?i)(amsiutils|amsiinitfailed|amsiscanbuffer|virtualalloc|writeprocessmemory|getdelegateforfunctionpointer|invoke-mimikatz|invoke-shellcode|invoke-dllinjection|createremotethread)") ||
(regexMatch("log.eventDataScriptBlockText", "(?i)(downloadstring|downloadfile|downloaddata|invoke-webrequest|net.webclient|start-bitstransfer)") &&
regexMatch("log.eventDataScriptBlockText", "(?i)(iex|invoke-expression|-enc |-encodedcommand|-w hidden|-windowstyle hidden|frombase64string)"))) &&
!contains("log.data.Path", "Windows Defender Advanced Threat Protection")$$
WHERE id = 1424;
```

> ⚠️ Avant d'appliquer ce fichier sur une instance différente de ce lab (ou après tout revert de snapshot), vérifier que l'ID 1424 correspond bien à cette règle — voir la section [Les ID de règles ne sont pas stables entre versions](#-les-id-de-règles-ne-sont-pas-stables-entre-versions-utmstack).
</details>

### Script `/usr/local/bin/utmstack-fix-rules.sh`

```bash
#!/bin/bash
# Réapplication automatique des fixes de règles de corrélation UTMStack
# Comportement confirmé : UTMStack réinitialise utm_correlation_rules
# au démarrage pour les règles system_owner=true (530, 525, 875, 876)

LOG="/var/log/utmstack-fix-rules.log"
echo "$(date) — Démarrage réapplication des fixes de règles" >> $LOG

# Attendre que PostgreSQL soit prêt (timeout 300s)
TIMEOUT=300
ELAPSED=0
POSTGRES_ID=""

while true; do
  POSTGRES_ID=$(docker ps -q -f name=utmstack_postgres)
  if [ -n "$POSTGRES_ID" ]; then
    docker exec $POSTGRES_ID psql -U postgres -d utmstack -c "SELECT 1" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
      break
    fi
  fi
  sleep 5
  ELAPSED=$((ELAPSED + 5))
  if [ $ELAPSED -ge $TIMEOUT ]; then
    echo "$(date) — ERREUR : timeout attente PostgreSQL après ${TIMEOUT}s" >> $LOG
    exit 1
  fi
done

echo "$(date) — PostgreSQL prêt après ${ELAPSED}s" >> $LOG

# Réappliquer les fixes
for sql in update-rule530.sql update-rule875.sql update-rule876.sql update-rule525.sql update-rule1424.sql; do
  if [ -f "/root/utmstack-fixes/$sql" ]; then
    docker cp /root/utmstack-fixes/$sql $POSTGRES_ID:/tmp/$sql
    docker exec -i $POSTGRES_ID psql -U postgres -d utmstack -f /tmp/$sql >> $LOG 2>&1
    echo "$(date) — Fix appliqué : $sql" >> $LOG
  else
    echo "$(date) — ERREUR : fichier manquant /root/utmstack-fixes/$sql" >> $LOG
  fi
done

# Attendre 120s que Docker Swarm et les event-processor soient stables
echo "$(date) — Attente 120s avant redémarrage des event-processor" >> $LOG
sleep 120

echo "$(date) — Redémarrage event-processor-worker" >> $LOG
docker service update --force utmstack_event-processor-worker >> $LOG 2>&1

echo "$(date) — Attente 30s avant redémarrage event-processor-manager" >> $LOG
sleep 30

echo "$(date) — Redémarrage event-processor-manager" >> $LOG
docker service update --force utmstack_event-processor-manager >> $LOG 2>&1

echo "$(date) — Terminé — fixes de règles appliqués avec succès" >> $LOG
```

```bash
chmod +x /usr/local/bin/utmstack-fix-rules.sh
```

### Service systemd `/etc/systemd/system/utmstack-fix-rules.service`

```ini
[Unit]
Description=UTMStack — Réapplication des fixes de règles de corrélation
After=docker.service
Requires=docker.service
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/utmstack-fix-rules.sh
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable utmstack-fix-rules.service
```

### Vérification

```bash
systemctl status utmstack-fix-rules.service
# Attendu : enabled + active (exited) + status=0/SUCCESS

tail -50 /var/log/utmstack-fix-rules.log
```

### Timings observés (post-reboot, 2026-07-01)

- PostgreSQL prêt : immédiat si UTMStack était déjà stable, jusqu'à ~60s après un cold boot
- 4 `UPDATE 1` en séquence : ~1 seconde
- Attente 120s : laisse Docker Swarm stabiliser tous les services
- Redémarrage worker : ~20s pour converger
- Attente 30s
- Redémarrage manager : ~20s pour converger
- **Durée totale : ~3 minutes**

> ℹ️ Le service est `oneshot` — il s'exécute une fois au démarrage puis reste en état `active (exited)`. C'est le comportement attendu, pas une erreur.

---

## ⚠️ Les ID de règles ne sont pas stables entre versions UTMStack

**Incident du 2026-07-01/02** : après un revert vers un snapshot antérieur (v11.2.8) puis une remise à jour vers v11.2.11, le fix prévu pour l'ID **1436** ("Windows: Suspicious PowerShell...") s'est retrouvé appliqué à une règle totalement différente — **"GCP Firewall Rule Created — Open Ingress"**. Entre les versions, UTMStack avait réattribué cet ID à une autre règle ; la vraie règle PowerShell vivait désormais sous l'ID **1424**.

Un script qui réapplique un fix par `UPDATE ... WHERE id = X` **sans vérifier au préalable que `X` correspond toujours au bon `rule_name`** peut donc silencieusement corrompre une règle sans rapport. C'est arrivé une fois dans ce lab — voir plus bas la procédure de retour en arrière pour ce cas précis.

### Méthode de recherche — retrouver une règle après un changement d'ID

Ne jamais appliquer un `UPDATE ... WHERE id = X` sur une règle `system_owner=true` sans avoir d'abord confirmé son identité. La méthode utilisée dans ce lab, à chaque fois qu'un ID semblait suspect :

**Étape 1 — Chercher par nom plutôt que par ID.** Le `rule_name` est plus stable que l'`id` entre versions (mais pas garanti à 100% non plus — vérifier aussi le contenu si un doute persiste) :

```bash
docker exec $(docker ps -q -f name=utmstack_postgres) psql -U postgres -d utmstack -c \
"SELECT id, rule_name FROM utm_correlation_rules WHERE rule_name ILIKE '%PowerShell%';"
```

Si plusieurs résultats correspondent (cas réel rencontré : 4 règles contenant "PowerShell"), identifier la bonne par son `rule_category` et par un extrait de sa `rule_definition_def` :

```bash
docker exec $(docker ps -q -f name=utmstack_postgres) psql -U postgres -d utmstack -x -c \
"SELECT id, rule_name, rule_category, rule_definition_def FROM utm_correlation_rules WHERE id IN (1424,1140,1362,1341);"
```

**Étape 2 — Avant d'appliquer un `UPDATE`, toujours vérifier ce qu'il y a déjà à cet ID.** Une simple lecture avant écriture aurait évité l'incident du 1436 :

```bash
docker exec $(docker ps -q -f name=utmstack_postgres) psql -U postgres -d utmstack -x -c \
"SELECT id, rule_name, rule_definition_def FROM utm_correlation_rules WHERE id = 1436;"
```

Si le `rule_name` retourné ne correspond pas à ce qu'on s'apprête à modifier, **s'arrêter** — l'ID a bougé, il faut relancer l'étape 1.

**Étape 3 — Si une règle a été écrasée par erreur**, deux options selon la disponibilité de sa vraie définition d'origine :
- Si elle est retrouvable (recherche externe, autre instance, contact communautaire UTMStack) : la restaurer avec un `UPDATE` normal.
- Si elle est introuvable et que la règle ne s'applique pas à l'environnement actuel (ex : règle cloud GCP dans un lab sans source GCP configurée) : la désactiver proprement plutôt que la laisser dans un état incohérent :
  ```bash
  docker exec $(docker ps -q -f name=utmstack_postgres) psql -U postgres -d utmstack -c \
  "UPDATE utm_correlation_rules SET rule_active = false WHERE id = <id>;"
  ```
  C'est réversible et explicite — préférable à une règle active dont le nom et la logique ne correspondent plus.

### Conséquence pour le script d'automatisation

Le script `utmstack-fix-rules.sh` (section précédente) applique ses `UPDATE` par ID, sans cette vérification de nom — c'est un choix assumé pour la vitesse d'exécution automatique au démarrage, mais **le fichier SQL de chaque fix doit être revalidé manuellement (étape 1 et 2 ci-dessus) après tout revert de snapshot vers une version différente**, avant de laisser le service tourner en confiance. Un revert n'est pas un reboot ordinaire — c'est le seul scénario où ce lab a rencontré une dérive d'ID.

**État actuel des IDs vérifiés dans ce lab (v11.2.11, au 2026-07-02) :**

| Règle | ID | rule_name |
|---|---|---|
| Tunneling Detection | 530 | Tunneling Detection |
| High level Suricata alert | 875 | High level Suricata alert |
| Medium level Suricata alert | 876 | Medium level Suricata alert |
| Port Scan Detection | 525 | Port Scan Detection |
| Windows Suspicious PowerShell | **1424** *(anciennement 1436)* | Windows: Suspicious PowerShell (Encoded / Download Cradle / AMSI Bypass) |
| GCP Firewall Rule Created | 1436 | GCP Firewall Rule Created — Open Ingress *(désactivée, `rule_active = false` — définition d'origine non restaurée après collision d'ID)* |

---

## ⚠️ Checklist post-reboot / post-update UTMStack

**Comportement confirmé empiriquement le 2026-07-01** : un reboot UTMStack réinitialise les règles `system_owner=true` à leur définition d'origine. Les fixes 530, 525, 875 et 876 ont tous été écrasés. La règle 1424 (PowerShell) a survécu à ce reboot précis — comportement non systématique, à ne pas présumer.

**Depuis le 2026-07-01**, le service `utmstack-fix-rules` gère automatiquement la réapplication au démarrage — voir section précédente. La vérification manuelle ci-dessous reste utile après un update majeur, un revert de snapshot, ou en cas de doute :

```bash
# Vérifier l'état du service après chaque reboot
systemctl status utmstack-fix-rules.service
# Attendu : enabled + active (exited) + status=0/SUCCESS

# Consulter le log d'exécution
tail -50 /var/log/utmstack-fix-rules.log

# Vérification manuelle des définitions si doute — par nom, pas seulement par ID
docker exec $(docker ps -q -f name=utmstack_postgres) psql -U postgres -d utmstack -c \
"SELECT id, rule_name FROM utm_correlation_rules WHERE id IN (530,875,876,525,1424);"
```

Si un fix est manquant, forcer une réexécution du service :

```bash
systemctl start utmstack-fix-rules.service
tail -f /var/log/utmstack-fix-rules.log
```

---

| [← Règles Suricata avancées](07-custom-rules.md) | [→ SOC AI](06-soc-ai.md) |
