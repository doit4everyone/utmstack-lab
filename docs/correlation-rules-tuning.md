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

## ⚠️ Checklist post-update UTMStack

Les règles modifiées (530, 875, 876) ont `system_owner = true` : elles sont fournies par UTMStack, pas créées par l'utilisateur. La persistance du fix à travers une montée de version d'UTMStack n'a pas encore pu être confirmée empiriquement (pattern courant sur ce type de table dans un produit versionné : réécriture/re-seed des définitions built-in à chaque update). À noter : `UTMStackComponentsUpdater` a fait passer ce lab de v11.2.10 à v11.2.11 automatiquement, en tâche de fond, sans action manuelle ni notification — confirmé via l'image des conteneurs `event-processor-*` (`docker service ps ... --no-trunc`).

**Procédure de vérification à exécuter après chaque update UTMStack**, en complément de la vérification de version déjà en place (`curl api.github.com/repos/utmstack/UTMStack/releases/tags/vX.X.X`) :

1. **Vérifier les définitions de règles** :
   ```bash
   docker exec $(docker ps -q -f name=utmstack_postgres) psql -U postgres -d utmstack -c \
   "SELECT id, rule_name, rule_definition_def FROM utm_correlation_rules WHERE id IN (530,875,876);" \
   > /root/post-update-check-$(date +%Y%m%d).txt

   diff /root/post-update-check-$(date +%Y%m%d).txt /root/verify-875-876.txt
   ```
   Si le `diff` montre un écart, relancer les fichiers `update-rule530.sql`, `update-rule875.sql`, `update-rule876.sql` déjà préparés (voir section méthode d'application ci-dessus). Conserver ces trois fichiers dans un emplacement durable (ex: `/root/utmstack-fixes/`) plutôt que dans `/tmp`.

2. **Redémarrer les services de corrélation systématiquement après tout update**, même si le `diff` ne montre aucun écart — un update remplace de toute façon les conteneurs `event-processor-worker`/`event-processor-manager`, ce qui revient à un rechargement à froid des règles. Cette étape est donc generalement déjà couverte par l'update lui-même, mais à vérifier explicitement (voir section précédente) si les fixes ne semblent pas effectifs après coup.

---

| [← Règles Suricata avancées](07-custom-rules.md) | [→ SOC AI](06-soc-ai.md) |
