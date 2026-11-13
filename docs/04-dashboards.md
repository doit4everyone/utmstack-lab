---
title: "Chapitre 04 : Tableaux de bord Suricata, NF Scanners, CrowdSec et NTLM | DoIt4Everyone"
description: "Visualisations et tableaux de bord UTMStack v11.3.0 CE : champs filtrables et agrégeables après le passage à event.*, création et réparation des visualisations en SQL, cartes des adresses bloquées, rapport des scanners NF, bans CrowdSec et audit NTLM."
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

# Chapitre 04 : Tableaux de bord UTMStack

> [← Retour à l'index](../)

## Sommaire

- [Ce que la v11.3.0 change pour les visualisations](#ce-que-la-v1130-change-pour-les-visualisations)
- [Où UTMStack stocke les visualisations](#où-utmstack-stocke-les-visualisations)
- [Créer une visualisation : interface ou SQL](#créer-une-visualisation--interface-ou-sql)
- [Réparer les visualisations après une rupture de schéma](#réparer-les-visualisations-après-une-rupture-de-schéma)
- [Tableau de bord Suricata](#tableau-de-bord-suricata)
- [Cartes des adresses bloquées](#cartes-des-adresses-bloquées)
- [Rapport des scanners NF](#rapport-des-scanners-nf)
- [Tableau de bord CrowdSec](#tableau-de-bord-crowdsec)
- [Tableau de bord NTLM](#tableau-de-bord-ntlm)
- [Ce qui ne peut plus être affiché](#ce-qui-ne-peut-plus-être-affiché)
- [Tester les visualisations](#tester-les-visualisations)

---

> ⚠️ **Ce chapitre décrit l'état v11.3.0 du lab (novembre 2026).** La version précédente, écrite pour UTMStack v11.2.8 (champs `log.*`, création pas à pas dans l'interface), reste disponible dans la release [`v11.2-final`](https://github.com/doit4everyone/utmstack-lab/releases/tag/v11.2-final) du dépôt.

Ce chapitre documente les tableaux de bord construits dans le lab pour suivre Suricata (chapitre 02), les règles NF de détection des scanners, les bans CrowdSec posés par le SOAR (chapitres 03 et 05) et l'audit NTLM (chapitre 08). Toutes les visualisations décrites ici sont en service et ont été vérifiées sur des données réelles.

---

## Ce que la v11.3.0 change pour les visualisations

La v11.3.0 remplace le sac de champs `log.*` par `event.*`, indexé en `flat_object` dans OpenSearch (voir le [chapitre 11](11-correlations-yaml.html#migration-utmstack-v1130)). Pour les visualisations, la conséquence tient en une phrase : **un champ `event.*` se filtre, mais ne s'agrège pas.**

| Usage | Champ `event.*` (flat_object) | Champ typé (`origin.*`, `target.*`, `dataSource`) |
|---|---|---|
| Filtre « IS » / « IS_NOT » | ✅ fonctionne | ✅ fonctionne |
| Filtre « CONTAIN » sur `raw` | ✅ fonctionne | sans objet |
| Regroupement (TERMS) d'un graphique, d'une table ou d'une carte | ❌ résultat vide, sans message d'erreur | ✅ fonctionne, avec le sous-champ `.keyword` pour les champs texte |

Une visualisation qui regroupe sur `event.alert.signature` ou `event.eventType` ne renvoie donc rien, sans le moindre message. C'est ce qui rend une rupture de schéma difficile à repérer : le tableau de bord s'affiche, simplement vide.

Champs agrégeables vérifiés dans le lab :

| Champ | Index | Usage |
|---|---|---|
| `origin.ip.keyword` | Suricata, O365, pfSense, NetFlow | top des adresses, cartes |
| `origin.geolocation.aso.keyword` | Suricata | top des fournisseurs (organisation propriétaire de l'adresse) |
| `origin.geolocation.country.keyword` | Suricata, O365 | top des pays (nom complet) |
| `origin.geolocation.countryCode.keyword` | Suricata | top des pays (code ISO) |
| `origin.geolocation.city.keyword` | Suricata | nombre de villes |
| `dataSource.keyword` | tous | machine ou équipement qui a envoyé l'événement |
| `raw.keyword` | syslog | liste des messages bruts (bans CrowdSec) |
| `@timestamp` | tous | chronologies (DATE_HISTOGRAM) |

> ℹ️ Les champs `origin.geolocation.latitude` et `longitude` existent (type `float`), mais les cartes d'UTMStack ne s'en servent pas. Voir [Cartes des adresses bloquées](#cartes-des-adresses-bloquées).

---

## Où UTMStack stocke les visualisations

Les visualisations sont des lignes de la table PostgreSQL **`utm_visualization`**. Celles du système (`system_owner = true`) portent des ID bas. Celles créées dans le lab commencent à **1000000**.

| Colonne | Contenu |
|---|---|
| `name` | nom affiché |
| `chart_type` | `METRIC_CHART`, `LINE_CHART`, `HORIZONTAL_BAR_CHART`, `PIE_CHART`, `TABLE_CHART`, `COORDINATE_MAP_CHART` |
| `id_pattern` | index interrogé (référence vers le motif d'index) |
| `filters` | filtres en JSON : opérateurs `IS`, `IS_NOT`, `CONTAIN`, `IS_BETWEEN` |
| `aggregation` | métrique (COUNT) et regroupement éventuel (TERMS, DATE_HISTOGRAM) en JSON |
| `chart_config` | options d'affichage (couleurs, légende, fond de carte) |
| `system_owner` | `true` pour les visualisations livrées par UTMStack |

Les valeurs de `id_pattern` relevées dans le lab :

| `id_pattern` | Index |
|---|---|
| 68 | `v11-log-suricata-*` |
| 62 | `v11-log-syslog-*` |
| 8 | `v11-log-wineventlog-*` |
| 12 | `v11-log-o365-*` |

> ⚠️ Ces numéros sont propres à chaque installation. Pour connaître le bon, reprendre celui d'une visualisation existante sur le même index plutôt que de le recopier d'ici.

L'accès à la base passe par le conteneur PostgreSQL :

```bash
PG=$(docker ps -qf name=postgres | head -1)
docker exec -i $PG psql -U postgres -d utmstack
```

---

## Créer une visualisation : interface ou SQL

L'interface (Dashboards → New Visualization) reste la voie normale pour une visualisation simple : un compteur, une chronologie, un top. Ses listes de champs proposent cependant aussi les champs `event.*`, qui donnent un graphique vide une fois choisis comme regroupement.

Pour une visualisation plus délicate, en particulier une carte, le lab utilise une autre méthode : **copier en SQL une visualisation système qui fonctionne**, et ne changer que le nom, l'index et les filtres. Le format de `chart_config`, que l'interface attend à l'identique, est ainsi repris tel quel.

Exemple, la carte des adresses bloquées par Suricata, copiée de la carte système « pfSense Traffic Geolocation » (ID 850) :

```bash
docker exec -i $PG psql -U postgres -d utmstack <<'SQL'
BEGIN;
INSERT INTO utm_visualization
  (id, name, description, created_date, user_created, chart_config, chart_type,
   filters, id_pattern, aggregation, event_type, chart_action, system_owner)
SELECT
  (SELECT MAX(id) + 1 FROM utm_visualization WHERE id >= 1000000),
  'Suricata - Blocked IPs Map',
  'Adresses sources des flux bloqués par Suricata (règles NF et ET)',
  NOW(), 'admin', v.chart_config, v.chart_type,
  '[{"operator":"IS_BETWEEN","field":"@timestamp","value":["now-24h","now"]},{"operator":"IS","field":"event.alert.action","value":"blocked"}]',
  (SELECT id_pattern FROM utm_visualization WHERE name = 'Top 10 blocked Suricata'),
  v.aggregation, NULL, v.chart_action, false
FROM utm_visualization v WHERE v.id = 850;
SELECT id, name, chart_type, id_pattern FROM utm_visualization WHERE name = 'Suricata - Blocked IPs Map';
COMMIT;
SQL
```

Le `heredoc` (`<<'SQL'`) évite d'avoir à échapper les guillemets du JSON. La visualisation créée apparaît dans Dashboards → Visualization List, et s'ajoute à un tableau de bord en mode édition.

---

## Réparer les visualisations après une rupture de schéma

Après le passage à la v11.3.0, toutes les visualisations du lab qui utilisaient `log.*` étaient vides. La réparation se fait en quatre temps.

**1. Sauvegarder la table**, pour pouvoir revenir en arrière :

```sql
CREATE TABLE IF NOT EXISTS utm_visualization_bak_20261112 AS SELECT * FROM utm_visualization;
```

**2. Lister les visualisations concernées :**

```sql
SELECT id, name FROM utm_visualization
WHERE id >= 1000000 AND (filters LIKE '%log.%' OR aggregation LIKE '%log.%')
ORDER BY id;
```

**3. Corriger, dans une transaction, filtre par filtre et regroupement par regroupement.** Le traitement diffère selon l'endroit où le champ est utilisé :

| Ancien usage | Correction |
|---|---|
| filtre sur `log.xxx` | même filtre sur `event.xxx` (filtrer fonctionne toujours) |
| regroupement sur `log.xxx` avec un équivalent typé | regroupement sur le champ typé : `origin.geolocation.aso.keyword`, `origin.ip.keyword`, `dataSource.keyword` |
| regroupement sur `log.xxx` sans équivalent | pas de correction possible : voir [Ce qui ne peut plus être affiché](#ce-qui-ne-peut-plus-être-affiché) |

Exemple pour un filtre :

```sql
UPDATE utm_visualization
SET filters = '[{"operator":"IS_BETWEEN","field":"@timestamp","value":["now-24h","now"]},{"operator":"IS","field":"event.alert.action","value":"blocked"}]',
    modified_date = NOW()
WHERE id = 1000017;
```

**4. Relancer la requête de l'étape 2.** Elle ne doit plus renvoyer que les visualisations sans correction possible. Recharger ensuite les tableaux de bord (Ctrl+F5) et vérifier qu'ils affichent des valeurs.

> 💡 Une visualisation vide n'est pas forcément cassée : sur 24 heures, certains compteurs peuvent valoir réellement 0. Pour trancher, comparer avec une requête OpenSearch sur la même période (voir [Tester les visualisations](#tester-les-visualisations)).

---

## Tableau de bord Suricata

Toutes les visualisations portent sur `v11-log-suricata-*` et sur les 24 dernières heures.

| Visualisation | Type | Filtre | Regroupement |
|---|---|---|---|
| Suricata - Total Alertes | compteur | `event.eventType` = `alert` | |
| Drops IPS Suricata | compteur | `event.eventType` = `drop` | |
| Blocked IPS Suricata | compteur | `event.eventType` = `alert` et `event.alert.action` = `blocked` | |
| allowed IPS Suricata | compteur | `event.alert.action` = `allowed` | |
| Top 10 blocked Suricata | barres | `alert` et `blocked` | `origin.geolocation.aso.keyword` |
| Suricata - Timeline Alertes | courbe | `event.eventType` = `alert` | `@timestamp` par heure |
| Suricata - Top Source IPs | barres | `event.eventType` = `alert` | `origin.ip.keyword` |
| Suricata - Top Pays | barres | `event.eventType` = `alert` | `origin.geolocation.country.keyword` |
| Suricata - Top Pays (codes ISO) | barres | `event.eventType` = `alert` | `origin.geolocation.countryCode.keyword` |
| Suricata - Top ASO Sources | barres | `event.eventType` = `alert` | `origin.geolocation.aso.keyword` |
| Suricata - Top Ports Cibles | barres | `event.eventType` = `alert` | `target.port` |
| Suricata - Blocked IPs Map | carte | `event.alert.action` = `blocked` | `origin.ip.keyword` |

### Lire les trois compteurs

Les trois compteurs du haut ne comptent pas la même chose :

- **Blocked** compte les **alertes** des règles en mode `drop` (règles NF, Spamhaus, Dshield, CINS) : une alerte par flux bloqué.
- **Drops IPS** compte les **paquets** supprimés par Suricata en mode IPS (`event.eventType` = `drop`).
- **Allowed** compte les alertes des règles restées en mode `alert` : le flux est signalé mais passe. C'est sur cette population que le SOAR intervient (chapitre 05, flow 5002).

> ⚠️ **Piège : un événement `drop` porte aussi l'alerte.** Quand c'est une règle qui supprime le paquet, Suricata joint à l'événement `drop` le bloc `alert` de la règle, avec `action` = `blocked`, la signature et le sid. Un filtre sur `event.alert.action` = `blocked` seul compte donc à la fois les alertes et les paquets supprimés, et le même scan est compté plusieurs fois. Le 13 novembre 2026, sur 24 heures, ce filtre renvoyait 1 471 événements : 684 alertes et 787 drops. D'où le filtre supplémentaire `event.eventType` = `alert` sur toutes les visualisations « blocked » qui comptent des alertes.

Ajout du filtre en une fois, dans une transaction :

```sql
UPDATE utm_visualization
SET filters = (filters::jsonb || '[{"operator":"IS","field":"event.eventType","value":"alert"}]'::jsonb)::text,
    modified_date = NOW()
WHERE name IN ('Blocked IPS Suricata', 'Top 10 blocked Suricata', 'Suricata - Count NF Blocked', 'Suricata - Top NF Scanners')
  AND filters NOT LIKE '%"event.eventType"%';
```

Pour les cartes, le filtre ne change rien : les alertes et les drops d'un même flux ont la même adresse source.

---

## Cartes des adresses bloquées

### Fonctionnement des cartes UTMStack

Les cartes (`COORDINATE_MAP_CHART`) ne lisent pas la latitude et la longitude des événements. Elles **regroupent les événements par `origin.ip.keyword`**, et c'est l'interface qui place ensuite chaque adresse sur un fond OpenStreetMap. Toutes les cartes livrées par UTMStack sont construites ainsi (O365, pfSense, NetFlow, GCP).

Une carte construite sur `origin.geolocation.latitude` et `longitude` reste donc vide. C'est probablement ce qui empêchait la carte « Threat Map » de la version v11.2 du lab de s'afficher, d'où la remarque de l'époque selon laquelle les cartes ne fonctionnaient pas.

Deux conditions suffisent pour qu'une carte fonctionne :

1. l'index contient un champ `origin.ip` agrégeable (`origin.ip.keyword`) ;
2. la visualisation reprend le `chart_config` d'une carte système, d'où la méthode par copie SQL décrite plus haut.

### Cartes du lab

| Carte | Filtre |
|---|---|
| Suricata - Blocked IPs Map | `event.alert.action` = `blocked` |
| Suricata - NF Scanners Map | `event.alert.action` = `blocked` et `raw` contient `NF` |

La seconde se crée comme la première, en reprenant les filtres de « Suricata - Count NF Blocked » :

```bash
docker exec -i $PG psql -U postgres -d utmstack <<'SQL'
BEGIN;
INSERT INTO utm_visualization
  (id, name, description, created_date, user_created, chart_config, chart_type,
   filters, id_pattern, aggregation, event_type, chart_action, system_owner)
SELECT
  (SELECT MAX(id) + 1 FROM utm_visualization WHERE id >= 1000000),
  'Suricata - NF Scanners Map',
  'Adresses sources des scanners bloqués par les règles NF',
  NOW(), 'admin', v.chart_config, v.chart_type,
  (SELECT filters FROM utm_visualization WHERE name = 'Suricata - Count NF Blocked'),
  v.id_pattern, v.aggregation, NULL, v.chart_action, false
FROM utm_visualization v WHERE v.name = 'Suricata - Blocked IPs Map';
COMMIT;
SQL
```

Une carte des drops (`event.eventType` = `drop`) a aussi été essayée. Elle affichait exactement les mêmes points que la carte des alertes bloquées, pour la raison expliquée plus haut (un drop porte l'alerte de la règle), et a été retirée.

### Pourquoi si peu de points

La carte paraît pauvre comparée aux compteurs. Les chiffres du 13 novembre 2026 sur 24 heures expliquent l'écart :

| Mesure | Valeur |
|---|---|
| Événements `blocked` (alertes et drops) | 1 481 |
| Adresses distinctes | 129 |
| Fournisseurs distincts | 41 |
| Villes distinctes (environ le nombre de points) | 24 |
| Part des 10 premières adresses | 57 % |
| Part d'un seul fournisseur de scans (5 adresses) | 31 % |

Trois effets se cumulent :

- un scanner teste des dizaines de ports, et chaque sonde bloquée crée une alerte et un ou plusieurs drops : environ 11 événements par adresse en moyenne ;
- le volume est très concentré : une poignée de moteurs de recherche d'équipements exposés (de la famille de Shodan ou Censys) produit la majorité des événements ;
- la carte place chaque adresse à la ville de sa géolocalisation (celle du centre de données, par exemple Toronto pour une adresse DigitalOcean), et toutes les adresses d'un même hébergeur dans une même ville se superposent. Il faut souvent zoomer pour distinguer un point posé près d'une frontière ou d'un lac.

C'est le bruit de fond normal d'une adresse publique, et pas une attaque distribuée. Le vrai signal d'un changement serait une hausse soudaine du nombre d'**adresses distinctes**, plus que du nombre d'événements. Les chiffres ci-dessus s'obtiennent par cette requête :

```bash
docker exec -i $(docker ps -qf name=utmstack_node1|head -1) curl -sk -K - -H 'Content-Type: application/json' \
  'https://localhost:9200/v11-log-suricata-*/_search?filter_path=hits.total,aggregations' \
  -d '{"size":0,"track_total_hits":true,"query":{"bool":{"filter":[{"term":{"event.alert.action":"blocked"}},{"range":{"@timestamp":{"gte":"now-24h"}}}]}},"aggs":{"ip":{"cardinality":{"field":"origin.ip.keyword"}},"villes":{"cardinality":{"field":"origin.geolocation.city.keyword"}},"aso":{"cardinality":{"field":"origin.geolocation.aso.keyword"}},"top10":{"terms":{"field":"origin.ip.keyword","size":10}}}}' < /root/.os.curl
```

> ℹ️ `-K - < /root/.os.curl` transmet les identifiants OpenSearch par l'entrée standard, depuis un fichier lisible par root seul (`chmod 600`), pour qu'ils n'apparaissent ni dans la ligne de commande ni dans l'historique. Le fichier contient une seule ligne : `user = "admin:<mot de passe>"`.

---

## Rapport des scanners NF

Les règles NF (chapitre 02) reconnaissent les scanners connus par leurs adresses publiées. Le tableau de bord « Suricata NF Scanner report » ne montre que les alertes de ces règles, repérées par le préfixe `NF` du nom de la signature dans `raw`.

| Visualisation | Type | Filtre | Regroupement |
|---|---|---|---|
| Suricata - Count NF Blocked | compteur | `alert`, `blocked` et `raw` contient `NF` | |
| Suricata - Top NF Scanners | barres | `alert`, `blocked` et `raw` contient `NF` | `origin.geolocation.aso.keyword` (13 premiers) |
| Suricata - Rapport Scanner | table | `alert`, `blocked` et `raw` contient `NF` | `origin.ip.keyword` (15 premières) |
| Suricata - NF Scanners Map | carte | `blocked` et `raw` contient `NF` | `origin.ip.keyword` |

> ℹ️ Le filtre `CONTAIN` sur `raw` fonctionne dans les visualisations. Dans une requête OpenSearch directe, en revanche, `match_phrase` et `wildcard` sur `raw` renvoient 0 : voir le [chapitre 11](11-correlations-yaml.html#diagnostiquer-dans-opensearch).

---

## Tableau de bord CrowdSec

Le script `soar_ban.sh` (chapitre 05) émet un message syslog à chaque ban posé par le SOAR :

```
<169>Nov 13 08:54:10 ms.lab.local crowdsec[40253]: CROWDSEC_BAN {"event_type":"ban","ip":"198.51.100.41","reason":"utmstack","country":"BG","as":"201814","type":"ban"}
```

Ces messages arrivent dans `v11-log-syslog-*`. Le filtre syslog d'UTMStack n'en extrait que l'hôte (`origin.host`) et le processus (`origin.process`). Le reste du message, adresse bannie comprise, reste du texte dans `raw` et `event.message`.

| Visualisation | Type | Filtre | Regroupement |
|---|---|---|---|
| CrowdSec - Total Bans | compteur | `raw` contient `CROWDSEC_BAN` | |
| CrowdSec - Timeline Bans | courbe | `raw` contient `CROWDSEC_BAN` | `@timestamp` par heure |
| CrowdSec - Derniers Bans | table | `raw` contient `CROWDSEC_BAN` | `raw.keyword` (50 derniers) |
| CrowdSec - Top Pays | barres | `raw` contient `CROWDSEC_BAN` | `crowdsec_country.keyword` (ingest pipeline, voir plus bas) |

> ⚠️ **Pas de carte des bans CrowdSec en l'état.** Les événements n'ont pas de champ `origin.ip`, et la carte n'a rien sur quoi regrouper. Les adresses bannies par le SOAR viennent toutes d'alertes Suricata ou « Known Malicious IP » : la carte « Blocked IPs » de Suricata montre déjà, pour l'essentiel, leur origine.

<!-- À COMPLÉTER : ingest pipeline crowdsec-country (existe, mais n'est plus appliqué aux index v11-log-syslog-* en v11.3.0) ; extension à origin.ip et carte CrowdSec, après validation. Visualisation 1000012 « Top Pays » CrowdSec vide pour la même raison. -->

---

## Tableau de bord NTLM

Le tableau de bord « Audit NTLM » suit les événements du journal `Microsoft-Windows-NTLM/Operational`, transférés vers `ForwardedEvents` par l'abonnement WEF décrit au [chapitre 08](08-ntlm-audit.html).

| Visualisation | Type | Filtre | Regroupement |
|---|---|---|---|
| NTLM - Total Authentifications | compteur, 7 jours | `event.providerName` = `Microsoft-Windows-NTLM` | |
| NTLM - NTLMv1 Detected | compteur, 7 jours | idem et `event.data.NtlmVersion` = `NTLMv1` | |
| NTLM - Failed Auth | compteur, 24 h | idem et `event.data.StatusMsg` différent de `0` | |
| NTLM - Top Machines | barres, 7 jours | idem | `dataSource.keyword` |

Un tableau de bord NTLM vide ne signifie pas forcément une panne de collecte. Dans le lab, il est resté vide plusieurs jours de suite alors que les contrôleurs de domaine journalisaient des événements NTLM. Ces événements portaient des ID que l'abonnement WEF ne transmettait pas (4032 notamment, voir le chapitre 08). Pour distinguer les deux cas, compter les événements à la source et dans UTMStack sur la même période :

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-NTLM/Operational'; StartTime=(Get-Date).AddDays(-10)} |
  Group-Object { $_.TimeCreated.ToString('MM-dd') + ' ' + $_.Id } | Sort-Object Name | Select-Object Count, Name
```

```bash
docker exec -i $(docker ps -qf name=utmstack_node1|head -1) curl -sk -K - -H 'Content-Type: application/json' \
  'https://localhost:9200/v11-log-*/_search?filter_path=aggregations' \
  -d '{"size":0,"query":{"bool":{"filter":[{"term":{"event.providerName":"Microsoft-Windows-NTLM"}},{"range":{"@timestamp":{"gte":"now-10d"}}}]}},"aggs":{"jour":{"date_histogram":{"field":"@timestamp","calendar_interval":"day"}}}}' < /root/.os.curl
```

---

## Ce qui ne peut plus être affiché

Certaines visualisations de la version v11.2 regroupaient sur un champ qui n'existe plus qu'en `event.*`. Elles n'ont pas de remplaçant dans le module de visualisation :

| Visualisation | Champ de regroupement | Alternative |
|---|---|---|
| Suricata - Types d'événements | `event.eventType` | un compteur par type, filtré sur `event.eventType` |
| Suricata - Top Signatures (barres et table) | `event.alert.signature` | Log Explorer, ou un comptage hors d'UTMStack (ci-dessous) |
| NTLM - Top Accounts | `event.data.Username` | Log Explorer |
| NTLM - Version Breakdown | `event.data.NtlmVersion` | le compteur « NTLMv1 Detected » |

Pour le classement des signatures, le lab utilise un script Python en lecture seule, `bilan-medium-suricata.py`, qui lit les événements par lots (`scroll`) et fait le comptage lui-même. C'est lui qui a servi à établir la liste des signatures du déclencheur SOAR du chapitre 05.

---

## Tester les visualisations

Les événements de test s'envoient en syslog depuis OPNsense. Ils apparaissent dans les tableaux de bord en moins d'une minute.

**Ban CrowdSec**, avec une adresse de documentation (RFC 5737) qui ne peut appartenir à personne :

```bash
logger -p local5.alert -t crowdsec 'CROWDSEC_BAN {"event_type":"ban","ip":"192.0.2.10","reason":"test","country":"CH","as":"AS0","type":"ban"}'
```

**Visualisations Suricata :** le plus simple est d'attendre le trafic réel, qui ne manque pas sur une adresse publique (plus de 1 400 alertes bloquées par jour dans le lab). Pour vérifier un compteur, comparer sa valeur avec un comptage direct dans OpenSearch sur la même période :

```bash
docker exec -i $(docker ps -qf name=utmstack_node1|head -1) curl -sk -K - -H 'Content-Type: application/json' \
  'https://localhost:9200/v11-log-suricata-*/_count' \
  -d '{"query":{"bool":{"filter":[{"term":{"event.alert.action":"blocked"}},{"range":{"@timestamp":{"gte":"now-24h"}}}]}}}' < /root/.os.curl
```

Les deux chiffres doivent être proches. Un léger écart vient de la fenêtre glissante de 24 heures, qui n'est pas calculée au même instant.

---

> ℹ️ *Testé sur UTMStack v11.3.0 CE, OpenSearch intégré, novembre 2026.*

---

[← Intégration CrowdSec](03-crowdsec.md) | [→ SOAR et réponse aux incidents](05-soar.md)
