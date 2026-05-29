---
title: "Dashboards Suricata & CrowdSec dans UTMStack | DoIt4Everyone"
description: "Création des dashboards UTMStack v11.2.8 pour Suricata et CrowdSec. Visualisations OpenSearch, threat map, géolocalisation, index v11-log-suricata-*."
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

# Dashboards UTMStack — Suricata & CrowdSec

> [← Retour à l'index](../)

---

## Dashboard Suricata

### Index et champs disponibles

L'intégration native Suricata (port 7019) crée l'index **`v11-log-suricata-*`** avec les champs parsés automatiquement par UTMStack :

| Champ | Contenu | Exemple |
|---|---|---|
| `log.eventType` | Type d'événement EVE | `alert`, `http`, `anomaly`, `dns` |
| `log.alert.signature` | Nom de la règle Suricata | `ET SCAN Zmap User-Agent` |
| `log.alert.severity` | Sévérité (1=High, 3=Low) | `1` |
| `log.alert.category` | Catégorie de l'alerte | `Network Scan` |
| `origin.ip` | IP source de l'attaque | `40.124.175.174` |
| `origin.geolocation.country` | Pays d'origine | `United States` |
| `origin.geolocation.city` | Ville | `Des Moines` |
| `origin.geolocation.countryCode` | Code ISO pays | `US` |
| `origin.geolocation.latitude` | Latitude | `41.6021` |
| `origin.geolocation.longitude` | Longitude | `-93.6124` |
| `target.ip` | IP cible | `10.100.1.254` |

> ℹ️ La géolocalisation est enrichie automatiquement par UTMStack — aucune configuration supplémentaire nécessaire.

---

### Visualisation 1 — Total Alertes (Metric)

**New Visualization → Metric**

- Source : `v11-log-suricata-*`
- Filter : `log.eventType.keyword` is `alert`
- Aggregation : `Count`
- Custom label : `Total Alertes Suricata`
- Save → `Suricata - Total Alertes`

---

### Visualisation 2 — Types d'événements (Bar horizontal)

**New Visualization → Bar horizontal**

- Source : `v11-log-suricata-*`
- Buckets → Split axis :
  - Aggregation : `Terms`
  - Field : `log.eventType.keyword`
  - Size : `10`
  - Order : Descending
- Save → `Suricata - Types d'événements`

Types attendus : `alert`, `http`, `anomaly`, `dns`, `flow`

---

### Visualisation 3 — Top Signatures (Bar horizontal)

**New Visualization → Bar horizontal**

- Source : `v11-log-suricata-*`
- Filter : `log.eventType.keyword` is `alert`
- Buckets → Split axis :
  - Aggregation : `Terms`
  - Field : `log.alert.signature.keyword`
  - Size : `10`
  - Order : Descending
- Save → `Suricata - Top Signatures`

---

### Visualisation 4 — Top Signatures (Table)

**New Visualization → Table**

- Source : `v11-log-suricata-*`
- Filter : `log.eventType.keyword` is `alert`
- Buckets → Split rows :
  - Aggregation : `Terms`
  - Field : `log.alert.signature.keyword`
  - Size : `100`
  - Order : Descending
- Save → `Suricata - Top Signatures Table`

---

### Visualisation 5 — Timeline Alertes (Line)

**New Visualization → Line**

- Source : `v11-log-suricata-*`
- Filter : `log.eventType.keyword` is `alert`
- Buckets → X-axis :
  - Aggregation : `Date Histogram`
  - Field : `@timestamp`
  - Minimum interval : `Hour`
- Save → `Suricata - Timeline Alertes`

---

### Visualisation 6 — Top Source IPs (Bar horizontal)

**New Visualization → Bar horizontal**

- Source : `v11-log-suricata-*`
- Filter : `log.eventType.keyword` is `alert`
- Buckets → Split axis :
  - Aggregation : `Terms`
  - Field : `origin.ip.keyword`
  - Size : `10`
  - Order : Descending
- Save → `Suricata - Top Source IPs`

---

### Visualisation 7 — Top Pays (Bar horizontal)

**New Visualization → Bar horizontal**

- Source : `v11-log-suricata-*`
- Filter : `log.eventType.keyword` is `alert`
- Buckets → Split axis :
  - Aggregation : `Terms`
  - Field : `origin.geolocation.country.keyword`
  - Size : `10`
  - Order : Descending
- Save → `Suricata - Top Pays`

> ℹ️ La visualisation **Region map** (carte monde) n'est pas fonctionnelle dans UTMStack v11.2.8 — utiliser le Bar horizontal pays à la place.

> ℹ️ Ce widget utilise `origin.geolocation.country.keyword` (nom complet : "United States") pour le Dashboard Suricata. Le widget "Top Pays — Alertes Suricata" dans le Dashboard CrowdSec utilise `origin.geolocation.countryCode.keyword` (code ISO : "US") pour une meilleure lisibilité côte à côte avec les bans CrowdSec.

---

### Assemblage Dashboard Suricata

**Dashboards → New Dashboard → Add Visualization** — ajouter les 7 visualisations :

```
[ Suricata - Total Alertes        ] [ Suricata - Types d'événements   ]
[ Suricata - Top Signatures       ] [ Suricata - Timeline Alertes     ]
[ Suricata - Top Signatures Table                                      ]
[ Suricata - Top Source IPs       ] [ Suricata - Top Pays             ]
```

**Save dashboard → `Dashboard Suricata`**

---

## Dashboard CrowdSec

### Index et données disponibles

Les décisions CrowdSec arrivent dans l'index **`v11-log-syslog-*`**. Les données sont filtrées par la présence de `CROWDSEC_BAN` dans le champ `raw`.

Format d'un événement dans `raw` (format JSON depuis la mise à jour de `soar_ban.sh`) :

```
<169>May 28 18:16:31 ms.bsculier.ch crowdsec[33276]: CROWDSEC_BAN {"event_type":"ban","ip":"45.67.246.120","reason":"utmstack","country":"ES","as":"214678","type":"ban"}
```

#### Champ `crowdsec_country` — Ingest pipeline OpenSearch

Le champ `country` dans le JSON est extrait automatiquement par un ingest pipeline OpenSearch et indexé comme champ structuré `crowdsec_country` :

```bash
# Création de l'ingest pipeline (à effectuer une seule fois)
docker exec $(docker ps -q -f name=utmstack_node1) curl -sk \
  -u 'admin:<password>' \
  -X PUT "https://localhost:9200/_ingest/pipeline/crowdsec-country" \
  -H "Content-Type: application/json" \
  -d '{
    "description": "Extract country from CROWDSEC_BAN syslog",
    "processors": [
      {
        "script": {
          "lang": "painless",
          "source": "if (ctx.raw != null && ctx.raw.contains(\"CROWDSEC_BAN\")) { def m = /country[=:\\\"]([A-Z]{2})/.matcher(ctx.raw); if (m.find()) { ctx.crowdsec_country = m.group(1); } }"
        }
      }
    ]
  }'

# Application du pipeline à l'index du jour courant (remplacer la date)
docker exec $(docker ps -q -f name=utmstack_node1) curl -sk \
  -u 'admin:<password>' \
  -X PUT "https://localhost:9200/v11-log-syslog-$(date +%Y-%m-%d)/_settings" \
  -H "Content-Type: application/json" \
  -d '{"index.default_pipeline": "crowdsec-country"}'

# Template pour tous les futurs index v11-log-syslog-* (automatique dès le lendemain)
docker exec $(docker ps -q -f name=utmstack_node1) curl -sk \
  -u 'admin:<password>' \
  -X PUT "https://localhost:9200/_index_template/utmstack-syslog-crowdsec" \
  -H "Content-Type: application/json" \
  -d '{
    "index_patterns": ["v11-log-syslog-*"],
    "priority": 1,
    "template": {
      "settings": {
        "index.default_pipeline": "crowdsec-country"
      }
    }
  }'
```

> ℹ️ Le pipeline s'applique automatiquement aux nouveaux index `v11-log-syslog-*` via le template OpenSearch. Vérification : `curl ... "https://localhost:9200/v11-log-syslog-$(date +%Y-%m-%d)/_settings" | grep pipeline`

| Champ | Contenu | Exemple |
|---|---|---|
| `raw` | Message syslog brut complet | `CROWDSEC_BAN {"event_type":"ban","ip":"45.67.246.120",...}` |
| `crowdsec_country` | Code ISO pays extrait par le pipeline | `ES`, `US`, `MX` |

---

### Visualisation 1 — Total Bans (Metric)

**New Visualization → Metric**

- Source : `v11-log-syslog-*`
- Filter : `raw` contains `CROWDSEC_BAN`
- Aggregation : `Count`
- Custom label : `Bans CrowdSec`
- Save → `CrowdSec - Total Bans`

---

### Visualisation 2 — Timeline Bans (Line)

**New Visualization → Line**

- Source : `v11-log-syslog-*`
- Filter : `raw` contains `CROWDSEC_BAN`
- Buckets → X-axis :
  - Aggregation : `Date Histogram`
  - Field : `@timestamp`
  - Minimum interval : `Hour`
- Save → `CrowdSec - Timeline Bans`

---

### Visualisation 3 — Derniers Bans (Table)

**New Visualization → Table**

- Source : `v11-log-syslog-*`
- Filter : `raw` contains `CROWDSEC_BAN`
- Buckets → Split rows :
  - Aggregation : `Terms`
  - Field : `raw.keyword`
  - Size : `50`
  - Order : Descending
- Save → `CrowdSec - Derniers Bans`

---

### Visualisation 4 — Top Pays — Bans CrowdSec (Bar horizontal)

**New Visualization → Bar horizontal**

- Source : `v11-log-syslog-*`
- Filter : `raw` **contain** `CROWDSEC_BAN`
- Buckets → Split axis :
  - Aggregation : `Terms`
  - Field : `crowdsec_country.keyword`
  - Size : `10`
  - Order : Descending
- Save → `Top Pays — Bans CrowdSec`

> ℹ️ Nécessite l'ingest pipeline `crowdsec-country` actif (voir section précédente). Le champ `crowdsec_country` n'est indexé que sur les événements arrivés **après** la mise en place du pipeline.

---

### Visualisation 5 — Top Pays — Alertes Suricata (Bar horizontal)

**New Visualization → Bar horizontal**

- Source : `v11-log-suricata-*`
- Filter : `log.eventType` **contain** `alert`
- Buckets → Split axis :
  - Aggregation : `Terms`
  - Field : `origin.geolocation.countryCode.keyword`
  - Size : `10`
  - Order : Descending
- Save → `Top Pays — Alertes Suricata`

> ℹ️ Ce widget est placé dans le **Dashboard CrowdSec** pour avoir une vue consolidée des menaces géographiques — bans vs alertes côte à côte.

---

### Assemblage Dashboard CrowdSec

**Dashboards → New Dashboard → Add Visualization** :

```
[ CrowdSec - Total Bans           ]
[ CrowdSec - Timeline Bans                                             ]
[ CrowdSec - Derniers Bans                                             ]
[ Top Pays — Bans CrowdSec        ] [ Top Pays — Alertes Suricata     ]
```

**Save dashboard → `Dashboard CrowdSec`**

---

## Test des visualisations

**Test Suricata :**
```bash
logger -p local5.info -t suricata '{"event_type":"alert","timestamp":"now","src_ip":"1.2.3.4","alert":{"signature":"TEST RULE","severity":1}}'
```

**Test CrowdSec :**
```bash
logger -p local5.alert -t crowdsec 'CROWDSEC_BAN {"event_type":"ban","ip":"1.2.3.4","reason":"test","country":"CH","as":"AS0","type":"ban"}'
```

Les événements apparaissent dans les dashboards dans les 30 secondes.

---

> ℹ️ *Testé sur UTMStack v11.2.8, OpenSearch 2.x intégré*

---

[← Intégration CrowdSec](03-crowdsec.md) | [→ SOAR & Incident Response](05-soar.md)
