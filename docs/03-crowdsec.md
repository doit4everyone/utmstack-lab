---
title: "Intégration CrowdSec → UTMStack | DoIt4Everyone"
description: "Procédure d'intégration CrowdSec dans UTMStack v11.2.8. Forwarding des décisions, bouncer OPNsense, whitelist Azure, dashboard."
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

# Intégration CrowdSec — OPNsense → UTMStack

> [← Retour à l'index](../)

## Architecture

```
CrowdSec (OPNsense / FreeBSD)
    ↓ cscli alerts list --since 2m (polling toutes les 2 min)
crowdsec-to-syslog.py (Python)
    ↓ syslog LOCAL5.alert tag=crowdsec, format JSON CROWDSEC_BAN
syslog-ng → TCP 10.100.1.16:7014
    ↓
Agent UTMStack gest-srv
    ↓
UTMStack (dataType: syslog, index v11-log-syslog-*)
    ↓
Ingest pipeline crowdsec-country → champ crowdsec_country
```

> ℹ️ CrowdSec ne dispose pas d'un parseur natif dans UTMStack v11.2.8 — les décisions arrivent dans l'index syslog général et sont filtrées par la présence du tag `CROWDSEC_BAN` dans le champ `raw`. Un ingest pipeline OpenSearch (`crowdsec-country`) extrait ensuite le code pays comme champ structuré — voir `04-dashboards.md`.

---

## Prérequis

- CrowdSec installé et actif sur OPNsense (`service crowdsec status`)
- Port 7014 TCP inbound ouvert sur gest-srv (voir `02-suricata.md`)
- `cscli` disponible dans `/usr/local/bin/cscli`

---

## Étape 1 — Script de forwarding des décisions

Créer `/usr/local/bin/crowdsec-to-syslog.py` :

```bash
nano /usr/local/bin/crowdsec-to-syslog.py
```

```python
#!/usr/local/bin/python3
import json
import subprocess
import syslog
import time

syslog.openlog("crowdsec", syslog.LOG_PID, syslog.LOG_LOCAL5)

def get_decisions():
    result = subprocess.run(
        ["/usr/local/bin/cscli", "alerts", "list", "--output", "json", "--since", "2m"],
        capture_output=True, text=True
    )
    try:
        return json.loads(result.stdout) or []
    except Exception:
        return []

while True:
    try:
        alerts = get_decisions()
        for alert in alerts:
            src = alert.get("source", {})
            decisions = alert.get("decisions", [{}])
            reason = alert.get("scenario", "-")
            # Ignorer les bans SOAR (déjà loggués par soar_ban.sh)
            if reason == "utmstack":
                continue
            ip      = src.get("ip", "-")
            country = src.get("cn", "-") or "-"
            asn     = src.get("as_name", "-") or "-"
            dtype   = decisions[0].get("type", "ban")
            msg = (
                f'CROWDSEC_BAN {{"event_type":"ban","ip":"{ip}",'
                f'"reason":"{reason}","country":"{country}",'
                f'"as":"{asn}","type":"{dtype}"}}'
            )
            syslog.syslog(syslog.LOG_ALERT, msg)
    except Exception as e:
        syslog.syslog(syslog.LOG_ERR, f"crowdsec-to-syslog error: {e}")
    time.sleep(120)
```

```bash
chmod +x /usr/local/bin/crowdsec-to-syslog.py
```

> ⚠️ Utiliser le chemin complet `/usr/local/bin/cscli` — le PATH des services daemon ne contient pas `/usr/local/bin` par défaut.

> ℹ️ Les alertes avec `reason=utmstack` sont ignorées — elles sont déjà loggées par `soar_ban.sh` pour éviter les doublons.

---

## Étape 2 — Service rc.d persistant

Créer `/usr/local/etc/rc.d/crowdsec_to_syslog` :

```sh
#!/bin/sh
# PROVIDE: crowdsec_to_syslog
# REQUIRE: LOGIN crowdsec
# KEYWORD: shutdown
. /etc/rc.subr
name="crowdsec_to_syslog"
rcvar="crowdsec_to_syslog_enable"
command="/usr/sbin/daemon"
pidfile="/var/run/crowdsec_to_syslog.pid"
command_args="-P ${pidfile} -r -f /usr/local/bin/python3 /usr/local/bin/crowdsec-to-syslog.py"
load_rc_config $name
: ${crowdsec_to_syslog_enable:="NO"}
run_rc_command "$1"
```

```bash
chmod +x /usr/local/etc/rc.d/crowdsec_to_syslog
echo 'crowdsec_to_syslog_enable="YES"' >> /etc/rc.conf.local
service crowdsec_to_syslog start
service crowdsec_to_syslog status
```

> ℹ️ Les flags `-P` (pidfile majuscule) et `-r` (restart automatique) sont obligatoires. Sans eux, le service ne redémarre pas après un crash et la commande `status` retourne toujours `not running`.

---

## Étape 3 — Vérification du pipeline

**Test d'injection manuelle :**

```bash
logger -p local5.alert -t crowdsec \
  'CROWDSEC_BAN {"event_type":"ban","ip":"1.2.3.4","reason":"crowdsecurity/http-probing","country":"CN","as":"TestAS","type":"ban"}'
```

Dans UTMStack → **Log Explorer** → filtre `raw CONTAINS CROWDSEC_BAN` — le message doit apparaître avec :

| Champ | Valeur |
|---|---|
| `dataType` | `syslog` |
| `dataSource` | `10.100.1.254` |
| `raw` | `... crowdsec[PID]: CROWDSEC_BAN {"event_type":"ban","ip":"1.2.3.4",...}` |
| `crowdsec_country` | `CN` (si l'ingest pipeline est actif) |

**Vérifier les décisions réelles CrowdSec :**

```bash
/usr/local/bin/cscli decisions list
```

---

## Format du message syslog

Chaque décision CrowdSec génère une ligne syslog au format JSON :

```
CROWDSEC_BAN {"event_type":"ban","ip":"<IP>","reason":"<scénario>","country":"<code ISO>","as":"<ASN>","type":"ban"}
```

Ce format JSON permet à l'ingest pipeline OpenSearch `crowdsec-country` d'extraire le champ `crowdsec_country` automatiquement pour les visualisations dashboard (voir `04-dashboards.md`).

---

## Whitelist — Exclure les IPs légitimes

Certaines IPs Microsoft Azure génèrent des alertes Suricata en masse (trafic MDE, Windows Update, M365). Les exclure de CrowdSec évite des bans sur du trafic légitime.

Créer ou compléter `/usr/local/etc/crowdsec/postoverflows/s01-whitelist/utmstack-whitelist.yaml` :

```yaml
name: crowdsecurity/utmstack-whitelist
description: Whitelist for known legitimate IPs (Azure, Microsoft)
whitelist:
  reason: Known legitimate infrastructure
  cidr:
    - "20.0.0.0/8"       # Microsoft Azure global
    - "40.64.0.0/10"     # Microsoft Azure
    - "74.160.0.0/14"    # Microsoft Corp (AS8075)
    - "192.168.0.0/16"   # RFC1918 — réseau interne
    - "10.0.0.0/8"       # RFC1918 — réseau interne
```

```bash
service crowdsec reload
```

> ℹ️ Les IPs privées (192.168.x.x, 10.x.x.x) peuvent être bannies si Suricata génère une alerte sur du trafic LAN — les ajouter en whitelist prévient les bans accidentels.

---

## Vérification des services au démarrage

```bash
service suricata_syslog status
service crowdsec_to_syslog status
service crowdsec status
netstat -an | grep "10.100.1.16"
```

Résultat attendu :
```
suricata_syslog is running as pid XXXX
crowdsec_to_syslog is running as pid XXXX
crowdsec is running as pid XXXX
tcp4 ... 10.100.1.254.XXXXX  10.100.1.16.7014  ESTABLISHED  ← CrowdSec
tcp4 ... 10.100.1.254.XXXXX  10.100.1.16.7019  ESTABLISHED  ← Suricata
```

---

> ℹ️ *Testé sur OPNsense 26.1, CrowdSec 1.6.x, UTMStack v11.2.8*

---

[← Intégration Suricata](02-suricata.md) | [→ Dashboards](04-dashboards.md)
