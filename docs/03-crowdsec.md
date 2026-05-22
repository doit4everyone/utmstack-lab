# Intégration CrowdSec — OPNsense → UTMStack

> [← Retour à l'index](../README.md)

## Architecture

```
CrowdSec (OPNsense / FreeBSD)
    ↓ cscli decisions list (polling toutes les 2 min)
crowdsec_to_syslog (script sh)
    ↓ syslog tag=crowdsec, format CROWDSEC_BAN
syslog-ng → TCP 10.100.1.16:7014
    ↓
Agent UTMStack gest-srv
    ↓
UTMStack (dataType: syslog, index v11-log-syslog-*)
```

> ℹ️ CrowdSec ne dispose pas d'un parseur natif dans UTMStack v11.2.8 — les décisions arrivent dans l'index syslog général et sont filtrées par la présence du tag `CROWDSEC_BAN` dans le champ `raw`.

---

## Prérequis

- CrowdSec installé et actif sur OPNsense (`service crowdsec status`)
- Port 7014 TCP inbound ouvert sur gest-srv (voir `02-suricata.md`)
- `cscli` disponible dans `/usr/local/bin/cscli`

---

## Étape 1 — Script de forwarding des décisions

Créer `/usr/local/bin/crowdsec-to-syslog.sh` :

```sh
#!/bin/sh

LAST_FILE="/var/run/crowdsec_last_decision"
CSCLI="/usr/local/bin/cscli"

# Initialiser le fichier de suivi si inexistant
if [ ! -f "$LAST_FILE" ]; then
    echo "0" > "$LAST_FILE"
fi

while true; do
    LAST_ID=$(cat "$LAST_FILE")

    # Récupérer les décisions depuis le dernier ID connu
    $CSCLI decisions list -o json 2>/dev/null | \
    /usr/local/bin/python3 -c "
import sys, json
data = json.load(sys.stdin)
if not data:
    sys.exit(0)
last_id = int(open('/var/run/crowdsec_last_decision').read().strip())
new_last = last_id
for d in data:
    did = int(d.get('id', 0))
    if did > last_id:
        ip      = d.get('value', 'unknown')
        reason  = d.get('reason', 'unknown')
        country = d.get('origin', 'unknown')
        asname  = d.get('scope', 'unknown')
        dtype   = d.get('type', 'ban')
        print(f'CROWDSEC_BAN | ip={ip} | reason={reason} | country={country} | as={asname} | type={dtype} | path=/ | ua=-')
        if did > new_last:
            new_last = did
open('/var/run/crowdsec_last_decision', 'w').write(str(new_last))
" | while read line; do
        logger -p local5.alert -t crowdsec "$line"
    done

    sleep 120
done
```

```bash
chmod +x /usr/local/bin/crowdsec-to-syslog.sh
```

> ⚠️ Utiliser le chemin complet `/usr/local/bin/cscli` — le PATH des services daemon ne contient pas `/usr/local/bin` par défaut.

---

## Étape 2 — Service rc.d persistant

Créer `/usr/local/etc/rc.d/crowdsec_to_syslog` :

```sh
#!/bin/sh
# PROVIDE: crowdsec_to_syslog
# REQUIRE: crowdsec syslog-ng
# KEYWORD: shutdown

. /etc/rc.subr

name="crowdsec_to_syslog"
rcvar="crowdsec_to_syslog_enable"
command="/usr/local/bin/crowdsec-to-syslog.sh"
pidfile="/var/run/crowdsec_to_syslog.pid"

start_cmd="${name}_start"
stop_cmd="${name}_stop"

crowdsec_to_syslog_start() {
    echo "Starting ${name}."
    daemon -p ${pidfile} ${command}
}

crowdsec_to_syslog_stop() {
    echo "Stopping ${name}."
    if [ -f ${pidfile} ]; then
        kill $(cat ${pidfile})
        rm -f ${pidfile}
    fi
}

load_rc_config $name
run_rc_command "$1"
```

```bash
chmod +x /usr/local/etc/rc.d/crowdsec_to_syslog
echo 'crowdsec_to_syslog_enable="YES"' >> /etc/rc.conf.local
service crowdsec_to_syslog start
service crowdsec_to_syslog status
```

---

## Étape 3 — Vérification du pipeline

**Test d'injection manuelle :**

```bash
logger -p local5.alert -t crowdsec \
  "CROWDSEC_BAN | ip=1.2.3.4 | reason=crowdsecurity/http-probing | country=CN | as=TestAS | type=ban | path=/admin | ua=python-requests"
```

Dans UTMStack → **Log Explorer** → filtre `raw CONTAINS CROWDSEC_BAN` — le message doit apparaître avec :

| Champ | Valeur |
|---|---|
| `dataType` | `syslog` |
| `dataSource` | `10.100.1.254` |
| `raw` | `... crowdsec[PID]: CROWDSEC_BAN \| ip=1.2.3.4 \| ...` |

**Vérifier les décisions réelles CrowdSec :**

```bash
/usr/local/bin/cscli decisions list
```

---

## Format du message syslog

Chaque décision CrowdSec génère une ligne syslog au format :

```
CROWDSEC_BAN | ip=<IP> | reason=<scénario> | country=<pays> | as=<ASN> | type=ban | path=<chemin> | ua=<user-agent>
```

Ce format fixe permet de créer des règles de corrélation UTMStack et des visualisations OpenSearch basées sur du parsing de texte dans le champ `raw`.

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
tcp4 ... 10.100.1.254.XXXXX  10.100.1.16.7019  ESTABLISHED
```

---

> ℹ️ *Testé sur OPNsense 26.1, CrowdSec 1.6.x, UTMStack v11.2.8*
