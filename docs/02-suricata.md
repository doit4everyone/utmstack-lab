# Intégration Suricata — OPNsense → UTMStack

> [← Retour à l'index](../)

## Architecture finale

```
OPNsense (WAN only)
    ↓ /var/log/suricata/eve.json
suricata_syslog (suricata-to-syslog.sh)
    ↓ syslog tag=suricata
syslog-ng (suricata-native.conf)
    ↓ TCP 10.100.1.16:7019
Agent UTMStack gest-srv
    ↓
Parseur natif Suricata UTMStack
    ↓
Alertes + champs parsés automatiquement
```

> ℹ️ OPNsense tourne sous FreeBSD — aucun agent UTMStack ou Filebeat n'est disponible. Le pipeline syslog-ng est la solution standard pour cette plateforme.

---

## Étape 1 — Activer l'intégration Suricata dans UTMStack

Dans UTMStack → **Data Sources** → sélectionner l'agent **gest-srv** → activer l'intégration **Suricata**.

UTMStack fournit la commande à exécuter sur l'agent. Sur **gest-srv** en PowerShell Administrator :

```powershell
Start-Process "C:\Program Files\UTMStack\UTMStack Agent\utmstack_agent_service_windows_amd64.exe" `
  -ArgumentList 'enable-integration', 'suricata', 'tcp' `
  -NoNewWindow -Wait
```

Ouvrir le port 7019 TCP inbound sur gest-srv :

```powershell
New-NetFirewallRule -DisplayName "UTMStack Suricata TCP 7019" `
  -Direction Inbound -Protocol TCP -LocalPort 7019 -Action Allow
```

Vérifier que le port écoute :

```powershell
netstat -an | findstr "7019"
```

Résultat attendu : `0.0.0.0:7019 ... LISTENING`

---

## Étape 2 — Script de forwarding sur OPNsense

Créer le script `/usr/local/bin/suricata-to-syslog.sh` :

```bash
#!/bin/sh
tail -n 0 -F /var/log/suricata/eve.json | while read line; do
    logger -p local5.info -t suricata "$line"
done
```

Rendre exécutable :

```bash
chmod +x /usr/local/bin/suricata-to-syslog.sh
```

---

## Étape 3 — Service rc.d persistant sur OPNsense

Créer `/usr/local/etc/rc.d/suricata_syslog` :

```sh
#!/bin/sh
# PROVIDE: suricata_syslog
# REQUIRE: suricata syslog-ng
# KEYWORD: shutdown

. /etc/rc.subr

name="suricata_syslog"
rcvar="suricata_syslog_enable"
command="/usr/local/bin/suricata-to-syslog.sh"
pidfile="/var/run/suricata_syslog.pid"

start_cmd="${name}_start"
stop_cmd="${name}_stop"

suricata_syslog_start() {
    echo "Starting ${name}."
    daemon -p ${pidfile} ${command}
}

suricata_syslog_stop() {
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
chmod +x /usr/local/etc/rc.d/suricata_syslog
echo 'suricata_syslog_enable="YES"' >> /etc/rc.conf.local
service suricata_syslog start
service suricata_syslog status
```

---

## Étape 4 — Configuration syslog-ng sur OPNsense

Créer `/usr/local/etc/syslog-ng.conf.d/suricata-native.conf` :

```
destination d_utmstack_suricata {
    network("10.100.1.16" port(7019) transport("tcp"));
};

filter f_suricata {
    program("suricata");
};

log {
    source(s_all);
    filter(f_suricata);
    destination(d_utmstack_suricata);
};
```

Valider et recharger :

```bash
syslog-ng --syntax-only && service syslog-ng reload
```

Vérifier la connexion établie :

```bash
netstat -an | grep "10.100.1.16"
# Attendu : tcp4 ... 10.100.1.254.XXXXX 10.100.1.16.7019 ESTABLISHED
```

---

## Étape 5 — Hook de démarrage (timing reboot)

syslog-ng démarre avant que les agents soient joignables au boot. Créer `/usr/local/etc/rc.syshook.d/start/99-syslog-ng-restart` :

```sh
#!/bin/sh
sleep 60
/usr/sbin/service syslog-ng restart
```

```bash
chmod +x /usr/local/etc/rc.syshook.d/start/99-syslog-ng-restart
```

---

## Vérification finale

**Test d'injection manuelle :**

```bash
logger -p local5.info -t suricata '{"event_type":"alert","timestamp":"now","src_ip":"1.2.3.4"}'
```

Dans UTMStack → **Log Explorer** → filtre `dataType: suricata` — l'événement doit apparaître avec les champs parsés :

| Champ UTMStack | Contenu |
|---|---|
| `dataType` | `suricata` |
| `dataSource` | `10.100.1.254` |
| `log.alert.signature` | Nom de la règle déclenchée |
| `log.alert.severity` | 1 (High) à 3 (Low) |
| `log.alert.category` | Catégorie MITRE |
| `origin.ip` | IP source de l'attaque |
| `target.ip` | IP cible |

---

## Points de vigilance

- **Suricata WAN uniquement** — activer l'IDS sur l'interface LAN génère du bruit sur du trafic interne légitime (WinRM, Kerberos, etc.)
- **`suricata-native.conf`** survit aux reboots et aux mises à jour OPNsense
- **Port 7014 TCP** doit rester ouvert sur gest-srv pour le pipeline CrowdSec (voir `03-crowdsec.md`)

---

> ℹ️ *Testé sur OPNsense 26.1, UTMStack v11.2.8, agent Windows v11.1.4*

---

[← Installation & Architecture](01-installation.md) | [→ Intégration CrowdSec](03-crowdsec.md)
