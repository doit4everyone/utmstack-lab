---
title: "Intégration Suricata OPNsense → UTMStack | DoIt4Everyone"
description: "Procédure d'intégration Suricata dans UTMStack v11.2.8 via syslog-ng natif. Pipeline OPNsense → agent Windows port 7019, source file() native, haute performance."
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

# Intégration Suricata — OPNsense → UTMStack

> [← Retour à l'index](../)

## Architecture

```
OPNsense (WAN only)
    ↓ /var/log/suricata/eve.json
syslog-ng source file() native (C, asynchrone)
    ↓ format syslog BSD : <174>MMM DD HH:MM:SS host suricata[1]: {JSON}
    ↓ TCP 10.100.1.16:7019
Agent UTMStack gest-srv
    ↓
Parseur natif Suricata UTMStack
    ↓
origin.ip / log.alert.signature / origin.geolocation.* / ...
```

> ℹ️ OPNsense tourne sous FreeBSD — aucun agent UTMStack ou Filebeat n'est disponible. La source `file()` native syslog-ng lit directement `eve.json` en C de façon asynchrone — aucun script shell intermédiaire nécessaire.

---

## Étape 1 — Activer l'intégration Suricata dans UTMStack

Dans UTMStack → **Data Sources** → sélectionner l'agent **gest-srv** → activer l'intégration **Suricata**.

Sur **gest-srv** en PowerShell Administrator :

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

## Étape 2 — Configuration syslog-ng native sur OPNsense

### 2.1 Source eve.json

Si OPNsense utilise ntopng, la source `s_suricata_eve` existe déjà dans `/usr/local/etc/syslog-ng.conf.d/suricata-ntopng.conf`. Vérifier et s'assurer qu'elle inclut `program-override` et les options de facility :

```bash
nano /usr/local/etc/syslog-ng.conf.d/suricata-ntopng.conf
```

```
source s_suricata_eve {
    file("/var/log/suricata/eve.json"
        follow-freq(1)
        flags(no-parse)
        default-facility(local5)
        default-severity(info)
        program-override("suricata")
    );
};
```

> ⚠️ **`program-override("suricata")` est obligatoire.** Sans lui, syslog-ng envoie la priorité `<13>` (user-level) au lieu de `<174>` (local5.info) et UTMStack ne parse pas les champs JSON — les événements arrivent en raw sans `origin.ip`, `log.alert.signature`, etc.

Si la source n'existe pas, créez-la directement dans `suricata-native.conf` (voir ci-dessous).

### 2.2 Destination UTMStack avec template BSD

Créer `/usr/local/etc/syslog-ng.conf.d/suricata-native.conf` :

```bash
nano /usr/local/etc/syslog-ng.conf.d/suricata-native.conf
```

```
destination d_utmstack_suricata {
    network("10.100.1.16" port(7019) transport("tcp")
        template("<174>${MONTH_ABBREV} ${DAY} ${HOUR}:${MIN}:${SEC} ${HOST} suricata[1]: ${MESSAGE}\n")
    );
};

log {
    source(s_suricata_eve);
    destination(d_utmstack_suricata);
};
```

> ⚠️ **`${HOUR}:${MIN}:${SEC}` et non `${TIME}`.** Avec `flags(no-parse)`, la variable `${TIME}` est vide — le timestamp disparaît du syslog header et UTMStack ne reconnaît plus le format. Utiliser les macros individuelles.

> ℹ️ Le PID `[1]` est fictif mais obligatoire — UTMStack attend le format `suricata[PID]:` pour activer l'extraction des champs JSON.

Valider et redémarrer :

```bash
syslog-ng --syntax-only && service syslog-ng restart
service syslog-ng status
```

Vérifier la connexion :

```bash
netstat -an | grep "10.100.1.16" | grep ESTABLISHED
# Attendu : tcp4 ... 10.100.1.254.XXXXX 10.100.1.16.7019 ESTABLISHED
```

> ℹ️ La connexion vers le port 7019 est établie de façon **lazy** — uniquement lors de l'arrivée du premier événement Suricata.

---

## Étape 3 — Hook de démarrage (timing reboot)

syslog-ng démarre avant que l'agent UTMStack soit joignable au boot. Un hook rc.syshook force un restart après 60 secondes :

```bash
nano /usr/local/etc/rc.syshook.d/start/99-syslog-ng-restart
```

```sh
#!/bin/sh
sleep 60
/usr/sbin/service syslog-ng restart
```

```bash
chmod +x /usr/local/etc/rc.syshook.d/start/99-syslog-ng-restart
```

---

## Étape 4 — Vérification et test d'injection

**Vérifier que Suricata génère du trafic :**

```bash
tail -f /var/log/suricata/eve.json | grep -v '"event_type":"stats"'
```

Des événements `http`, `dns`, `flow` doivent défiler en continu.

**Test d'injection manuelle :**

```bash
echo '{"timestamp":"2026-05-28T11:00:00.000000+0200","flow_id":111111111,"in_iface":"em1","event_type":"alert","src_ip":"1.2.3.4","src_port":12345,"dest_ip":"192.168.1.203","dest_port":80,"proto":"TCP","alert":{"action":"blocked","gid":1,"signature_id":2029022,"rev":3,"signature":"ET SCAN Test Injection","category":"Attempted Administrator Privilege Gain","severity":1},"direction":"to_server"}' >> /var/log/suricata/eve.json
```

Dans UTMStack → **Log Explorer** → filtre `dataType: suricata` — l'événement doit apparaître avec tous les champs parsés :

| Champ UTMStack | Contenu |
|---|---|
| `dataType` | `suricata` |
| `dataSource` | `10.100.1.254` |
| `log.eventType` | `alert` |
| `log.alert.signature` | Nom de la règle déclenchée |
| `log.alert.severity` | 1 (High) à 3 (Low) |
| `log.alert.category` | Catégorie MITRE |
| `origin.ip` | IP source de l'attaque |
| `origin.geolocation.country` | Pays (enrichi automatiquement) |
| `origin.geolocation.countryCode` | Code pays |
| `origin.geolocation.asn` | Numéro d'AS |
| `origin.geolocation.aso` | Nom de l'AS |
| `target.ip` | IP cible |

> ✅ Si `origin.ip` et `log.alert.signature` apparaissent → le pipeline fonctionne correctement et les règles de corrélation UTMStack peuvent se déclencher.

---

## Bugs connus

### `${TIME}` vide avec `flags(no-parse)`

**Symptôme :** Le raw dans UTMStack montre `<174>May 28 ms.bsculier.ch suricata[1]:` sans heure — les champs ne sont pas parsés.

**Cause :** `flags(no-parse)` empêche syslog-ng d'extraire le timestamp du message, laissant `${TIME}` vide.

**Solution :** Utiliser `${HOUR}:${MIN}:${SEC}` dans le template.

### `<13>` au lieu de `<174>`

**Symptôme :** Les événements arrivent avec priorité `<13>` (user-level) — UTMStack les reçoit comme raw sans champs structurés.

**Cause :** `program-override("suricata")` absent de la source `file()`.

**Solution :** Ajouter `program-override("suricata")` + `default-facility(local5)` + `default-severity(info)` dans la source.

---

## Points de vigilance

- **Suricata WAN uniquement** — activer l'IDS sur l'interface LAN génère du bruit sur du trafic interne légitime (WinRM, Kerberos, etc.)
- **Source unique** — syslog-ng interdit deux sources lisant le même fichier — si ntopng utilise déjà `eve.json`, réutilisez `s_suricata_eve` dans le `log {}` plutôt que d'en créer une nouvelle
- **`suricata-native.conf`** survit aux reboots et aux mises à jour OPNsense
- **Port 7014 TCP** doit rester ouvert sur gest-srv pour le pipeline CrowdSec (voir `03-crowdsec.md`)
- **Page Suricata Alerts dans OPNsense UI** — bug connu : tourne en boucle sur "Processing request..." indépendamment du pipeline. Utiliser `tail -f /var/log/suricata/eve.json` en CLI à la place

---

> ℹ️ *Testé sur OPNsense 26.1, UTMStack v11.2.8, agent Windows v11.1.4, syslog-ng 4.x*

---

[← Installation & Architecture](01-installation.md) | [→ Intégration CrowdSec](03-crowdsec.md)
