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
    ↓ TCP 10.100.1.16:7019
Agent UTMStack gest-srv
    ↓
Parseur natif Suricata UTMStack
    ↓
Alertes + champs parsés automatiquement
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

Créer `/usr/local/etc/syslog-ng.conf.d/suricata-native.conf` :

```bash
nano /usr/local/etc/syslog-ng.conf.d/suricata-native.conf
```

```
destination d_utmstack_suricata {
    network("10.100.1.16" port(7019) transport("tcp"));
};

log {
    source(s_suricata_eve);
    destination(d_utmstack_suricata);
};
```

> ℹ️ La source `s_suricata_eve` lit `/var/log/suricata/eve.json` — elle est définie dans la configuration syslog-ng existante d'OPNsense. Si elle n'existe pas, ajoutez-la :
>
> ```
> source s_suricata_eve {
>     file("/var/log/suricata/eve.json"
>         follow-freq(1)
>         flags(no-parse)
>     );
> };
> ```

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

## Vérification finale

**Test d'injection manuelle :**

```bash
echo '{"event_type":"alert","timestamp":"2026-05-25T20:55:00","src_ip":"1.2.3.4","alert":{"signature":"TEST NATIVE SYSLOG","severity":1}}' >> /var/log/suricata/eve.json
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
| `origin.geolocation.country` | Pays (enrichi automatiquement) |
| `target.ip` | IP cible |

---

## Points de vigilance

- **Suricata WAN uniquement** — activer l'IDS sur l'interface LAN génère du bruit sur du trafic interne légitime (WinRM, Kerberos, etc.)
- **Source unique** — si OPNsense a déjà une source `file()` sur `eve.json` (ex: ntopng), réutilisez-la dans le `log {}` plutôt que d'en créer une nouvelle — syslog-ng interdit deux sources lisant le même fichier
- **`suricata-native.conf`** survit aux reboots et aux mises à jour OPNsense
- **Port 7014 TCP** doit rester ouvert sur gest-srv pour le pipeline CrowdSec (voir `03-crowdsec.md`)

---

> ℹ️ *Testé sur OPNsense 26.1, UTMStack v11.2.8, agent Windows v11.1.4, syslog-ng 4.x*

---

[← Installation & Architecture](01-installation.md) | [→ Intégration CrowdSec](03-crowdsec.md)
