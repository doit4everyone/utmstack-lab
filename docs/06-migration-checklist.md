---
title: "Checklist post-migration OPNsense 26.1 | DoIt4Everyone"
description: "Points de vigilance après migration OPNsense 25.7 vers 26.1. GUI port 8081, OpenVPN TLS static key, syslog-ng restart hook, pipeline UTMStack."
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

# Checklist post-migration OPNsense 26.1

> [← Retour à l'index](../)

## 📋 Table des matières

1. [Interface web GUI](#1-interface-web-gui)
2. [OpenVPN](#2-openvpn)
3. [Suricata / Intrusion Detection](#3-suricata--intrusion-detection)
4. [Pipeline syslog-ng → UTMStack](#4-pipeline-syslog-ng--utmstack)
5. [Services custom](#5-services-custom)
6. [Vérifications finales](#6-vérifications-finales)

---

## 1. Interface web GUI

> ⚠️ **Breaking change 26.1** : L'interface OPNsense est maintenant sur le port **8081** via lighttpd. nginx WAF tourne sur 80/443.

**Bookmarker :** `https://<IP-OPNsense>:8081`

| Accès | URL |
|-------|-----|
| Interface principale | `https://10.100.1.254:8081` |
| Ancien port (bloqué par WAF) | `http://10.100.1.254` → ❌ |

---

## 2. OpenVPN

> ⚠️ **Breaking change 26.1** : Les clés statiques TLS sont dissociées des instances lors de la migration.

**Action requise après chaque mise à jour majeure :**

1. **VPN → OpenVPN → Instances** → éditez chaque instance serveur et client
2. Vérifiez que **TLS static key** est assignée (pas `None`)
3. Si `None` → sélectionnez la clé → **Save** → **Apply**

**Symptôme si oublié :**
```
TLS Error: TLS key negotiation failed to occur within 60 seconds
TLS handshake failed
```

### Renégociation TLS — tunnel site-to-site

Après migration, le tunnel peut rester actif (ancienne session TLS en mémoire) mais la **renégociation périodique** (défaut : toutes les 3600 secondes) échoue silencieusement. Le tunnel tombe au prochain reboot ou expiration de session.

**Symptôme :**
```
TLS key negotiation failed to occur within 60 seconds
TLS handshake failed
```
Les erreurs apparaissent toutes les ~60 secondes dans les logs OPNsense alors que le tunnel semble actif.

**Fix — désactiver la renégociation (site-to-site uniquement) :**

Sur le **serveur** → **VPN → OpenVPN → Instances** → éditer → `Renegotiate time` → `0` → Save → Apply

Sur le **client** → même procédure → `Durée de renégociation` → `0` → Sauvegarder → Apply

> ℹ️ Mettre `0` des deux côtés est obligatoire — un seul côté ne suffit pas. La renégociation est utile pour les clients nomades mais inutile sur un lien site-to-site permanent.

---

## 3. Suricata / Intrusion Detection

```bash
# Suricata tourne ?
ps aux | grep suricata | grep -v grep

# Interface(s) monitorées
grep -A5 "netmap:" /usr/local/etc/suricata/suricata.yaml
```

> ⚠️ **Breaking change 26.1** : Le fichier `custom.yaml` n'est plus supporté. Migrez vers `/usr/local/etc/suricata/conf.d/`.

```bash
# Vérifier les règles custom
cat /usr/local/etc/suricata/rules/custom.rules
```

---

## 4. Pipeline syslog-ng → UTMStack

**Vérifier les connexions TCP :**

```bash
netstat -an | grep "10.100.1.16"
```

Résultat attendu :
```
tcp4  0  0  10.100.1.254.xxxxx  10.100.1.16.7014  ESTABLISHED  ← CrowdSec
tcp4  0  0  10.100.1.254.xxxxx  10.100.1.16.7019  ESTABLISHED  ← Suricata
```

**Si les connexions sont absentes :**

```bash
service syslog-ng restart
sleep 15
netstat -an | grep "10.100.1.16"
```

**Vérifier le hook de démarrage :**

```bash
cat /usr/local/etc/rc.syshook.d/start/99-syslog-ng-restart
```

Contenu attendu :
```sh
#!/bin/sh
sleep 60
/usr/sbin/service syslog-ng restart
```

---

## 5. Services custom

```bash
service suricata_syslog status      # Forwarding EVE JSON → port 7019
service crowdsec_to_syslog status   # Forwarding décisions CrowdSec → port 7014
service crowdsec status             # CrowdSec engine
```

**Si un service ne démarre pas :**

```bash
cat /etc/rc.conf.local
# Contenu attendu : crowdsec_to_syslog_enable="YES"
```

---

## 6. Vérifications finales

**Test pipeline Suricata :**
```bash
logger -p local5.info -t suricata '{"event_type":"test","timestamp":"now"}'
# Vérifier dans UTMStack Log Explorer : dataType=suricata
```

**Test pipeline CrowdSec :**
```bash
logger -p local5.alert -t crowdsec 'CROWDSEC_BAN {"event_type":"ban","ip":"1.2.3.4","reason":"test","country":"CH","as":"AS0","type":"ban"}'
# Vérifier dans UTMStack Log Explorer : raw CONTAINS CROWDSEC_BAN
```

**Test CrowdSec décisions :**
```bash
/usr/local/bin/cscli decisions list
```

---

> ℹ️ *Testé sur OPNsense 26.1 après migration depuis 25.7.11*

> [← Retour à l'index](index.md)
