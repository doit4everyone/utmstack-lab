---
title: "Règles Suricata avancées — suricata-update & NF Rules | DoIt4Everyone"
description: "Ajout de règles Suricata avancées sur OPNsense 26.1 : suricata-update (ptrules, stamus/lateral, tgreen/hunting), NF Rules networkforensic.dk, mode IPS drop, persistance."
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

# Règles Suricata avancées — suricata-update & NF Rules

> [← Retour à l'index](../)

---

## ⚠️ Prérequis critique — HOME_NET doit inclure le réseau WAN

Par défaut, OPNsense configure `HOME_NET` avec uniquement le réseau LAN. Si Suricata monitore l'interface WAN (em1), **toutes les règles `-> $HOME_NET` sont aveugles** sur le trafic WAN — les scanners, les attaques et les sondes ne sont jamais détectés.

**Symptôme :** les règles NF-Scanners (Shodan, Censys, BinaryEdge) ne déclenchent aucune alerte malgré un trafic de scan visible dans les logs.

**Fix :** OPNsense GUI → **Services → Intrusion Detection → Administration → Settings → Home Networks** → ajouter le réseau WAN :

```
10.100.1.0/24, 192.168.1.0/24
```

Vérification :
```bash
grep "HOME_NET" /usr/local/etc/suricata/suricata.yaml | head -1
# → HOME_NET: "[10.100.1.0/24,192.168.1.0/24]"
```

**Résultat après correction** — en 24h, 139 scans bloqués par les règles NF qui étaient précédemment invisibles :

| Scanner | Hits bloqués | SID |
|---|---|---|
| Stretchoid | 40 | 5034xxx |
| BinaryEdge 1 | 36 | 5034101 |
| BinaryEdge 2 | 36 | 5034104 |
| Visionheight | 17 | 5034xxx |
| ShadowServer | 10 | 5034xxx |
| SYN scans divers | 12 | 9000200 |
| Dshield blocklist | 23 | 2402000 |

> ℹ️ **Visibilité UTMStack** — Les événements `event_type: alert` avec `action: blocked` remontent dans UTMStack et peuvent déclencher les corrélations. Les événements `event_type: drop` ne remontent pas — c'est le comportement normal du pipeline syslog.

---

## Stratégie et sources retenues

OPNsense gère nativement ET Open et Abuse.ch via **Services → Intrusion Detection → Administration → Download**. Ces sources couvrent l'essentiel. Pour aller plus loin sans compromettre la conformité nLPD, trois sources complémentaires ont été retenues :

| Source | Méthode | Contenu | Règles |
|---|---|---|---|
| ET Open + Abuse.ch | UI OPNsense | Référence absolue | ~30 000 |
| suricata-update | CLI | APT, lateral movement, threat hunting | ~1701 |
| NF Scanners | Script custom | Scanners connus (Shodan, Censys…) en `drop` | 222 |
| NF Local | Script custom | Threat hunting, C2, malware | 727 |
| NF Suricata | Script custom | JA3 fingerprints botnets/RAT | 6 |

**Rejeté — ET Pro Telemetry :** partage anonyme des alertes avec Proofpoint (USA). Non conforme nLPD pour un contexte PME suisse.

---

## Partie 1 — suricata-update

### Sources activées

```bash
suricata-update update-sources
suricata-update enable-source ptrules/open      # PT Security — APT Windows/AD
suricata-update enable-source stamus/lateral    # Lateral movement SMB/DCERPC
suricata-update enable-source tgreen/hunting    # Threat hunting général
suricata-update enable-source etnetera/aggressive
suricata-update enable-source abuse.ch/sslbl-ja3
suricata-update disable-source et/open          # Déjà géré par OPNsense UI
```

> ⚠️ `abuse.ch/feodotracker` désactivé — déjà présent dans OPNsense (`abuse.ch.feodotracker.rules`).

### Conflit avec OPNsense — architecture

OPNsense génère `suricata.yaml` avec cette structure :

```yaml
default-rule-path: /usr/local/etc/suricata/opnsense.rules
rule-files:
  - suricata.rules          ← ignoré (écrasé par installed_rules.yaml)
include:
  - installed_rules.yaml    ← liste effective des fichiers chargés
```

**Solution :** sortir suricata-update directement dans `opnsense.rules/` et ajouter `suricata.rules` à `installed_rules.yaml`.

### disable.conf — exclure les règles DNP3

OPNsense désactive le protocole DNP3 (SCADA) — les distribution rules correspondantes font planter le chargement.

```bash
mkdir -p /var/lib/suricata/update
nano /var/lib/suricata/update/disable.conf
```

Contenu :
```
re:SURICATA DNP3
```

### Déploiement

```bash
suricata-update \
  --disable-conf /var/lib/suricata/update/disable.conf \
  -o /usr/local/etc/suricata/opnsense.rules \
  --no-test

echo " - suricata.rules" >> /usr/local/etc/suricata/installed_rules.yaml
kill -USR2 `pgrep -x suricata | head -1`
```

> ⚠️ `--no-test` obligatoire — en Suricata 8.x, la redéfinition de `rule-files` par `installed_rules.yaml` génère un exit code 1 en mode `-T` même si les règles sont valides. Le service fonctionne normalement.

### Script de mise à jour

```bash
nano /usr/local/bin/update-suricata-rules.sh
```

```sh
#!/bin/sh
/usr/local/bin/suricata-update \
  --disable-conf /var/lib/suricata/update/disable.conf \
  -o /usr/local/etc/suricata/opnsense.rules \
  --no-test

grep -q "suricata\.rules" /usr/local/etc/suricata/installed_rules.yaml || \
  echo " - suricata.rules" >> /usr/local/etc/suricata/installed_rules.yaml

kill -USR2 `pgrep -x suricata | head -1`
echo "suricata-update done: `date`"
```

```bash
chmod +x /usr/local/bin/update-suricata-rules.sh
```

### Cron — lundi 3h

```
# /etc/cron.d/suricata-update
0	3	*	*	1	root	/usr/local/bin/update-suricata-rules.sh >> /var/log/suricata-update.log 2>&1
```

---

## Partie 2 — NF Rules (networkforensic.dk)

### Source

[https://networkforensic.dk/SNORT/default.html](https://networkforensic.dk/SNORT/default.html) — règles écrites en format Snort, mises à jour régulièrement.

| Fichier ZIP | Contenu | Conversion |
|---|---|---|
| `NF-Scanners.zip` | 222 règles Snort — 80 scanners connus | flow + `alert` → `drop` |
| `NF-local.zip` | 729 règles Snort — threat hunting général | flow uniquement |
| `NF-Suricata.zip` | 6 règles Suricata natives — JA3 botnets/RAT | aucune |

### Pourquoi `drop` pour NF-Scanners

En mode `alert` + SOAR, le scanner reçoit une réponse avant le ban → il sait que l'IP existe. En mode `drop` IPS direct, le paquet est bloqué immédiatement sans réponse → invisibilité totale. Suricata en mode IPS sur OPNsense exécute réellement le `drop`.

> ℹ️ Les règles `drop` génèrent quand même un événement dans `eve.json` avec `alert_action: blocked` — UTMStack voit toujours l'alerte.

### Conversions Snort → Suricata 8.x

| Problème | Correction sed |
|---|---|
| `flow:to_server,established` | → `flow:established,to_server` |
| `flow:from_server,established` | → `flow:established,from_server` |
| `flow:from_client,established` | → `flow:established,to_server` |
| `flow:established, to_server` (espace) | → sans espace |
| `;;` double point-virgule | → `;` |
| `flowbits:noalert` | → `noalert` |
| `dsize:X<>Y content:` (semicolon manquant) | → `dsize:X<>Y; content:` |

**SIDs désactivés (incompatibles Suricata 8.x) :**
- `5017877` — PCRE invalide (`\m` non supporté par pcre2)
- `5050006` — sticky buffer incompatible

### Script de mise à jour

```bash
nano /usr/local/bin/update-nf-rules.sh
```

```sh
#!/bin/sh
TMPDIR="/tmp/nf-rules"
RULES_DIR="/usr/local/etc/suricata/opnsense.rules"
CONF_DIR="/conf"
INSTALLED="/usr/local/etc/suricata/installed_rules.yaml"

mkdir -p "$TMPDIR"

fetch -qo "$TMPDIR/NF-Scanners.zip" "https://networkforensic.dk/SNORT/NF-Scanners.zip"
fetch -qo "$TMPDIR/NF-local.zip"    "https://networkforensic.dk/SNORT/NF-local.zip"
fetch -qo "$TMPDIR/NF-Suricata.zip" "https://networkforensic.dk/SNORT/NF-Suricata.zip"

echo "SHA1 NF-Scanners : $(sha1 -q $TMPDIR/NF-Scanners.zip)"
echo "SHA1 NF-local    : $(sha1 -q $TMPDIR/NF-local.zip)"
echo "SHA1 NF-Suricata : $(sha1 -q $TMPDIR/NF-Suricata.zip)"

unzip -o "$TMPDIR/NF-Scanners.zip" -d "$TMPDIR"
unzip -o "$TMPDIR/NF-local.zip"    -d "$TMPDIR"
unzip -o "$TMPDIR/NF-Suricata.zip" -d "$TMPDIR"

# NF-Scanners : flow Snort→Suricata + alert→drop (scanners connus)
sed -e 's/flow:to_server,established/flow:established,to_server/g' \
    -e 's/flow:from_server,established/flow:established,from_server/g' \
    -e 's/flow:from_client,established/flow:established,to_server/g' \
    -e 's/flow:established, to_server/flow:established,to_server/g' \
    -e 's/flow:established, from_server/flow:established,from_server/g' \
    -e 's/^alert/drop/' \
    "$TMPDIR/NF-Scanners.rules" > "$RULES_DIR/NF-Scanners.rules"

# NF-local : flow + corrections Suricata 8.x (garder alert)
sed -e 's/flow:to_server,established/flow:established,to_server/g' \
    -e 's/flow:from_server,established/flow:established,from_server/g' \
    -e 's/flow:from_client,established/flow:established,to_server/g' \
    -e 's/flow:established, to_server/flow:established,to_server/g' \
    -e 's/flow:established, from_server/flow:established,from_server/g' \
    -e 's/;;/;/g' \
    -e 's/flowbits:noalert/noalert/g' \
    -e 's/dsize:\([0-9]*<>[0-9]*\) content:/dsize:\1; content:/g' \
    "$TMPDIR/NF-local.rules" | \
grep -v "sid:5017877\|sid:5050006" > "$RULES_DIR/NF-local.rules"

# NF-Suricata : natif, copie directe
cp "$TMPDIR/NF-Suricata.rules" "$RULES_DIR/NF-Suricata.rules"

# Persistance
cp "$RULES_DIR/NF-Scanners.rules" "$CONF_DIR/"
cp "$RULES_DIR/NF-local.rules"    "$CONF_DIR/"
cp "$RULES_DIR/NF-Suricata.rules" "$CONF_DIR/"

# Ajouter à installed_rules.yaml si absent
grep -q "NF-Scanners" "$INSTALLED" || echo " - NF-Scanners.rules" >> "$INSTALLED"
grep -q "NF-local"    "$INSTALLED" || echo " - NF-local.rules"    >> "$INSTALLED"
grep -q "NF-Suricata" "$INSTALLED" || echo " - NF-Suricata.rules" >> "$INSTALLED"

kill -USR2 `pgrep -x suricata | head -1`

echo "Done : $(date)"
echo "NF-Scanners (drop)  : $(grep -c '^drop'  $RULES_DIR/NF-Scanners.rules) règles"
echo "NF-local (alert)    : $(grep -c '^alert' $RULES_DIR/NF-local.rules) règles"
echo "NF-Suricata (drop)  : $(grep -c '^drop'  $RULES_DIR/NF-Suricata.rules) règles"

rm -rf "$TMPDIR"
```

```bash
chmod +x /usr/local/bin/update-nf-rules.sh
```

### Cron — lundi 4h (décalé de suricata-update)

```
# /etc/cron.d/nf-rules
0	4	*	*	1	root	/usr/local/bin/update-nf-rules.sh >> /var/log/nf-rules-update.log 2>&1
```

### Persistance après mises à jour OPNsense — mécanisme syshook

#### Comment fonctionne un syshook OPNsense

OPNsense exécute au démarrage tous les scripts présents dans `/usr/local/etc/rc.syshook.d/start/` par ordre alphabétique. Ces scripts sont des hooks de boot personnalisés — l'équivalent d'un `rc.local` sous Linux. Le préfixe numérique (`98-`) détermine l'ordre d'exécution (après les services système).

**Persistance du hook lui-même :** `/usr/local/etc/` survit aux mises à jour normales OPNsense (c'est une partition de données, pas le système de base). En revanche, une **réinstallation complète** ou une **migration vers une nouvelle VM** efface ce répertoire. La stratégie retenue : sauvegarder le hook dans `/conf/` (toujours persistant, inclus dans les backups OPNsense XML) et le redéployer manuellement si nécessaire.

#### Création initiale du hook

```bash
nano /usr/local/etc/rc.syshook.d/start/98-soar-ban
```

Contenu complet actuel du hook :

```sh
#!/bin/sh
# Hook de boot OPNsense — restaure configurations SOAR + Suricata
cp /conf/soar_ban.sh /usr/local/bin/soar_ban.sh
chmod +x /usr/local/bin/soar_ban.sh
# Restaurer suricata-update si OPNsense a régénéré installed_rules.yaml
grep -q "suricata\.rules" /usr/local/etc/suricata/installed_rules.yaml || \
  echo " - suricata.rules" >> /usr/local/etc/suricata/installed_rules.yaml
# Restaurer les règles NF après mise à jour OPNsense
cp /conf/NF-Scanners.rules /usr/local/etc/suricata/opnsense.rules/
cp /conf/NF-local.rules    /usr/local/etc/suricata/opnsense.rules/
cp /conf/NF-Suricata.rules /usr/local/etc/suricata/opnsense.rules/
grep -q "NF-Scanners" /usr/local/etc/suricata/installed_rules.yaml || echo " - NF-Scanners.rules" >> /usr/local/etc/suricata/installed_rules.yaml
grep -q "NF-local"    /usr/local/etc/suricata/installed_rules.yaml || echo " - NF-local.rules"    >> /usr/local/etc/suricata/installed_rules.yaml
grep -q "NF-Suricata" /usr/local/etc/suricata/installed_rules.yaml || echo " - NF-Suricata.rules" >> /usr/local/etc/suricata/installed_rules.yaml
# Restaurer suricata.yaml si threshold-file absent
grep -q "threshold-file" /usr/local/etc/suricata/suricata.yaml || \
  cp /conf/suricata.yaml /usr/local/etc/suricata/suricata.yaml
# Restaurer cron Spamhaus DROP
cp /conf/suricata-drop-fix /etc/cron.d/suricata-drop-fix
exit 0
```

```bash
chmod +x /usr/local/etc/rc.syshook.d/start/98-soar-ban
```

#### Sauvegarde dans /conf/

```bash
cp /usr/local/etc/rc.syshook.d/start/98-soar-ban /conf/98-soar-ban
```

`/conf/` est inclus dans les backups XML OPNsense (**System → Configuration → Backups**). En cas de réinstallation, restaurer le backup XML suffit à récupérer `/conf/98-soar-ban`, puis redéployer manuellement :

```bash
cp /conf/98-soar-ban /usr/local/etc/rc.syshook.d/start/98-soar-ban
chmod +x /usr/local/etc/rc.syshook.d/start/98-soar-ban
```

#### Vérification

```bash
sh -n /usr/local/etc/rc.syshook.d/start/98-soar-ban  # syntaxe OK si aucune sortie
sh /usr/local/etc/rc.syshook.d/start/98-soar-ban      # test d'exécution manuelle
```

> ℹ️ Le contenu complet du hook est centralisé dans la section **Partie 3 → Persistance après mises à jour OPNsense — mécanisme syshook** ci-dessous.

---

## Partie 3 — Réduction du bruit avec threshold.config

### Contexte

OPNsense ne configure pas `threshold.config` par défaut. Le fichier n'est pas référencé dans `suricata.yaml` généré automatiquement — Suricata l'ignore complètement même s'il existe sur disque.

Sans ce mécanisme, certaines signatures légitimes mais très répétitives (Mirai botnet, wget injection par le même bot, anomalies TCP) génèrent des dizaines d'alertes par heure sans valeur ajoutée.

> ⚠️ `threshold.config` se charge **uniquement au démarrage de Suricata** — un `kill -USR2` (rechargement des règles) ne le relit pas. Toute modification nécessite `service suricata restart`.

### Création du fichier threshold.config

```bash
nano /usr/local/etc/suricata/threshold.config
```

Deux types d'entrées :

**`suppress`** — supprime complètement les alertes d'un SID :
```
suppress gen_id 1, sig_id 2210008
```

**`threshold`** — limite à N alertes par source/heure :
```
threshold gen_id 1, sig_id 2610808, type threshold, track by_src, count 1, seconds 3600
```

### Suppressions et thresholds en place

```
# Bruit TCP/HTTP infrastructure — supprimés le 2026-06-03
# SURICATA STREAM anomalies (TCP normal avec middleboxes/NAT)
suppress gen_id 1, sig_id 2221010   # HTTP unable to match response
suppress gen_id 1, sig_id 2210008   # STREAM 3way SYN resend
suppress gen_id 1, sig_id 2210022   # STREAM anomalie
suppress gen_id 1, sig_id 2210023   # STREAM anomalie
suppress gen_id 1, sig_id 2210024   # STREAM anomalie
suppress gen_id 1, sig_id 2210025   # STREAM anomalie
suppress gen_id 1, sig_id 2210026   # STREAM anomalie
suppress gen_id 1, sig_id 2210027   # STREAM anomalie
suppress gen_id 1, sig_id 2210028   # STREAM anomalie
suppress gen_id 1, sig_id 2210042   # STREAM ESTABLISHED SYN resend
suppress gen_id 1, sig_id 2210043   # STREAM SYNACK wrong ack
suppress gen_id 1, sig_id 2210044   # STREAM TIMEWAIT anomalie
suppress gen_id 1, sig_id 2210045   # STREAM Packet invalid timestamp

# Thresholds — 1 alerte par IP source par heure
# TGI HUNT wget injection (Mirai botnet en boucle)
threshold gen_id 1, sig_id 2610808, type threshold, track by_src, count 1, seconds 3600
threshold gen_id 1, sig_id 2610850, type threshold, track by_src, count 1, seconds 3600

# Faux positif — OPNsense External IP lookup (ipify.org)
suppress gen_id 1, sig_id 2047703, track by_src, ip 192.168.1.203
```

> ⚠️ **`suppress` ne fonctionne PAS sur les règles `drop`** — testé avec SID 7000005 (NGROK JA3). Le suppress empêche l'`alert` mais le `drop` continue de fire. Pour les règles `drop`, modifier la source de la règle directement (voir section NF-Suricata ci-dessous).

| Type de règle | suppress/threshold | Modification directe |
|---|---|---|
| `alert` | ✅ fonctionne | pas nécessaire |
| `drop` | ❌ ne fonctionne pas | ✅ modifier la règle |

### Faux positif NGROK JA3 — CrowdSec CAPI (règle drop)

CrowdSec (écrit en Go) utilise un fingerprint JA3 identique à NGROK (aussi en Go). La règle NF SID 7000005 (`drop`) bloque les connexions CrowdSec CAPI sortantes d'OPNsense.

**Le `suppress` dans threshold.config ne fonctionne pas** sur cette règle `drop`. Fix : modifier la règle directement dans `NF-Suricata.rules` pour exclure l'IP WAN d'OPNsense :

```
# Avant (bloque tout $HOME_NET, y compris OPNsense)
drop tls $HOME_NET 1024: -> $EXTERNAL_NET 443 (msg:"NF - NGROK Tunnels - JA3 match"; ...

# Après (exclut OPNsense WAN)
drop tls [$HOME_NET,!192.168.1.203] 1024: -> $EXTERNAL_NET 443 (msg:"NF - NGROK Tunnels - JA3 match"; ...
```

Cette modification est automatiquement réappliquée par `update-nf-rules.sh` après chaque mise à jour des règles NF (voir section Partie 2).

### Déclaration dans suricata.yaml

OPNsense ne référence pas automatiquement `threshold.config`. Il faut ajouter la directive manuellement :

```bash
nano /usr/local/etc/suricata/suricata.yaml
```

Ajouter `threshold-file` juste après `default-rule-path` :

```yaml
default-rule-path: /usr/local/etc/suricata/opnsense.rules
threshold-file: /usr/local/etc/suricata/threshold.config
rule-files:
  - suricata.rules
```

> ⚠️ **Ne pas utiliser sed** pour cette modification — la syntaxe `\n` et les chemins avec `/` sont problématiques sur FreeBSD/csh.

Vérification :
```bash
grep "threshold-file" /usr/local/etc/suricata/suricata.yaml
```

Puis restart (obligatoire — `kill -USR2` ne recharge pas threshold.config) :
```bash
service suricata restart
```

### Persistance — OPNsense peut régénérer suricata.yaml

OPNsense régénère `suricata.yaml` lors des mises à jour système ou d'une réinstallation du package Suricata — la directive `threshold-file` est alors perdue.

**Solution : ajouter le contrôle dans le hook de boot `98-soar-ban`**

Ajouter dans `/usr/local/etc/rc.syshook.d/start/98-soar-ban` :

```sh
# Vérifier que threshold.config est référencé dans suricata.yaml
grep -q "threshold-file" /usr/local/etc/suricata/suricata.yaml || \
  sed -i '' 's|classification-file: /usr/local/etc/suricata/classification.config|classification-file: /usr/local/etc/suricata/classification.config\nthreshold-file: /usr/local/etc/suricata/threshold.config|' \
  /usr/local/etc/suricata/suricata.yaml
```

Ce bloc vérifie la présence de `threshold-file` à chaque boot et la réinsère si manquante. `threshold.config` lui-même ne risque pas d'être effacé car il ne fait pas partie des fichiers gérés par OPNsense.

### Persistance suricata.yaml — approche cp

OPNsense régénère `suricata.yaml` régulièrement et supprime la directive `threshold-file`. L'approche la plus fiable est de sauvegarder le fichier complet :

```bash
# Après avoir configuré threshold-file manuellement
cp /usr/local/etc/suricata/suricata.yaml /conf/suricata.yaml
```

Dans le hook `98-soar-ban` :

```sh
# Restaurer suricata.yaml si threshold-file absent
grep -q "threshold-file" /usr/local/etc/suricata/suricata.yaml || \
  cp /conf/suricata.yaml /usr/local/etc/suricata/suricata.yaml
```

> ⚠️ Si tu modifies des réglages Suricata via l'interface OPNsense, pense à refaire `cp /usr/local/etc/suricata/suricata.yaml /conf/suricata.yaml` pour mettre à jour le backup.

---

## Partie 4 — Spamhaus DROP en mode drop

> ℹ️ **Vérification 2026-06-30** — Contrôle de l'état réel, avec une nuance importante entre les deux flux regroupés sous ce titre :
>
> - **Spamhaus** (règles `ET DROP Spamhaus...`, dans `drop.rules`) : 0 ligne `alert` restante ce matin-là. Ce résultat ne prouve **pas** une livraison native en `drop` par ET — il confirme que le mécanisme ci-dessous, déployé depuis le 2026-06-10/11 (cron `suricata-drop-fix`, 00:30 quotidien), fonctionne correctement : le téléchargement nocturne OPNsense (00:00) régénère `drop.rules` en `alert`, et le cron de 00:30 reconvertit avant toute vérification matinale. La procédure ci-dessous reste donc nécessaire et active pour Spamhaus.
> - **Dshield** (règles `ET DROP Dshield...`, sid 2402000+) : vit en réalité dans un fichier séparé, **`dshield.rules`**, non couvert par le cron `suricata-drop-fix` (qui ne cible que `drop.rules`). Vérifié déjà en `drop ip [...]` directement à la source, sans aucune action de notre part. Pour ce flux précis, la livraison native en `drop` par ET est confirmée — aucune action requise.

### Problème

Les règles ET DROP (Spamhaus, Dshield) sont en mode `alert` par défaut. Les IPs les plus dangereuses d'Internet passent le firewall — elles sont détectées mais **pas bloquées**.

### Fix — sed + rechargement à chaud

```bash
sed -i '' 's/^alert/drop/' /usr/local/etc/suricata/opnsense.rules/drop.rules
kill -USR2 `pgrep -x suricata`

# Vérifier
grep -c "^drop" /usr/local/etc/suricata/opnsense.rules/drop.rules
grep -c "^alert" /usr/local/etc/suricata/opnsense.rules/drop.rules
```

### Persistance — cron quotidien

Le download nocturne des règles (00:00) régénère `drop.rules` en mode `alert`. Un cron à 00:30 corrige automatiquement :

```bash
nano /etc/cron.d/suricata-drop-fix
```

```
30 0 * * * root sed -i '' 's/^alert/drop/' /usr/local/etc/suricata/opnsense.rules/drop.rules && kill -USR2 `pgrep -x suricata`
```

```bash
cp /etc/cron.d/suricata-drop-fix /conf/suricata-drop-fix
```

Dans le hook `98-soar-ban`, ajouter :

```sh
cp /conf/suricata-drop-fix /etc/cron.d/suricata-drop-fix
```

---

## Partie 5 — CINS Active Threat Intelligence en mode drop

### Problème

Contrairement à Spamhaus et Dshield (Partie 4, nativement en `drop`), le flux **ET CINS Active Threat Intelligence** (`ciarmy.rules` — CINS Army, liste de réputation IP) est livré par Emerging Threats en mode `alert`. Les IP listées comme malveillantes par CINS traversent donc le firewall sans être bloquées :

```
log.alert.action: allowed
log.alert.metadata.tag: CINS
log.alert.signature: "ET CINS Active Threat Intelligence Poor Reputation IP group X"
```

Volume mesuré : **299 règles** au format `alert ip [...] any -> $HOME_NET any` dans `ciarmy.rules`, organisées en groupes (`group 1` à `group N`).

### Fix — sed ciblé + rechargement à chaud

À la différence de la Partie 4 (transformation globale de `drop.rules`), le `sed` cible spécifiquement le format `alert ip` propre à `ciarmy.rules`, pour éviter tout effet de bord sur d'autres syntaxes de règles potentiellement présentes dans le même fichier :

```bash
cp /usr/local/etc/suricata/opnsense.rules/ciarmy.rules /conf/ciarmy.rules.backup-`date +%Y%m%d`
```

> ⚠️ Utiliser des **backticks**, pas `$()` — csh (shell par défaut OPNsense) ne supporte pas la substitution de commande au format bash et renvoie `Illegal variable name.`

```bash
nano /usr/local/bin/ciarmy-drop-fix.sh
```

```sh
#!/bin/sh
sed -i '' 's/^alert ip/drop ip/' /usr/local/etc/suricata/opnsense.rules/ciarmy.rules
kill -USR2 `pgrep -x suricata`
```

```bash
chmod +x /usr/local/bin/ciarmy-drop-fix.sh
sh /usr/local/bin/ciarmy-drop-fix.sh

# Vérifier
grep -c "^drop ip"  /usr/local/etc/suricata/opnsense.rules/ciarmy.rules   # → 299
grep -c "^alert ip" /usr/local/etc/suricata/opnsense.rules/ciarmy.rules   # → 0
```

Confirmation du rechargement (chercher dans le log Suricata courant — `latest.log`, pas un fichier daté) :

```bash
tail -50 /var/log/suricata/latest.log | grep -i "reload complete"
# → [Notice] -- rule reload complete
```

### Persistance — cron quotidien

`ciarmy.rules` étant un flux ET re-téléchargé périodiquement (révision quasi quotidienne), toute modification manuelle est écrasée au prochain refresh sans automatisation :

```bash
nano /etc/cron.d/ciarmy-drop-fix
```

```
30 0 * * * root /usr/local/bin/ciarmy-drop-fix.sh
```

```bash
cp /usr/local/bin/ciarmy-drop-fix.sh /conf/ciarmy-drop-fix.sh
cp /etc/cron.d/ciarmy-drop-fix /conf/ciarmy-drop-fix
```

Dans le hook `98-soar-ban`, ajouter :

```sh
cp /conf/ciarmy-drop-fix.sh /usr/local/bin/ciarmy-drop-fix.sh && chmod +x /usr/local/bin/ciarmy-drop-fix.sh
cp /conf/ciarmy-drop-fix /etc/cron.d/ciarmy-drop-fix
```

### Pourquoi 299 règles individuelles plutôt qu'une transformation via l'UI

OPNsense permet de basculer une règle individuelle Alert/Drop via Services → Intrusion Detection → Administration → Rules, mais sans action groupée par fichier source. Avec 299 règles à traiter, le `sed` reste la seule approche réaliste — l'UI étant réservée à des ajustements ponctuels sur une poignée de règles.

### Validation en conditions réelles

Confirmation côté Log Explorer UTMStack — une IP CINS bloquée par Suricata (`action: blocked`) déclenche ensuite le flow SOAR `Suricata Network Anomaly Detected`, qui ban automatiquement l'IP via CrowdSec :

```bash
cscli decisions list | grep "<ip>"
# → reason=utmstack, decisions: ban:1
```

Boucle complète vérifiée de bout en bout : CINS détecté → bloqué par Suricata → remonté UTMStack → SOAR → ban CrowdSec.

Une fois bloqué côté Suricata, le trafic CINS bascule de `action: allowed` à `action: blocked` — il devient alors éligible aux exclusions de bruit posées côté règles de corrélation UTMStack, voir [annexe — Réduction du bruit, règles de corrélation UTMStack](correlation-rules-tuning.md).

---

## Vérification globale

```bash
# Règles NF chargées
grep -c "^drop"  /usr/local/etc/suricata/opnsense.rules/NF-Scanners.rules
grep -c "^alert" /usr/local/etc/suricata/opnsense.rules/NF-local.rules
grep -c "^drop"  /usr/local/etc/suricata/opnsense.rules/NF-Suricata.rules

# threshold-file présent dans suricata.yaml
grep "threshold-file" /usr/local/etc/suricata/suricata.yaml

# Erreurs au chargement Suricata
grep -i "error" /var/log/suricata/suricata_$(date +%Y%m%d).log | grep "NF-"

# Suricata tourne
service suricata status
```

---

## Gestion des règles NF — CLI uniquement

> ⚠️ Les règles NF ne sont **pas visibles dans l'UI OPNsense** (Services → Intrusion Detection → Rules). L'UI ne gère que les règles téléchargées via son propre système (onglet Download). Les règles NF sont chargées directement par Suricata via `installed_rules.yaml` — toute gestion passe par la CLI.

```bash
# Chercher une règle par SID
grep "sid:5034006" /usr/local/etc/suricata/opnsense.rules/NF-Scanners.rules

# Lister les règles par scanner
grep "Censys" /usr/local/etc/suricata/opnsense.rules/NF-Scanners.rules
grep "Shodan" /usr/local/etc/suricata/opnsense.rules/NF-Scanners.rules

# Désactiver une règle spécifique (commenter)
sed -i '' 's/^drop.*sid:5034006.*/#&/' /usr/local/etc/suricata/opnsense.rules/NF-Scanners.rules

# Recharger Suricata après modification
kill -USR2 `pgrep -x suricata | head -1`
```

---

## Persistance — Problème connu

OPNsense régénère le répertoire `opnsense.rules/` lors de chaque téléchargement de règles via l'UI (**Download → Apply**). Les fichiers NF sont alors supprimés. Le hook `98-soar-ban` ne restaure qu'au boot — pas lors d'un Download en cours d'utilisation.

**Solution : cron de surveillance toutes les 30 minutes**

```
# /etc/cron.d/nf-rules-check
*/30	*	*	*	*	root	test -f /usr/local/etc/suricata/opnsense.rules/NF-Scanners.rules || /usr/local/bin/update-nf-rules.sh >> /var/log/nf-rules-update.log 2>&1
```

Si `NF-Scanners.rules` est absent → `update-nf-rules.sh` est relancé automatiquement.

---

> ℹ️ *Testé sur OPNsense 26.1, Suricata 8.0.4 / 8.0.5, suricata-update 1.3.7*

---

[← SOAR & Automatisation](05-soar.md) | [→ SOC AI](06-soc-ai.md) | [Annexe — Réduction du bruit, corrélation UTMStack →](correlation-rules-tuning.md)
