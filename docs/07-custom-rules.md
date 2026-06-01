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

### Persistance après mises à jour OPNsense

Ajouter dans `/usr/local/etc/rc.syshook.d/start/98-soar-ban` :

```sh
# Restaurer les règles NF
cp /conf/NF-Scanners.rules /usr/local/etc/suricata/opnsense.rules/
cp /conf/NF-local.rules    /usr/local/etc/suricata/opnsense.rules/
cp /conf/NF-Suricata.rules /usr/local/etc/suricata/opnsense.rules/
grep -q "NF-Scanners" /usr/local/etc/suricata/installed_rules.yaml || echo " - NF-Scanners.rules" >> /usr/local/etc/suricata/installed_rules.yaml
grep -q "NF-local"    /usr/local/etc/suricata/installed_rules.yaml || echo " - NF-local.rules"    >> /usr/local/etc/suricata/installed_rules.yaml
grep -q "NF-Suricata" /usr/local/etc/suricata/installed_rules.yaml || echo " - NF-Suricata.rules" >> /usr/local/etc/suricata/installed_rules.yaml

# Restaurer suricata-update
grep -q "suricata\.rules" /usr/local/etc/suricata/installed_rules.yaml || \
  echo " - suricata.rules" >> /usr/local/etc/suricata/installed_rules.yaml
```

---

## Vérification

```bash
# Règles chargées
grep -c "^drop"  /usr/local/etc/suricata/opnsense.rules/NF-Scanners.rules
grep -c "^alert" /usr/local/etc/suricata/opnsense.rules/NF-local.rules
grep -c "^drop"  /usr/local/etc/suricata/opnsense.rules/NF-Suricata.rules

# Erreurs au chargement
grep -i "error" /var/log/suricata/suricata_$(date +%Y%m%d).log | grep "NF-"

# Suricata tourne
service suricata status
```

---

> ℹ️ *Testé sur OPNsense 26.1, Suricata 8.0.4, suricata-update 1.3.7*

---

[← SOAR & Automatisation](05-soar.md) | [→ SOC AI](06-soc-ai.md)
