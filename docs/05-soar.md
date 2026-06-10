---
title: "SOAR & Automatisation — UTMStack Lab | DoIt4Everyone"
description: "Configuration du SOAR UTMStack v11.2.8 — Ban automatique CrowdSec via SSH, déduplication, replay detection, fermeture dynamique des alertes."
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

# SOAR & Automatisation

> [← Retour à l'index](../)

> ⚠️ **Version v0.2** — Les tests Red Team / Kali seront ajoutés en V4.

---

## Architecture

```
UTMStack détecte une alerte (Known Malicious IP / Suricata Anomaly)
    ↓
Flow SOAR déclenche soar_ban.bat sur gest-srv (agent Windows)
    ↓
SSH synchrone → OPNsense (10.100.1.254) — ConnectTimeout=3s
    ↓
soar_ban.sh — Replay detection + déduplication 7j + cscli ban
    ↓
CrowdSec banne l'IP 24h
    ↓
logger syslog → CROWDSEC_BAN avec country/ASN → UTMStack
    ↓
cron utmstack-close-alerts.sh (5 min) — ferme les alertes SOAR + purge PENDING
```

> ℹ️ **Country et ASN** sont fournis directement par les variables SOAR `$(adversary.geolocation.countryCode)` et `$(adversary.geolocation.asn)` — aucun lookup GeoIP externe requis.

---

## Étape 1 — Clé SSH pour le compte SYSTEM

L'agent UTMStack tourne sous `NT AUTHORITY\SYSTEM`. La clé SSH doit être accessible depuis ce contexte.

### Génération de la paire de clés

Sur **gest-srv** en PowerShell admin :

```powershell
ssh-keygen -t ed25519 -f C:\UTMStack\ssh\soar_key -N ""
```

### Dépôt de la clé dans le profil SYSTEM

```powershell
mkdir C:\Windows\System32\config\systemprofile\.ssh -ErrorAction SilentlyContinue

schtasks /create /tn "CopySOARKey" /tr "cmd /c copy /y C:\UTMStack\ssh\soar_key C:\Windows\System32\config\systemprofile\.ssh\soar_key" /sc once /st 00:00 /ru SYSTEM /f
schtasks /run /tn "CopySOARKey"
ping -n 8 127.0.0.1 > nul
schtasks /delete /tn "CopySOARKey" /f
```

### Autorisation de la clé sur OPNsense

```bash
# Afficher la clé publique (depuis gest-srv)
type C:\UTMStack\ssh\soar_key.pub

# Sur OPNsense
echo "ssh-ed25519 AAAA... utmstack-soar" > /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
```

> ⚠️ **Persistance** — Configurer la clé via **System → Access → Users → root → Authorized Keys** dans l'interface GUI OPNsense pour survivre aux reboots.

### Test depuis SYSTEM

```cmd
schtasks /create /tn "SOARTest" /tr "cmd /c C:\Windows\System32\OpenSSH\ssh.exe -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -o BatchMode=yes -o ConnectTimeout=3 -i C:\Windows\System32\config\systemprofile\.ssh\soar_key root@10.100.1.254 echo ssh_ok >> C:\UTMStack\soar_debug.log 2>&1" /sc once /st 00:00 /ru SYSTEM /f
schtasks /run /tn "SOARTest"
ping -n 8 127.0.0.1 > nul
type C:\UTMStack\soar_debug.log
```

---

## Étape 2 — Script soar_ban.sh sur OPNsense

4 niveaux de protection contre le replay et les bans intempestifs.

```bash
nano /usr/local/bin/soar_ban.sh
```

```sh
#!/bin/sh
LOG="/var/log/soar_ban.log"
IP=$1
COUNTRY=$2
ASN=$3
EVENT_TIMESTAMP=$4
ALERT_ID=$5

echo "$(date) START: IP=$IP COUNTRY=$COUNTRY ASN=$ASN TS=$EVENT_TIMESTAMP" >> "$LOG"

# -------------------------------------------------------
# 0. Protection IPs internes
# -------------------------------------------------------
# Après ajout de 192.168.1.0/24 à HOME_NET, UTMStack peut voir
# l'IP WAN OPNsense comme adversary dans certaines alertes (flow inversé).
case "$IP" in
    192.168.1.*|10.100.1.*|10.100.2.*|127.0.0.1)
        echo "$(date) SKIP: $IP is internal, not banning" >> "$LOG"
        echo "OK: $IP (internal)"
        exit 0
        ;;
esac

# -------------------------------------------------------
# 1. Détection de replay par timestamp de l'événement
# -------------------------------------------------------
# Les timestamps SOAR sont en UTC (suffixe Z) — TZ=UTC obligatoire
if [ -n "$EVENT_TIMESTAMP" ] && [ "$EVENT_TIMESTAMP" != "null" ] && [ "$EVENT_TIMESTAMP" != '$(timestamp)' ]; then
    TS_CLEAN=$(echo "$EVENT_TIMESTAMP" | sed 's/\.[0-9]*//' | sed 's/+[0-9:]*//' | sed 's/Z$//' | tr 'T' ' ')
    EVENT_UNIX=$(TZ=UTC date -j -f "%Y-%m-%d %H:%M:%S" "$TS_CLEAN" "+%s" 2>/dev/null)
    NOW_UNIX=$(date +%s)
    if [ -n "$EVENT_UNIX" ] && [ "$EVENT_UNIX" -gt 0 ]; then
        AGE=$((NOW_UNIX - EVENT_UNIX))
        echo "$(date) TIMESTAMP: age=${AGE}s" >> "$LOG"
        if [ "$AGE" -gt 7200 ]; then
            echo "$(date) REPLAY: event is ${AGE}s old, skipping ban for $IP" >> "$LOG"
            echo "OK: $IP (replay)"
            exit 0
        fi
    else
        echo "$(date) TIMESTAMP: parse failed for '$EVENT_TIMESTAMP', skipping replay check" >> "$LOG"
    fi
fi

# -------------------------------------------------------
# 2. Déduplication IP 7 jours — filet de sécurité
# -------------------------------------------------------
RECENT_BANS="/conf/soar_recent_bans.txt"

if [ -f "$RECENT_BANS" ]; then
    CUTOFF=$(date -v-168H +%s 2>/dev/null)
    if [ -z "$CUTOFF" ]; then
        CUTOFF=$(date -d '168 hours ago' +%s 2>/dev/null)
    fi
    if [ -n "$CUTOFF" ]; then
        awk -v cutoff="$CUTOFF" '$1 > cutoff' "$RECENT_BANS" > /tmp/bans_clean.txt
        mv /tmp/bans_clean.txt "$RECENT_BANS"
    fi
fi

if grep -q " $IP$" "$RECENT_BANS" 2>/dev/null; then
    echo "$(date) DEDUPE 7j: $IP already processed, skipping" >> "$LOG"
    if [ -n "$ALERT_ID" ] && [ "$ALERT_ID" != "null" ]; then
        TOKEN=$(cat /conf/utmstack_token.txt 2>/dev/null)
        if [ -n "$TOKEN" ]; then
            curl -sk -X POST "https://10.100.1.150/api/utm-alerts/status" \
              -H "Authorization: Bearer $TOKEN" \
              -H "Content-Type: application/json" \
              -d "{\"alertIds\":[\"$ALERT_ID\"],\"status\":5,\"statusObservation\":\"Auto-closed by SOAR — IP already in dedup 7j\"}" \
              >> "$LOG" 2>&1
        fi
    fi
    echo "OK: $IP (dedup)"
    exit 0
fi

# -------------------------------------------------------
# 3. Bannissement CrowdSec
# -------------------------------------------------------
[ -z "$COUNTRY" ] || [ "$COUNTRY" = "null" ] && COUNTRY="Unknown"
[ -z "$ASN" ] || [ "$ASN" = "null" ] && ASN="AS0"

if ! /usr/local/bin/cscli decisions list --ip "$IP" 2>/dev/null | grep -q "ban"; then
    /usr/local/bin/cscli decisions add --ip "$IP" --duration 24h --reason utmstack
    echo "$(date +%s) $IP" >> "$RECENT_BANS"
    logger -p local5.alert -t crowdsec \
      "CROWDSEC_BAN {\"event_type\":\"ban\",\"ip\":\"$IP\",\"reason\":\"utmstack\",\"country\":\"$COUNTRY\",\"as\":\"$ASN\",\"type\":\"ban\"}"
    echo "$(date) BAN: $IP ($COUNTRY / $ASN)" >> "$LOG"
    echo "OK: BAN $IP ($COUNTRY / $ASN)"
else
    echo "$(date) SKIP: $IP already in CrowdSec" >> "$LOG"
    echo "OK: $IP (exists)"
fi

# -------------------------------------------------------
# 4. Fermeture de l'alerte via UTMStack API
# (ALERT_ID non exposé en v11.2.8 CE — section prête pour version future)
# -------------------------------------------------------
if [ -n "$ALERT_ID" ] && [ "$ALERT_ID" != "null" ]; then
    TOKEN=$(cat /conf/utmstack_token.txt 2>/dev/null)
    if [ -n "$TOKEN" ]; then
        curl -sk -X POST "https://10.100.1.150/api/utm-alerts/status" \
          -H "Authorization: Bearer $TOKEN" \
          -H "Content-Type: application/json" \
          -d "{\"alertIds\":[\"$ALERT_ID\"],\"status\":5,\"statusObservation\":\"Auto-closed by SOAR after CrowdSec ban\"}" \
          >> "$LOG" 2>&1
        echo "$(date) ALERT CLOSED: $ALERT_ID" >> "$LOG"
    fi
fi

echo "$(date) END: completed for $IP" >> "$LOG"
```

```bash
chmod +x /usr/local/bin/soar_ban.sh
cp /usr/local/bin/soar_ban.sh /conf/soar_ban.sh
```

> ⚠️ **TZ=UTC obligatoire** — Les timestamps SOAR sont en UTC (suffixe Z). Sans ce préfixe, `date -j` sur FreeBSD interprète l'heure comme locale (CEST = UTC+2), causant un faux-positif de 2h qui déclenche systématiquement la détection de replay.

> ℹ️ **stdout aux points de sortie** — chaque `echo "OK: ..."` sans redirection vers `$LOG` est capturé par l'agent UTMStack via SSH et affiché dans la console interactive. Nécessaire pour que l'agent reçoive une réponse.

> ℹ️ **nohup ne fonctionne pas en csh** (shell OPNsense/FreeBSD). L'exécution en arrière-plan via SSH doit utiliser `sh -c '... &'`.

### Persistance aux reboots OPNsense

```bash
nano /usr/local/etc/rc.syshook.d/start/98-soar-ban
```

```sh
#!/bin/sh
cp /conf/soar_ban.sh /usr/local/bin/soar_ban.sh
chmod +x /usr/local/bin/soar_ban.sh
```

```bash
chmod +x /usr/local/etc/rc.syshook.d/start/98-soar-ban
```

### Token UTMStack API (pour section 4)

```csh
# Stocker le token JWT de session browser (valide ~13 mois)
# Extraire depuis F12 → Network → Authorization: Bearer <token>
echo "<TOKEN>" > /conf/utmstack_token.txt
chmod 600 /conf/utmstack_token.txt
```

### Test

```bash
/usr/local/bin/soar_ban.sh 45.205.1.71 ES 198193 2026-06-07T10:30:00Z
# → OK: BAN 45.205.1.71 (ES / 198193)
# → Sun Jun 7 12:32:00 CEST 2026 BAN: 45.205.1.71 (ES / 198193)

/usr/local/bin/soar_ban.sh 45.205.1.71 ES 198193 2026-06-07T10:30:00Z
# → OK: 45.205.1.71 (dedup)
```

---

## Étape 3 — Script soar_ban.bat sur gest-srv

```powershell
Set-Content "C:\Program Files\UTMStack\UTMStack Agent\soar_ban.bat" -Encoding ASCII -Value '@echo off
if "%1"=="" exit /b 1
set LOGFILE=C:\Program Files\UTMStack\UTMStack Agent\logs\soar.log
for %%F in ("%LOGFILE%") do if %%~zF gtr 1048576 del "%LOGFILE%"
echo [%DATE% %TIME%] SOAR triggered - IP: %1 Country: %2 ASN: %3 Timestamp: %4 >> "%LOGFILE%"
C:\Windows\System32\OpenSSH\ssh.exe -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -o BatchMode=yes -o ConnectTimeout=3 -i C:\Windows\System32\config\systemprofile\.ssh\soar_key root@10.100.1.254 "/usr/local/bin/soar_ban.sh %1 %2 %3 %4"
echo [%DATE% %TIME%] Exit: %ERRORLEVEL% >> "%LOGFILE%"
exit 0'
```

> ⚠️ **Encodage** — Utiliser impérativement `-Encoding ASCII`. Un encodage UTF-16 (défaut PowerShell) rend le BAT silencieusement non fonctionnel.

> ℹ️ **SSH synchrone** avec `ConnectTimeout=3` — sur LAN la connexion prend < 1s. L'exécution synchrone permet à l'agent de capturer l'output de soar_ban.sh (`OK: BAN IP...`) et de le retourner à UTMStack.

> ℹ️ **exit 0 explicite** — garantit que l'agent Windows reçoit toujours un code de retour propre, indépendamment du résultat SSH.

> ⚠️ **PENDING comportement** — Même avec exit 0 et output, UTMStack v11.2.8 CE ne marque **jamais** les exécutions SOAR comme COMPLETED via le retour gRPC de l'agent. La purge automatique des PENDING dans `utmstack-close-alerts.sh` reste indispensable. Confirmé par analyse du bytecode Java (`utmstack.war`) et monitoring `utm_alert_response_rule_execution`.

---

## Étape 4 — Flows SOAR dans UTMStack

### Création des règles

Dans UTMStack → **SOAR → Automation Rules → New Rule** :

**Flow 5000 — Known Malicious IP :**

| Champ | Valeur |
|---|---|
| Nom | CrowdSec Ban Known Malicious IP |
| Condition | `name IS Known Malicious IP Detected` |
| Agent | gest-srv |
| Commande | `soar_ban.bat $(adversary.ip) $(adversary.geolocation.countryCode) $(adversary.geolocation.asn) $(timestamp)` |

**Flow 5001 — Suricata Anomaly :**

| Champ | Valeur |
|---|---|
| Nom | CrowdSec Ban Suricata Anomaly |
| Condition | `name IS Suricata Network Anomaly Detected` |
| Agent | gest-srv |
| Commande | `soar_ban.bat $(adversary.ip) $(adversary.geolocation.countryCode) $(adversary.geolocation.asn) $(timestamp)` |

### ⚠️ Bug UTMStack v11.2.8 — Bouton Create Flow

Le bouton **Create Flow** est non fonctionnel dans tous les navigateurs sauf Edge. Même sous Edge, seul **Update Flow** est fiable. Dupliquer un flow existant comme contournement.

### Modification directe en base (recommandée)

```bash
docker exec -it $(docker ps -q -f name=utmstack_postgres) psql -U postgres -d utmstack -c \
"UPDATE utm_alert_response_rule 
SET rule_cmd = 'soar_ban.bat \$(adversary.ip) \$(adversary.geolocation.countryCode) \$(adversary.geolocation.asn) \$(timestamp)'
WHERE id IN (5000, 5001);"
```

> ℹ️ Les modifications de `rule_cmd` dans PostgreSQL prennent effet **sans restart** du backend.

### Variables SOAR disponibles — v11.2.8

Variables confirmées par analyse du code source (`utm_alert_response_rule.sql` extrait de `utmstack.war`) :

| Variable | Description |
|---|---|
| `$(adversary.ip)` | IP de l'attaquant |
| `$(adversary.user)` | Utilisateur attaquant |
| `$(adversary.geolocation.countryCode)` | Pays |
| `$(adversary.geolocation.asn)` | ASN |
| `$(target.user)` | Utilisateur cible |
| `$(target.process)` | Processus cible |
| `$(target.file)` | Fichier cible |
| `$(origin.ip)` | IP d'origine |
| `$(log.message)` | Message du log brut |
| `$(timestamp)` | Timestamp de l'événement original Suricata |

> ⚠️ **L'alert ID n'est pas exposé comme variable SOAR** — ni `$(id)`, `$(alertId)`, `$(alert_id)`, ni `$(uuid)` ne fonctionnent. Confirmé par analyse bytecode Java (`utmstack.war`) et tests exhaustifs. Non documenté sur le GitHub UTMStack ni sur docs.utmstack.com.

---

## Étape 5 — Compatibilité Microsoft Defender for Endpoint

Si MDE est actif sur l'agent Windows, les règles ASR bloquent silencieusement l'exécution des commandes SOAR.

**Symptômes :**
- Timeout dans l'audit SOAR
- Log `soar.log` vide
- Console interactive UTMStack freeze sur gest-srv

**Cause :** La règle ASR `d1e49aac-8f56-4280-b9ba-993a6d77406c` bloque les processus enfants créés par le service agent UTMStack.

**Lab — Offboarder MDE :**
- M365 Defender portal → **Settings → Endpoints → Offboarding** → script local
- Supprimer les clés de registre résiduelles :

```powershell
Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Force
```

**Production — Indicator of Allow :**
- M365 Defender → **Settings → Endpoints → Indicators → Files → Add**
- Hash SHA1 de `utmstack_agent_service_windows_amd64.exe` → Action : **Allow**

---

## Étape 6 — Gestion automatique des alertes et PENDING

### Contexte — Deux problèmes distincts

**Problème 1 — PENDING SOAR (cause racine du replay massif)**

Quand le SOAR envoie une commande à l'agent Windows, l'agent exécute `soar_ban.bat` mais UTMStack v11.2.8 CE **ne marque jamais** l'exécution comme COMPLETED via le retour gRPC — même avec exit 0 et output. Les entrées restent PENDING indéfiniment. UTMStack retente toutes les actions PENDING en batch toutes les 5 minutes → vagues de bans intempestifs.

**Diagnostic :**
```bash
docker exec -it $(docker ps -q -f name=utmstack_postgres) psql -U postgres -d utmstack -c \
"SELECT execution_status, COUNT(*) FROM utm_alert_response_rule_execution GROUP BY execution_status;"
```

**Problème 2 — Replay au redémarrage backend**

Au redémarrage du backend UTMStack, toutes les alertes OPEN sont rejouées par le SOAR → milliers d'exécutions en quelques secondes.

**Solution : toujours utiliser `utmstack-pre-restart.sh` avant tout restart backend.**

---

### Script utmstack-close-alerts.sh — dynamique

Deux fonctions en un seul script :
1. Ferme les alertes gérées par le SOAR **après 15 minutes** — détection dynamique depuis PostgreSQL, zéro maintenance
2. Purge les PENDING SOAR de plus de 3 minutes

```bash
nano /usr/local/bin/utmstack-close-alerts.sh
```

```bash
#!/bin/bash
# utmstack-close-alerts.sh
# 1. Ferme les alertes gérées par le SOAR (dynamique) après 15 minutes
# 2. Purge les PENDING SOAR de plus de 3 minutes
# Cron : */5 * * * * root /usr/local/bin/utmstack-close-alerts.sh >> /var/log/utmstack-close-alerts.log 2>&1
#
# Les alertes NON gérées par le SOAR (PowerShell Empire, Brute Force, etc.)
# restent ouvertes pour investigation par l'analyste SOC.
# Lors de l'ajout d'un nouveau flow SOAR, ce script le prend en compte
# automatiquement — aucune modification requise.

PSQL="docker exec $(docker ps -q -f name=utmstack_postgres) psql -U postgres -d utmstack"

# -------------------------------------------------------
# 1. Fermeture des alertes gérées par le SOAR actif
# -------------------------------------------------------
ALERT_NAMES=$($PSQL -t -A -c \
"SELECT rule_conditions FROM utm_alert_response_rule WHERE rule_active = true;" 2>/dev/null \
| python3 -c "
import sys, json
names = set()
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        conditions = json.loads(line)
        for c in conditions:
            if c.get('field') == 'name' and c.get('operator') == 'IS':
                names.add(c.get('value', ''))
    except: pass
for n in sorted(names):
    if n: print(n)
" 2>/dev/null)

if [ -n "$ALERT_NAMES" ]; then
    JSON_NAMES=$(echo "$ALERT_NAMES" | while read name; do
        echo "\"$name\""
    done | paste -sd ',' -)

    RESULT=$(docker exec $(docker ps -q -f name=utmstack_node1) curl -sk \
      -u 'admin:<OPENSEARCH_PASSWORD>' \
      -X POST "https://localhost:9200/v11-alert-*/_update_by_query" \
      -H "Content-Type: application/json" \
      -d '{
        "query": {
          "bool": {
            "must": [
              {"term": {"status": 2}},
              {"terms": {"name.keyword": ['"$JSON_NAMES"']}},
              {"range": {"@timestamp": {"lt": "now-15m"}}}
            ]
          }
        },
        "script": {
          "source": "ctx._source.status = 5; ctx._source.statusLabel = \"Completed\"; ctx._source.statusObservation = \"Auto-closed — SOAR processed (CrowdSec ban)\"",
          "lang": "painless"
        }
      }' 2>/dev/null)

    UPDATED=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('updated',0))" 2>/dev/null)
    if [ "$UPDATED" != "0" ] && [ -n "$UPDATED" ]; then
        echo "$(date) ALERTS CLOSED: $UPDATED (types: $JSON_NAMES)"
    fi
fi

# -------------------------------------------------------
# 2. Purger les PENDING SOAR de plus de 3 minutes
# -------------------------------------------------------
$PSQL -c "
UPDATE utm_alert_response_rule_execution
SET execution_status = 'COMPLETED', command_result = 'cleared-pending'
WHERE execution_status = 'PENDING'
AND execution_date < NOW() - INTERVAL '3 minutes';" 2>/dev/null | grep -v "^UPDATE 0" | while read line; do
  echo "$(date) PENDING cleared: $line"
done
```

```bash
chmod +x /usr/local/bin/utmstack-close-alerts.sh
```

> ℹ️ **15 minutes** — fenêtre d'investigation pour les alertes SOAR avant fermeture automatique. Le ban CrowdSec ayant déjà été appliqué par soar_ban.sh, le replay SOAR pendant cette fenêtre est inoffensif grâce à la déduplication 7 jours.

> ℹ️ **Détection dynamique** — le script lit `utm_alert_response_rule WHERE rule_active = true` et extrait les noms d'alertes des conditions JSON. Tout nouveau flow SOAR activé est automatiquement inclus sans modifier ce script.

### Cron — toutes les 5 minutes

```bash
nano /etc/cron.d/utmstack-close-alerts
```

```
*/5 * * * * root /usr/local/bin/utmstack-close-alerts.sh >> /var/log/utmstack-close-alerts.log 2>&1
```

### Purge manuelle PENDING

```bash
docker exec -it $(docker ps -q -f name=utmstack_postgres) psql -U postgres -d utmstack -c \
"UPDATE utm_alert_response_rule_execution 
SET execution_status = 'COMPLETED', command_result = 'cleared-pending'
WHERE execution_status = 'PENDING';"
```

---

### Script utmstack-pre-restart.sh

> ⚠️ **Ce script remplace `docker service update --force utmstack_backend` dans toutes les procédures de maintenance.**

```bash
nano /usr/local/bin/utmstack-pre-restart.sh
```

```bash
#!/bin/bash
# À lancer AVANT tout restart du backend UTMStack
# Durée totale : ~8 minutes

PSQL="docker exec $(docker ps -q -f name=utmstack_postgres) psql -U postgres -d utmstack"

echo "$(date) === utmstack-pre-restart.sh démarré ==="

# 1. Désactiver les flows SOAR
echo "$(date) — Désactivation des flows SOAR 5000 et 5001..."
$PSQL -c "UPDATE utm_alert_response_rule SET rule_active = false WHERE id IN (5000, 5001);"

# 2. Fermer TOUTES les alertes ouvertes
echo "$(date) — Fermeture de toutes les alertes OPEN..."
docker exec $(docker ps -q -f name=utmstack_node1) curl -sk \
  -u 'admin:<OPENSEARCH_PASSWORD>' \
  -X POST "https://localhost:9200/v11-alert-*/_update_by_query" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {"term": {"status": 2}},
    "script": {
      "source": "ctx._source.status = 5; ctx._source.statusLabel = \"Completed\"; ctx._source.statusObservation = \"Pre-restart close — prevent SOAR replay\"",
      "lang": "painless"
    }
  }'

echo ""
sleep 5

# 3. Redémarrer le backend
echo "$(date) — Restart utmstack_backend..."
docker service update --force utmstack_backend > /dev/null 2>&1
echo "$(date) — Attente 5 minutes pour vidage de la queue..."
sleep 300

# 4. Deuxième fermeture
echo "$(date) — Deuxième fermeture post-queue..."
docker exec $(docker ps -q -f name=utmstack_node1) curl -sk \
  -u 'admin:<OPENSEARCH_PASSWORD>' \
  -X POST "https://localhost:9200/v11-alert-*/_update_by_query" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {"term": {"status": 2}},
    "script": {
      "source": "ctx._source.status = 5; ctx._source.statusLabel = \"Completed\"; ctx._source.statusObservation = \"Post-restart queue flush\"",
      "lang": "painless"
    }
  }'

echo ""

# 5. Purge PENDING résiduels
echo "$(date) — Purge PENDING..."
$PSQL -c "UPDATE utm_alert_response_rule_execution SET execution_status = 'COMPLETED', command_result = 'pre-restart-purge' WHERE execution_status = 'PENDING';"

# 6. Réactiver les flows SOAR
echo "$(date) — Réactivation des flows SOAR 5000 et 5001..."
$PSQL -c "UPDATE utm_alert_response_rule SET rule_active = true WHERE id IN (5000, 5001);"

echo "$(date) === Terminé ==="
```

```bash
chmod +x /usr/local/bin/utmstack-pre-restart.sh
```

---

### 3 niveaux de protection contre le replay

| Niveau | Mécanisme | Rôle |
|---|---|---|
| **1 — Purge PENDING** | Cron 5min dans `utmstack-close-alerts.sh` | Corrige la cause racine — empêche les retries en batch |
| **2 — Timestamp event > 2h** | `TZ=UTC date -j` dans `soar_ban.sh` | Bloque les bans si UTMStack rejoue un vieux log |
| **3 — Déduplication IP 7 jours** | `/conf/soar_recent_bans.txt` | Filet de sécurité si timestamp indisponible |

---

## Vérification end-to-end

**Log soar.log (gest-srv) :**

```
[07.06.2026 11:04:10] SOAR triggered - IP: 192.168.20.20 Country: XX ASN: 99999 Timestamp: 2026-06-07T11:00:00Z
[07.06.2026 11:04:10] Exit: 0
```

**Log soar_ban.log (OPNsense) :**

```
Sun Jun 7 11:04:10 CEST 2026 START: IP=192.168.20.20 COUNTRY=XX ASN=99999 TS=2026-06-07T11:00:00Z
Sun Jun 7 11:04:10 CEST 2026 TIMESTAMP: age=244s
level=info msg="Decision successfully added"
Sun Jun 7 11:04:10 CEST 2026 BAN: 192.168.20.20 (XX / 99999)
Sun Jun 7 11:04:10 CEST 2026 END: completed for 192.168.20.20
```

**Console interactive UTMStack :**

```
soar_ban.bat 192.168.20.20 XX 99999 2026-06-07T11:00:00Z
OK: BAN 192.168.20.20 (XX / 99999)
```

**Décisions CrowdSec (OPNsense) :**

```
cscli decisions list
→ Ip:192.168.20.20 | utmstack | ban | 23h57m
```

**PENDING dans UTMStack :**
```bash
docker exec -it $(docker ps -q -f name=utmstack_postgres) psql -U postgres -d utmstack -c \
"SELECT execution_status, COUNT(*) FROM utm_alert_response_rule_execution GROUP BY execution_status;"
# → COMPLETED | 631
# → Aucun PENDING
```

---

## Réduction des faux positifs — Règles built-in

Les règles de corrélation built-in (icône 🚫 dans l'UI) ne sont pas modifiables via l'interface. Modification directe en base :

```bash
docker exec -it $(docker ps -q -f name=utmstack_postgres) psql -U postgres -d utmstack
```

**Exclusions connues :**

```sql
-- Exclure Azure AD Connect (AADConnector.psm1)
UPDATE utm_correlation_rules
SET rule_definition_def = rule_definition_def ||
  E'\n&& !contains("log.data.Path", "Microsoft Azure AD Sync")'
WHERE rule_name = 'PowerShell Empire Detection'
AND rule_definition_def NOT LIKE '%Microsoft Azure AD Sync%';

-- Exclure MDE scripts (Log4j scanner, DataCollection)
UPDATE utm_correlation_rules
SET rule_definition_def = rule_definition_def || 
  E'\n&& !contains("log.data.Path", "Windows Defender Advanced Threat Protection")'
WHERE rule_name = 'PowerShell Empire Detection'
AND rule_definition_def NOT LIKE '%Windows Defender Advanced Threat Protection%';
```

Restart backend après modification :

```bash
/usr/local/bin/utmstack-pre-restart.sh
```

---

## Limitations connues — UTMStack v11.2.8 Community Edition

| Limitation | Description | Contournement |
|---|---|---|
| **PENDING permanent** | UTMStack ne marque jamais COMPLETED via gRPC, même avec exit 0 | Cron purge toutes les 5 min |
| **Alert ID non exposé** | `$(alertId)`, `$(id)`, `$(uuid)` retournent null dans les variables SOAR | Fermeture via cron (15 min) |
| **API Keys bloquées** | UI Enterprise — la table `api_keys` existe en base mais l'interface est verrouillée | Token JWT browser (13 mois) dans `/conf/utmstack_token.txt` |
| **Playbooks built-in** | 17 rules prédéfinies Windows/Linux, toutes désactivées, aucune pour Suricata/réseau | Créer des flows custom (5000/5001) |
| **Create Flow button** | Non fonctionnel sauf Edge (Update Flow seulement) | Modifier `rule_cmd` via PostgreSQL |

---

> ℹ️ *Testé sur UTMStack v11.2.8, agent Windows v11.1.4, OPNsense 26.1, CrowdSec 1.6.x*

---

[← Dashboards UTMStack](04-dashboards.md) | [→ SOC AI](06-soc-ai.md)
