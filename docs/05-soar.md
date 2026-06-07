---
title: "SOAR & Automatisation — UTMStack Lab | DoIt4Everyone"
description: "Configuration du SOAR UTMStack v11.2.8 — Ban automatique CrowdSec via SSH, GeoIP enrichissement, clé SSH SYSTEM, script OPNsense, compatibilité MDE."
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

> ⚠️ **Version v0.1** — Les tests Red Team / Kali seront ajoutés en V4.

---

## Architecture

```
UTMStack détecte une alerte
    ↓
Flow SOAR déclenche soar_ban.bat (agent gest-srv)
    ↓
SSH → OPNsense (10.100.1.254)
    ↓
soar_ban.sh — GeoIP lookup + déduplication + cscli ban
    ↓
CrowdSec banne l'IP 24h
    ↓
logger syslog → CROWDSEC_BAN avec country/ASN → UTMStack
```

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
schtasks /create /tn "SOARTest" /tr "cmd /c C:\Windows\System32\OpenSSH\ssh.exe -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -o BatchMode=yes -o ConnectTimeout=10 -i C:\Windows\System32\config\systemprofile\.ssh\soar_key root@10.100.1.254 echo ssh_ok >> C:\UTMStack\soar_debug.log 2>&1" /sc once /st 00:00 /ru SYSTEM /f
schtasks /run /tn "SOARTest"
ping -n 8 127.0.0.1 > nul
type C:\UTMStack\soar_debug.log
```

---

## Étape 2 — Script soar_ban.sh sur OPNsense

Ce script gère la déduplication et l'enrichissement GeoIP via ipapi.co (1000 req/jour gratuit).

```bash
nano /usr/local/bin/soar_ban.sh
```

```sh
#!/bin/sh
IP=$1

# Déduplication 7 jours (168h) — évite le cycle replay SOAR infini
# UTMStack rejoue les vieux logs périodiquement → SOAR re-fire → ban recréé
# Solution : si l'IP a été bannie dans les 7 derniers jours, on skip
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
    echo "IP $IP already banned within 7 days, skipping"
    exit 0
fi

# GeoIP lookup (ipapi.co - 1000 req/jour gratuit)
COUNTRY=$(fetch -qo - "https://ipapi.co/$IP/country_code/" 2>/dev/null | tr -d '\n\r')
ASN=$(fetch -qo - "https://ipapi.co/$IP/asn/" 2>/dev/null | tr -d '\n\r')
[ -z "$COUNTRY" ] || [ "$COUNTRY" = "Undefined" ] && COUNTRY="Unknown"
[ -z "$ASN" ] || [ "$ASN" = "Undefined" ] && ASN="AS0"

if ! /usr/local/bin/cscli decisions list --ip "$IP" 2>/dev/null | grep -q "ban"; then
    /usr/local/bin/cscli decisions add --ip "$IP" --duration 24h --reason utmstack
    # Enregistrer dans la liste des bans récents
    echo "$(date +%s) $IP" >> "$RECENT_BANS"
    logger -p local5.alert -t crowdsec \
      "CROWDSEC_BAN {\"event_type\":\"ban\",\"ip\":\"$IP\",\"reason\":\"utmstack\",\"country\":\"$COUNTRY\",\"as\":\"$ASN\",\"type\":\"ban\"}"
    echo "Decision successfully added for $IP ($COUNTRY / $ASN)"
else
    echo "IP $IP already banned in CrowdSec, skipping"
fi
```

> ℹ️ `/conf/soar_recent_bans.txt` est persistant (survit aux reboots OPNsense). Les entrées sont nettoyées automatiquement à chaque appel. La fenêtre de 7 jours (168h) couvre une semaine complète de replay potentiel d'UTMStack. Le ban CrowdSec lui-même reste 24h — seul le re-fire SOAR est bloqué pendant 7 jours.

```bash
chmod +x /usr/local/bin/soar_ban.sh
cp /usr/local/bin/soar_ban.sh /conf/soar_ban.sh
```

> ℹ️ Les IPs privées (192.168.x.x) retournent "Undefined" depuis ipapi.co — comportement normal.

> ℹ️ Les bans SOAR via `cscli` sont loggués directement par soar_ban.sh. Le script `crowdsec-to-syslog.py` traite uniquement les alertes CrowdSec natives — aucun doublon.

### Persistance aux reboots et mises à jour OPNsense

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

### Test

```bash
/usr/local/bin/soar_ban.sh 45.205.1.71
# → Decision successfully added for 45.205.1.71 (ES / AS215925)

/usr/local/bin/soar_ban.sh 45.205.1.71
# → IP 45.205.1.71 already banned, skipping
```

---

## Étape 3 — Script soar_ban.bat sur gest-srv

```powershell
Set-Content "C:\Program Files\UTMStack\UTMStack Agent\soar_ban.bat" -Encoding ASCII -Value '@echo off
if "%1"=="" exit /b 1
set LOGFILE=C:\Program Files\UTMStack\UTMStack Agent\logs\soar.log
for %%F in ("%LOGFILE%") do if %%~zF gtr 1048576 del "%LOGFILE%"
echo [%DATE% %TIME%] SOAR triggered - IP: %1 >> "%LOGFILE%"
C:\Windows\System32\OpenSSH\ssh.exe -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -o BatchMode=yes -o ConnectTimeout=30 -i C:\Windows\System32\config\systemprofile\.ssh\soar_key root@10.100.1.254 "/usr/local/bin/soar_ban.sh %1" >> "%LOGFILE%" 2>&1
echo [%DATE% %TIME%] Exit: %ERRORLEVEL% >> "%LOGFILE%"'
```

**Fonctionnalités :**
- Vérifie que l'IP n'est pas vide
- Rotation automatique du log à 1 MB
- Timestamp sur chaque entrée
- Exit code enregistré
- Appel de soar_ban.sh avec l'IP uniquement (GeoIP géré côté OPNsense)

> ⚠️ **Encodage** — Utiliser impérativement `-Encoding ASCII`. Un encodage UTF-16 (défaut PowerShell) rend le BAT silencieusement non fonctionnel.

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
| Commande | `soar_ban.bat $(adversary.ip)` |

**Flow 5001 — Suricata Anomaly :**

| Champ | Valeur |
|---|---|
| Nom | CrowdSec Ban Suricata Anomaly |
| Condition | `name IS Suricata Network Anomaly Detected` |
| Agent | gest-srv |
| Commande | `soar_ban.bat $(adversary.ip)` |

### ⚠️ Bug UTMStack v11.2.8 — Cache backend

Après toute modification d'un flow, le backend conserve l'ancienne commande en mémoire. L'UI affiche également l'ancienne règle après sauvegarde — les modifications via l'interface ne sont pas fiables.

**Procédure obligatoire après modification :**

```bash
docker exec -it $(docker ps -q -f name=utmstack_postgres) psql -U postgres -d utmstack -c \
  "DELETE FROM utm_alert_response_rule_execution WHERE execution_status = 'PENDING';"

docker service update --force utmstack_backend
```

**Modification directe en base (recommandée) :**

```bash
docker exec -it $(docker ps -q -f name=utmstack_postgres) psql -U postgres -d utmstack -c \
  "UPDATE utm_alert_response_rule SET rule_cmd = 'soar_ban.bat \$(adversary.ip)' WHERE id IN (5000, 5001);"
```

> ℹ️ **Limitation** — UTMStack v11.2.8 n'expose pas `$(origin.geolocation.countryCode)` comme variable SOAR au niveau de l'alerte de corrélation, même si ce champ est présent dans les événements sous-jacents. L'enrichissement GeoIP est donc géré directement dans `soar_ban.sh`.

---

## Étape 5 — Compatibilité Microsoft Defender for Endpoint

Si MDE est actif sur l'agent Windows, les règles ASR bloquent silencieusement l'exécution des commandes SOAR.

**Symptômes :**
- Timeout 5 minutes dans l'audit SOAR
- Log `soar.log` vide
- Console interactive UTMStack freeze sur gest-srv

**Cause :** La règle ASR `d1e49aac-8f56-4280-b9ba-993a6d77406c` (*Block process creations originating from PSExec and WMI commands*) bloque les processus enfants créés par le service agent UTMStack. MDE voit le pattern `service inconnu → cmd.exe → ssh.exe → connexion externe` comme un comportement C2 malware.

**Lab — Offboarder MDE :**
- M365 Defender portal → **Settings → Endpoints → Offboarding** → script local
- Supprimer les clés de registre résiduelles :

```powershell
Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Force
```

- Réinstaller l'agent UTMStack après offboarding (MDE peut endommager des fichiers)

**Production — Indicator of Allow :**
- M365 Defender → **Settings → Endpoints → Indicators → Files → Add**
- Hash SHA1 de `utmstack_agent_service_windows_amd64.exe` → Action : **Allow**

---

## Vérification end-to-end

**Log soar.log (gest-srv) :**

```
[25.05.2026 16:45:53,87] SOAR triggered - IP: 20.163.15.91
Warning: Permanently added '10.100.1.254' (ED25519) to the list of known hosts.
level=info msg="Decision successfully added"
Decision successfully added for 20.163.15.91 (US / AS8075)
[25.05.2026 16:45:53,87] Exit: 0
```

**Décisions CrowdSec (OPNsense) :**

```
cscli decisions list
→ Ip:20.163.15.91 | utmstack | ban | US | AS8075 (Microsoft)
```

---

## Étape 6 — Auto-fermeture des alertes après traitement SOAR

### Contexte

Les alertes UTMStack sont stockées dans les index OpenSearch **`v11-alert-YYYY-MM-DD`** avec les statuts :

| Valeur | Label | Signification |
|---|---|---|
| `2` | Open | Alerte non traitée |
| `5` | Completed | Alerte traitée / fermée |

Le SOAR traite les alertes automatiquement via CrowdSec. Le SOC AI les ferme ensuite. Un cron sert de filet de sécurité quand le quota API SOC AI est épuisé.

> ⚠️ **Problème critique — Replay SOAR au redémarrage backend**
>
> Au redémarrage du backend UTMStack (`docker service update --force utmstack_backend`), toutes les alertes encore en statut `OPEN` sont rejouées par le SOAR. Cela provoque :
> - Des milliers d'exécutions SOAR en quelques secondes (22 000+ pages d'audit observées)
> - Des bans CrowdSec recréés pour des événements vieux de plusieurs jours
> - Des IPs bannies sans log Suricata correspondant dans UTMStack
>
> **Solution : toujours utiliser `utmstack-pre-restart.sh` avant tout restart backend.**

### Prérequis — Récupérer le mot de passe OpenSearch

Les scripts de cette section utilisent `admin:<OPENSEARCH_PASSWORD>` pour interroger OpenSearch. Ce mot de passe est généré à l'installation d'UTMStack et stocké dans le compose :

```bash
grep "OPENSEARCH_INITIAL_ADMIN_PASSWORD\|s2X9\|opensearch.*pass" /opt/utmstack/compose.yml | head -3
```

Ou depuis les variables d'environnement du conteneur :

```bash
docker exec $(docker ps -q -f name=utmstack_node1) env | grep -i "OPENSEARCH\|PASSWORD" | head -5
```

Remplacer `<OPENSEARCH_PASSWORD>` par la valeur trouvée dans tous les scripts ci-dessous avant déploiement.

> ⚠️ Ne pas committer ce mot de passe dans GitHub — utiliser `<OPENSEARCH_PASSWORD>` comme placeholder dans la documentation publique.

---

### Script de fermeture automatique

Ferme toutes les alertes Suricata de plus de 2 heures. Cron toutes les 5 minutes.

```bash
nano /usr/local/bin/utmstack-close-alerts.sh
```

```bash
#!/bin/bash
# Fermeture automatique des alertes UTMStack — évite le replay SOAR au redémarrage
# Cron : */5 * * * * root /usr/local/bin/utmstack-close-alerts.sh >> /var/log/utmstack-close-alerts.log 2>&1

docker exec $(docker ps -q -f name=utmstack_node1) curl -sk \
  -u 'admin:<OPENSEARCH_PASSWORD>' \
  -X POST "https://localhost:9200/v11-alert-*/_update_by_query" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {
      "bool": {
        "must": [
          {"term": {"status": 2}},
          {"range": {"@timestamp": {"lt": "now-2h"}}}
        ],
        "should": [
          {"terms": {"name.keyword": [
            "Suricata Network Anomaly Detected",
            "Known Malicious IP Detected",
            "High level Suricata alert",
            "Medium level Suricata alert",
            "Malicious JA3 SSL Fingerprint Detected",
            "Cobalt Strike Malleable C2 Profile"
          ]}},
          {"term": {"dataType.keyword": "suricata"}}
        ],
        "minimum_should_match": 1
      }
    },
    "script": {
      "source": "ctx._source.status = 5; ctx._source.statusLabel = \"Completed\"; ctx._source.statusObservation = \"Auto-closed by SOAR cron after CrowdSec ban\"",
      "lang": "painless"
    }
  }'
```

```bash
chmod +x /usr/local/bin/utmstack-close-alerts.sh
```

> ℹ️ `now-2h` laisse 2 heures pour investigation manuelle avant fermeture automatique. `dataType.keyword: suricata` couvre automatiquement tous les futurs types d'alertes Suricata sans maintenir une liste.

### Cron — toutes les 5 minutes

```bash
nano /etc/cron.d/utmstack-close-alerts
```

```
*/5 * * * * root /usr/local/bin/utmstack-close-alerts.sh >> /var/log/utmstack-close-alerts.log 2>&1
```

Vérification :

```bash
tail /var/log/utmstack-close-alerts.log
# {"updated": X, "failures": []}
```

> ℹ️ `"updated": 0` est normal quand le SOC AI a déjà fermé les alertes.

### Script de pré-restart — utmstack-pre-restart.sh

> ⚠️ **Ce script remplace `docker service update --force utmstack_backend` dans toutes les procédures de maintenance.**

Au redémarrage du backend, UTMStack traite sa **queue d'événements** et génère de nouvelles alertes à partir de logs anciens — même si toutes les alertes ont été fermées avant le restart. Le SOAR fire alors sur ces nouvelles alertes et crée des bans CrowdSec pour des événements vieux de plusieurs jours.

**Solution : double fermeture** — avant et après le restart, avec 5 minutes d'attente pour que la queue soit vidée.

```bash
nano /usr/local/bin/utmstack-pre-restart.sh
```

```bash
#!/bin/bash
# À lancer AVANT tout restart du backend UTMStack
# Évite le replay SOAR des alertes historiques au redémarrage
# Durée totale : ~8 minutes

PSQL="docker exec $(docker ps -q -f name=utmstack_postgres) psql -U postgres -d utmstack"

echo "$(date) === utmstack-pre-restart.sh démarré ==="

# 1. Désactiver les flows SOAR pendant la maintenance
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
echo "$(date) — Alertes fermées, attente 5s..."
sleep 5

# 3. Redémarrer le backend
echo "$(date) — Restart utmstack_backend..."
docker service update --force utmstack_backend > /dev/null 2>&1
echo "$(date) — Restart lancé, attente 5 minutes pour vidage de la queue..."

# 4. Attendre que le backend traite sa queue d'événements
sleep 300

# 5. Deuxième fermeture — élimine les alertes générées depuis la queue post-restart
echo "$(date) — Deuxième fermeture des alertes post-queue..."
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

# 6. Réactiver les flows SOAR
echo "$(date) — Réactivation des flows SOAR 5000 et 5001..."
$PSQL -c "UPDATE utm_alert_response_rule SET rule_active = true WHERE id IN (5000, 5001);"

# 7. Vérification état SOAR
echo "$(date) — Vérification état SOAR..."
$PSQL -c "SELECT id, rule_name, rule_active FROM utm_alert_response_rule WHERE id IN (5000, 5001);"

echo "$(date) === Terminé ==="
```

```bash
chmod +x /usr/local/bin/utmstack-pre-restart.sh
```

**Test de validation :**

```bash
# Compter les alertes OPEN avant
docker exec $(docker ps -q -f name=utmstack_node1) curl -sk \
  -u 'admin:<OPENSEARCH_PASSWORD>' \
  -X GET "https://localhost:9200/v11-alert-*/_count" \
  -H "Content-Type: application/json" \
  -d '{"query": {"term": {"status": 2}}}'

# Lancer le script (~6 minutes)
/usr/local/bin/utmstack-pre-restart.sh

# Vérifier après — doit retourner 0
docker exec $(docker ps -q -f name=utmstack_node1) curl -sk \
  -u 'admin:<OPENSEARCH_PASSWORD>' \
  -X GET "https://localhost:9200/v11-alert-*/_count" \
  -H "Content-Type: application/json" \
  -d '{"query": {"term": {"status": 2}}}'
# → {"count":0, "updated":0} ← queue vide après 5 minutes

# Surveiller les bans CrowdSec pendant 5 minutes (FreeBSD)
sh -c 'for i in 1 2 3 4 5; do date +"%H:%M:%S"; cscli decisions list | grep -c utmstack; sleep 60; done'
# → Chiffre stable ou en baisse = replay neutralisé ✅
```

> ℹ️ Si la deuxième fermeture retourne `updated > 0`, augmenter le `sleep 300` à `sleep 600` — la queue d'événements est plus longue que prévu.

### Cause racine identifiée — PENDING SOAR actions

> ⚠️ **Cause réelle du replay massif** : les entrées `PENDING` dans `utm_alert_response_rule_execution`.

Quand le SOAR fire et envoie une commande à l'agent Windows (gest-srv), l'agent exécute `soar_ban.bat` mais **ne retourne jamais de résultat** à UTMStack. L'entrée reste `PENDING` indéfiniment. UTMStack retente périodiquement toutes les actions `PENDING` en batch → vagues de milliers d'exécutions toutes les quelques heures.

**Diagnostic :**
```bash
docker exec -it $(docker ps -q -f name=utmstack_postgres) psql -U postgres -d utmstack -c \
"SELECT execution_status, COUNT(*) FROM utm_alert_response_rule_execution GROUP BY execution_status;"
```

Si `PENDING > 0` → c'est la cause des vagues de bans.

**Purge manuelle :**
```bash
docker exec -it $(docker ps -q -f name=utmstack_postgres) psql -U postgres -d utmstack -c \
"UPDATE utm_alert_response_rule_execution 
SET execution_status = 'COMPLETED', command_result = 'cleared-pending'
WHERE execution_status = 'PENDING';"
```

**La purge automatique toutes les 5 minutes** est intégrée dans `utmstack-close-alerts.sh`.

---

> ⚠️ **Cause réelle confirmée** : le cycle infini de bans est causé par les PENDING qui s'accumulent et se rejouent en batch, **pas** par le replay des alertes ouvertes. La purge automatique des PENDING dans `utmstack-close-alerts.sh` résout le problème définitivement.

**3 niveaux de protection contre le replay (défense en profondeur) :**

| Niveau | Mécanisme | Rôle |
|---|---|---|
| **1 — Purge PENDING** | Cron 5min dans `utmstack-close-alerts.sh` | Corrige la cause racine — empêche les retries en batch |
| **2 — Timestamp event > 2h** | Dans `soar_ban.sh` | Bloque les bans si UTMStack crée une nouvelle alerte depuis un vieux log |
| **3 — Déduplication IP 7 jours** | Dans `soar_ban.sh` via `/conf/soar_recent_bans.txt` | Filet de sécurité si timestamp indisponible ou mal parsé |

---

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

> ⚠️ **L'alert ID n'est pas exposé comme variable SOAR** — ni `$(id)`, `$(alertId)`, `$(alert_id)`, ni `$(uuid)` ne fonctionnent. Confirmé par analyse du bytecode Java et du code source. Non documenté sur le GitHub UTMStack. La fermeture des alertes est gérée par le cron `utmstack-close-alerts.sh`.

### Commande SOAR finale — rule_cmd

```bash
docker exec -it $(docker ps -q -f name=utmstack_postgres) psql -U postgres -d utmstack -c \
"UPDATE utm_alert_response_rule 
SET rule_cmd = 'soar_ban.bat \$(adversary.ip) \$(adversary.geolocation.countryCode) \$(adversary.geolocation.asn) \$(timestamp)'
WHERE id IN (5000, 5001);"
```

---

## Réduction des faux positifs — Règles built-in

Les règles de corrélation built-in (icône 🚫 dans l'UI) ne sont pas modifiables via l'interface. Modification directe en base :

```bash
docker exec -it $(docker ps -q -f name=utmstack_postgres) psql -U postgres -d utmstack
```

**Exclusions connues :**

```sql
-- Exclure Azure AD Connect (AADConnector.psm1) de PowerShell Empire Detection
UPDATE utm_correlation_rules
SET rule_definition_def = rule_definition_def ||
  E'\n&& !contains("log.data.Path", "Microsoft Azure AD Sync")'
WHERE rule_name = 'PowerShell Empire Detection'
AND rule_definition_def NOT LIKE '%Microsoft Azure AD Sync%';

-- Exclure MDE scripts (Log4j scanner, DataCollection) de PowerShell Empire Detection
UPDATE utm_correlation_rules
SET rule_definition_def = rule_definition_def || 
  E'\n&& !contains("log.data.Path", "Windows Defender Advanced Threat Protection")'
WHERE rule_name = 'PowerShell Empire Detection'
AND rule_definition_def NOT LIKE '%Windows Defender Advanced Threat Protection%';
```

Restart backend après modification :

```bash
docker service update --force utmstack_backend
```

### Script centralisé — utmstack-apply-exclusions.sh

> ⚠️ Les modifications de `utm_correlation_rules` peuvent être perdues lors d'une mise à jour majeure UTMStack. Centraliser toutes les exclusions dans un script à relancer après chaque mise à jour.

```bash
# Déploiement
scp utmstack-apply-exclusions.sh root@10.100.1.150:/usr/local/bin/
chmod +x /usr/local/bin/utmstack-apply-exclusions.sh
/usr/local/bin/utmstack-apply-exclusions.sh
```

Le script applique toutes les exclusions connues et vérifie leur présence. Ajouter un bloc pour chaque nouveau faux positif identifié.

**Méthodes de gestion des faux positifs en v11.2.8 :**

| Méthode | Portée | Persistance | Usage |
|---|---|---|---|
| `UPDATE utm_correlation_rules` | Permanente | Risque perte MàJ | Règles built-in — méthode principale |
| Tag "False positive" dans l'UI | Par alerte | SOC AI en tient compte | Cas ponctuels |
| Désactiver règle via UI | Complète | Persistant | Uniquement si règle entièrement inutile |

---

> ℹ️ *Testé sur UTMStack v11.2.8, agent Windows v11.1.4, OPNsense 26.1, CrowdSec 1.6.x, ipapi.co free tier*

---

[← Dashboards UTMStack](04-dashboards.md) | [→ SOC AI](06-soc-ai.md)
