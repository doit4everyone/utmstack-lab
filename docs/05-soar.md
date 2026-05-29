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

# GeoIP lookup (ipapi.co - 1000 req/jour gratuit)
COUNTRY=$(fetch -qo - "https://ipapi.co/$IP/country_code/" 2>/dev/null | tr -d '\n\r')
ASN=$(fetch -qo - "https://ipapi.co/$IP/asn/" 2>/dev/null | tr -d '\n\r')
[ -z "$COUNTRY" ] || [ "$COUNTRY" = "Undefined" ] && COUNTRY="Unknown"
[ -z "$ASN" ] || [ "$ASN" = "Undefined" ] && ASN="AS0"

if ! /usr/local/bin/cscli decisions list --ip "$IP" 2>/dev/null | grep -q "ban"; then
    /usr/local/bin/cscli decisions add --ip "$IP" --duration 24h --reason utmstack
    logger -p local5.alert -t crowdsec \
      "CROWDSEC_BAN {\"event_type\":\"ban\",\"ip\":\"$IP\",\"reason\":\"utmstack\",\"country\":\"$COUNTRY\",\"as\":\"$ASN\",\"type\":\"ban\"}"
    echo "Decision successfully added for $IP ($COUNTRY / $ASN)"
else
    echo "IP $IP already banned, skipping"
fi
```

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

## Réduction des faux positifs — Règles built-in

Les règles de corrélation built-in (icône 🚫 dans l'UI) ne sont pas modifiables via l'interface. Modification directe en base :

```bash
docker exec -it $(docker ps -q -f name=utmstack_postgres) psql -U postgres -d utmstack
```

```sql
-- Exemple : exclure les scripts MDE de la règle PowerShell Empire Detection
UPDATE utm_correlation_rules
SET rule_definition_def = rule_definition_def || 
  E'\n&& !contains("log.data.Path", "Windows Defender Advanced Threat Protection")'
WHERE rule_name = 'PowerShell Empire Detection';
```

Restart backend après modification :

```bash
docker service update --force utmstack_backend
```

---

> ℹ️ *Testé sur UTMStack v11.2.8, agent Windows v11.1.4, OPNsense 26.1, CrowdSec 1.6.x, ipapi.co free tier*

---

[← Dashboards UTMStack](04-dashboards.md) | [→ SOC AI](06-soc-ai.md)
