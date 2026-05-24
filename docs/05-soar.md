---
title: "SOAR & Automatisation — UTMStack Lab"
description: "Configuration du SOAR UTMStack v11.2.8 — Ban automatique CrowdSec via SSH, flows, clé SSH SYSTEM, script OPNsense."
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

> [← Retour à l'index](../README.md)

> ⚠️ **Version préliminaire v0.1** — Cette documentation couvre l'infrastructure SOAR. Les tests Red Team / Kali seront ajoutés en V4.

---

## Architecture

```
UTMStack détecte une alerte
    ↓
Flow SOAR déclenche soar_ban.bat (agent gest-srv)
    ↓
SSH → OPNsense (10.100.1.254)
    ↓
soar_ban.sh vérifie si l'IP est déjà bannie
    ↓
CrowdSec banne l'IP 24h
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
# Créer le répertoire .ssh de SYSTEM si inexistant
mkdir C:\Windows\System32\config\systemprofile\.ssh -ErrorAction SilentlyContinue

# Copier la clé via une tâche planifiée (seul SYSTEM peut écrire dans son profil)
schtasks /create /tn "CopySOARKey" /tr "cmd /c copy /y C:\UTMStack\ssh\soar_key C:\Windows\System32\config\systemprofile\.ssh\soar_key" /sc once /st 00:00 /ru SYSTEM /f
schtasks /run /tn "CopySOARKey"
ping -n 8 127.0.0.1 > nul
schtasks /delete /tn "CopySOARKey" /f
```

### Autorisation de la clé sur OPNsense

Sur **OPNsense** :

```bash
# Afficher la clé publique (depuis gest-srv)
type C:\UTMStack\ssh\soar_key.pub

# Sur OPNsense
echo "ssh-ed25519 AAAA... utmstack-soar" > /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
```

> ⚠️ **Persistance** — La clé `authorized_keys` est perdue après un reboot OPNsense si elle n'est pas configurée via **System → Access → Users → root → Authorized Keys** dans l'interface GUI.

### Test de la connexion SSH depuis SYSTEM

```cmd
schtasks /create /tn "SOARTest" /tr "cmd /c C:\Windows\System32\OpenSSH\ssh.exe -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -o BatchMode=yes -o ConnectTimeout=10 -i C:\Windows\System32\config\systemprofile\.ssh\soar_key root@10.100.1.254 echo ssh_ok >> C:\UTMStack\soar_debug.log 2>&1" /sc once /st 00:00 /ru SYSTEM /f
schtasks /run /tn "SOARTest"
ping -n 8 127.0.0.1 > nul
type C:\UTMStack\soar_debug.log
```

Résultat attendu : `ssh_ok` dans le log.

---

## Étape 2 — Script soar_ban.sh sur OPNsense

Ce script gère la déduplication — il vérifie si l'IP est déjà bannie avant d'agir.

```bash
nano /usr/local/bin/soar_ban.sh
```

```sh
#!/bin/sh
IP=$1
if ! /usr/local/bin/cscli decisions list --ip "$IP" 2>/dev/null | grep -q "ban"; then
    /usr/local/bin/cscli decisions add --ip "$IP" --duration 24h --reason utmstack
else
    echo "IP $IP already banned, skipping"
fi
```

```bash
chmod +x /usr/local/bin/soar_ban.sh
```

### Persistance aux reboots et mises à jour OPNsense

```bash
# Sauvegarder dans /conf/ (stockage persistant)
cp /usr/local/bin/soar_ban.sh /conf/soar_ban.sh

# Hook de restauration au démarrage
cat > /usr/local/etc/rc.syshook.d/start/98-soar-ban << 'EOF'
#!/bin/sh
cp /conf/soar_ban.sh /usr/local/bin/soar_ban.sh
chmod +x /usr/local/bin/soar_ban.sh
EOF
chmod +x /usr/local/etc/rc.syshook.d/start/98-soar-ban
```

### Test du script

```bash
/usr/local/bin/soar_ban.sh 192.168.99.1   # → Decision successfully added
/usr/local/bin/soar_ban.sh 192.168.99.1   # → IP already banned, skipping
```

---

## Étape 3 — Script soar_ban.bat sur gest-srv

Créer le fichier dans le répertoire de l'agent (répertoire de travail par défaut lors de l'exécution SOAR) :

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

Après toute modification d'un flow (via UI ou DB), le backend conserve l'ancienne commande en mémoire. L'UI affiche également l'ancienne règle après sauvegarde.

**Procédure obligatoire après modification :**

```bash
# Sur le serveur UTMStack
docker exec -it $(docker ps -q -f name=utmstack_postgres) psql -U postgres -d utmstack -c \
  "DELETE FROM utm_alert_response_rule_execution WHERE execution_status = 'PENDING';"

docker service update --force utmstack_backend
```

**Modification directe en base (recommandée) :**

```bash
docker exec -it $(docker ps -q -f name=utmstack_postgres) psql -U postgres -d utmstack -c \
  "UPDATE utm_alert_response_rule SET rule_cmd = 'soar_ban.bat \$(adversary.ip)' WHERE id IN (5000, 5001);"
```

---

## Étape 5 — Compatibilité Microsoft Defender for Endpoint

Si MDE est actif sur l'agent Windows, les règles ASR bloquent silencieusement l'exécution des commandes SOAR.

**Symptômes :**
- Timeout 5 minutes dans l'audit SOAR
- Log `soar.log` vide
- Console interactive UTMStack freeze sur gest-srv

**Cause :** La règle ASR `d1e49aac-8f56-4280-b9ba-993a6d77406c` (*Block process creations originating from PSExec and WMI commands*) bloque les processus enfants créés par le service agent UTMStack.

**Lab — Offboarder MDE :**
- M365 Defender portal → **Settings → Endpoints → Offboarding** → script local
- Supprimer les clés de registre résiduelles après offboarding :

```powershell
Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Force
```

**Production — Indicator of Allow :**
- M365 Defender → **Settings → Endpoints → Indicators → Files → Add**
- Hash SHA1 de `utmstack_agent_service_windows_amd64.exe` → Action : **Allow**

> ℹ️ Reinstaller l'agent UTMStack après offboarding MDE — MDE peut endommager des fichiers de l'agent pendant son fonctionnement.

---

## Vérification end-to-end

**Log soar.log (gest-srv) :**

```
[24.05.2026 02:09:59,06] SOAR triggered - IP: 74.249.178.25
Warning: Permanently added '10.100.1.254' (ED25519) to the list of known hosts.
level=info msg="Decision successfully added"
[24.05.2026 02:09:59,25] Exit: 0
```

**Décisions CrowdSec (OPNsense) :**

```
cscli decisions list
→ Ip:74.249.178.25 | utmstack | ban | 23h59m
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

Restart backend après modification.

---

> ℹ️ *Testé sur UTMStack v11.2.8, agent Windows v11.1.4, OPNsense 26.1, CrowdSec 1.6.x*

---

[← Dashboards UTMStack](04-dashboards.md) | [→ SOC AI](06-soc-ai.md)
