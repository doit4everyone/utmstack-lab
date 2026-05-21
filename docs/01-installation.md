---
title: "Installation UTMStack v11 sous VMware Workstation | DoIt4Everyone"
description: "Guide complet installation UTMStack v11.2.8 Community Edition sous VMware Workstation. Configuration VM, bug DHCP, optimisations post-install pour lab PME Suisse."
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

# Installation UTMStack v11.2.8 sous VMware Workstation

> [← Retour à l'index](index.md)

## 📋 Table des matières

1. [Paramètres de la machine virtuelle](#1-paramètres-de-la-machine-virtuelle)
2. [Bug critique — DHCP](#2-bug-critique--le-dhcp-fait-planter-linstallateur)
3. [Procédure d'installation](#3-procédure-dinstallation)
   - [3.1 Boot depuis l'ISO](#31-boot-depuis-liso)
   - [3.2 Configuration réseau](#32-configuration-réseau-dans-linstallateur)
   - [3.3 Reconnexion carte réseau](#33-reconnexion-de-la-carte-réseau-dans-vmware)
   - [3.4 Configuration du profil](#34-configuration-du-profil-utilisateur)
4. [Première connexion SSH](#4-première-connexion-ssh-avec-putty)
5. [Vérification de l'installation](#5-vérification-de-linstallation)
   - [5.1 Lancement manuel](#51-lancement-manuel-de-linstallateur-si-nécessaire)
6. [Optimisations post-installation](#6-optimisations-post-installation)
7. [Ports importants](#7-ports-importants-v1128)
8. [Snapshots recommandés](#8-snapshots-recommandés)
9. [Credentials](#9-credentials)

---

## 1. Paramètres de la machine virtuelle

Créer une nouvelle VM dans VMware Workstation avec les paramètres suivants :

| Paramètre | Valeur |
|-----------|--------|
| Système d'exploitation | Linux → Ubuntu 64-bit |
| RAM (installation) | 14336 MB — minimum requis par l'installateur |
| RAM (post-install) | 10240 MB — réduire après installation |
| vCPU | 1 socket × 4 cœurs |
| Disque | 150 GB SATA — thin provisioning |
| Firmware | UEFI |
| Réseau | Personnalisé (VMnet selon l'environnement) |
| Contrôleur I/O | LSI Logic (SCSI) |
| CD/DVD | SATA — pointer vers l'ISO UTMStack v11 |

> ⚠️ **État du périphérique — DÉCOCHER « Connecté » sur la carte réseau avant de démarrer la VM.**

---

## 2. Bug critique — Le DHCP fait planter l'installateur

### Symptôme

- L'installateur ISO démarre
- Une barre orange avec `[Help]` apparaît en haut de l'écran
- L'écran reste noir indéfiniment — le disque n'est jamais écrit

### Cause

Quand la carte réseau est connectée au démarrage, le serveur DHCP du réseau répond avant que l'installateur puisse configurer son environnement réseau interne, causant un conflit fatal dans le processus cloud-init d'autoinstall.

### Solution

Démarrer avec la carte réseau **déconnectée**. L'installateur affiche alors l'écran de configuration réseau permettant de saisir une IP statique, puis on reconnecte la carte dans VMware pendant l'installation.

---

## 3. Procédure d'installation

### 3.1 Boot depuis l'ISO

- Démarrer la VM (carte réseau déconnectée)
- Le menu GRUB apparaît automatiquement
- Sélectionner **« Install UTMStack v11 Community Edition »** → Entrée

### 3.2 Configuration réseau dans l'installateur

L'installateur détecte que la carte réseau est déconnectée et affiche : `disabled — autoconfiguration failed`.

- Cliquer sur l'interface réseau listée (ex : `ens33`)
- Sélectionner **« Edit IPv4 configuration »**
- Changer IPv4 Method de **Disabled → Manual**
- Remplir les champs :

| Champ | Exemple |
|-------|---------|
| Subnet | 192.168.1.0/24 |
| Address | 192.168.1.150 |
| Gateway | 192.168.1.254 |
| Name servers | 192.168.1.1, 8.8.8.8 |
| Search domains | mondomaine.local |

- Cliquer **« Save »**

### 3.3 Reconnexion de la carte réseau dans VMware

Pendant que l'installateur attend sur l'écran Network configuration :

- Dans VMware → **VM → Paramètres**
- Sélectionner la carte réseau
- Cocher **« Connecté »** dans « État du périphérique »
- Cliquer **OK**

> ℹ️ Utiliser `Alt+Tab` pour basculer entre VMware Settings et la console de la VM sans perdre le focus.

- Revenir dans l'installateur → **« Done »** ou **« Continue »**

### 3.4 Configuration du profil utilisateur

| Champ | Description |
|-------|-------------|
| Your name | Nom complet (ex : Admin UTMStack) |
| Your server's name | Nom de la machine (ex : utmstack) |
| Pick a username | Identifiant SSH (ex : admin) |
| Choose a password | Mot de passe sudo — **noter impérativement** |
| Confirm your password | Confirmation |

- L'installation Ubuntu se déroule automatiquement (10–20 minutes)
- La VM reboot automatiquement à la fin

> ℹ️ Après le reboot, le CD-ROM peut être éjecté dans les paramètres VMware.

---

## 4. Première connexion SSH avec PuTTY

| Paramètre | Valeur |
|-----------|--------|
| Hôte | IP statique configurée à l'étape 3.2 |
| Port | 22 |
| Utilisateur | Username saisi à l'étape 3.4 |
| Mot de passe | Password saisi à l'étape 3.4 |

Passer en root immédiatement après connexion :

```bash
sudo su
```

---

## 5. Vérification de l'installation

Environ 30 minutes après le début de l'installation, vérifier que tous les services UTMStack sont démarrés :

```bash
docker service ls
```

### Installation réussie — tous les services à 1/1

```
✅ utmstack_agentmanager              1/1
✅ utmstack_backend                   1/1
✅ utmstack_event-processor-manager   1/1
✅ utmstack_event-processor-worker    1/1
✅ utmstack_frontend                  1/1
✅ utmstack_node1                     1/1  ← OpenSearch
✅ utmstack_postgres                  1/1
✅ utmstack_user-auditor              1/1
✅ utmstack_web-pdf                   1/1
```

### Installation incomplète

```
❌ bash: docker: command not found
❌ Un ou plusieurs services à 0/1
❌ Aucun service listé
```

→ Lancer l'installateur manuellement (voir étape 5.1)

### 5.1 Lancement manuel de l'installateur (si nécessaire)

> ⚠️ Cette étape n'est nécessaire que si la vérification précédente indique une installation incomplète.

```bash
free -h          # Vérifier RAM disponible (minimum 12 GB libres)
sudo su
cd /opt/utmstack
./installer
```

Suivi en parallèle (second terminal PuTTY) :

```bash
tail -f /var/log/utmstack/installer.log
```

| Message affiché | Signification |
|-----------------|---------------|
| Generating Stack configuration... | Calcul de la distribution mémoire |
| Memory distribution successful | RAM suffisante — installation continue |
| Downloading images... | Téléchargement Docker (10–20 min) |
| Installing reverse proxy... | Configuration nginx |
| Initializing databases... | PostgreSQL + OpenSearch |
| Waiting for Backend to be ready... | Démarrage backend (2–3 min) |
| Generating Connection Key... | Génération token agents |
| Installation finished successfully. | Installation terminée ✔ |

**Erreur fréquente — RAM insuffisante :**
```
error balancing memory: insufficient memory: Available 7897MB < Total Minimum Required 11150MB
```
Solution : Power Off → augmenter à 14 GB dans VMware → relancer `./installer`

---

## 6. Optimisations post-installation

> ℹ️ Les étapes 6.4, 6.5 et 6.7 ne sont pas obligatoires si UTMStack dispose de 32 GB+. Les étapes 6.1, 6.2, 6.3 et 6.6 sont toujours recommandées.

### 6.1 Mise à jour du système d'exploitation

```bash
apt update && apt upgrade -y
```

### 6.2 Mises à jour de sécurité automatiques

```bash
apt install unattended-upgrades -y
dpkg-reconfigure --priority=low unattended-upgrades
```

### 6.3 Extension LVM — disque partiel par défaut

```bash
df -h /
lvextend -l +100%FREE /dev/mapper/ubuntu--vg-ubuntu--lv
resize2fs /dev/mapper/ubuntu--vg-ubuntu--lv
df -h /   # Résultat attendu : ~145 GB disponibles
```

### 6.4 Réduction mémoire OpenSearch (lab uniquement)

```bash
sed -i 's/OPENSEARCH_JAVA_OPTS=-Xms[0-9]*m -Xmx[0-9]*m/OPENSEARCH_JAVA_OPTS=-Xms1024m -Xmx1024m/' \
  /opt/utmstack/compose.yml
```

### 6.5 Suppression des réservations mémoire Docker (lab uniquement)

```bash
sed -i '/reservations:/{N;d;}' /opt/utmstack/compose.yml
```

### 6.6 Redéploiement avec les nouvelles configurations

```bash
export UTMSTACK_TAG=v11.2.8
docker stack deploy -c /opt/utmstack/compose.yml utmstack
docker service ls   # Vérifier 1/1
```

### 6.7 Réduction RAM VM à 10 GB (lab uniquement)

- Power Off la VM UTMStack
- VM → Settings → Memory → **10240 MB**
- Power On — tous les services remontent automatiquement

---

## 7. Ports importants v11.2.8

| Port | Service | Usage |
|------|---------|-------|
| 443 / 10001 | Frontend | Interface web |
| 9000 | agentmanager | gRPC agents — contrôle |
| 9001 | agentmanager | HTTP agents |
| 50051 | event-processor-worker | gRPC — envoi logs agents |
| 8080 | event-processor-worker | HTTP |
| 8000 | event-processor-manager | HTTP |
| 7014 | Agent Windows | Réception syslog TCP/UDP |
| 7019 | Agent Windows | Suricata EVE JSON |

> ⚠️ Le port 7014 TCP doit être ouvert manuellement dans le Windows Firewall :

```powershell
New-NetFirewallRule -DisplayName "UTMStack Syslog TCP 7014" -Direction Inbound -Protocol TCP -LocalPort 7014 -Action Allow
```

---

## 8. Snapshots recommandés

| Nom du snapshot | Moment |
|-----------------|--------|
| UTMStack-v11.2.8-clean-install | Après installation + optimisations, avant agents |
| UTMStack-v11.2.8-operational | Après connexion de tous les agents et validation syslog |

> ⚠️ Ne jamais restaurer un backup PostgreSQL d'une version antérieure dans une installation v11.2.8.

---

## 9. Credentials

| Accès | Valeur |
|-------|--------|
| Interface web | `https://<IP configurée>` |
| Username web | `admin` |
| Password web | Généré à l'installation — affiché en fin d'installateur |
| SSH user | Username saisi à l'étape 3.4 |
| SSH password | Password saisi à l'étape 3.4 |
| Admin interface | `https://<IP>:9090` |

> ⚠️ Le mot de passe admin est généré automatiquement et affiché **une seule fois** à la fin de l'installation. Le noter immédiatement.

---

> [← Retour à l'index](index.md) | [→ Intégration Suricata](02-suricata.md)
